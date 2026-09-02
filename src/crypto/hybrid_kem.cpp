#include "aegis/crypto_interface.hpp"
#include "aegis/common.hpp"
#include <stdexcept>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>

namespace aegis::crypto {

class hybrid_kem_x25519_mlkem768 : public ikem_engine {
private:
    // derive session key using hkdf sha256 into zeroizing secure_vector
    [[nodiscard]] secure_vector derive_hkdf(std::span<const uint8_t> ikm) {
        secure_vector okm(32);
        evp_pkey_ctx_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
        if (!pctx) throw std::runtime_error("hkdf context allocation failed");

        if (EVP_PKEY_derive_init(pctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0) {
            throw std::runtime_error("hkdf setup failed");
        }

        size_t out_len = okm.size();
        if (EVP_PKEY_derive(pctx.get(), okm.data(), &out_len) <= 0) {
            throw std::runtime_error("hkdf derivation failed");
        }

        return okm;
    }

public:
    [[nodiscard]] key_pair generate_keypair() override {
        key_pair pair;

        // generate x25519 keypair
        evp_pkey_ctx_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
        if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
            throw std::runtime_error("x25519 keygen init failed");
        }

        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) {
            throw std::runtime_error("x25519 keygen failed");
        }
        evp_pkey_ptr x25519_pkey(raw_pkey);

        size_t x_pub_len = x25519_pub_len;
        size_t x_priv_len = x25519_priv_len;
        std::vector<uint8_t> x_pub(x_pub_len);
        secure_vector x_priv(x_priv_len);

        EVP_PKEY_get_raw_public_key(x25519_pkey.get(), x_pub.data(), &x_pub_len);
        EVP_PKEY_get_raw_private_key(x25519_pkey.get(), x_priv.data(), &x_priv_len);

        // generate mlkem768 keypair
        oqs_kem_ptr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768));
        if (!kem) throw std::runtime_error("mlkem768 init failed");

        std::vector<uint8_t> oqs_pub(kem->length_public_key);
        secure_vector oqs_priv(kem->length_secret_key);

        if (OQS_KEM_keypair(kem.get(), oqs_pub.data(), oqs_priv.data()) != OQS_SUCCESS) {
            throw std::runtime_error("mlkem768 keygen failed");
        }

        pair.public_key.reserve(x_pub_len + oqs_pub.size());
        pair.public_key.insert(pair.public_key.end(), x_pub.begin(), x_pub.end());
        pair.public_key.insert(pair.public_key.end(), oqs_pub.begin(), oqs_pub.end());

        pair.secret_key.reserve(x_priv_len + oqs_priv.size());
        pair.secret_key.insert(pair.secret_key.end(), x_priv.begin(), x_priv.end());
        pair.secret_key.insert(pair.secret_key.end(), oqs_priv.begin(), oqs_priv.end());

        return pair;
    }

    [[nodiscard]] encapsulated_secret encapsulate(std::span<const uint8_t> peer_pubkey) override {
        if (peer_pubkey.size() != (x25519_pub_len + mlkem768_pub_len)) {
            throw std::invalid_argument("invalid public key size");
        }

        // slice public keys with zero copy spans
        auto peer_x_pub = peer_pubkey.subspan(0, x25519_pub_len);
        auto peer_oqs_pub = peer_pubkey.subspan(x25519_pub_len, mlkem768_pub_len);

        // perform ecdh exchange
        key_pair eph_x = generate_keypair();
        evp_pkey_ptr peer_pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_x_pub.data(), peer_x_pub.size()));
        evp_pkey_ptr my_privkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, eph_x.secret_key.data(), x25519_priv_len));

        evp_pkey_ctx_ptr derive_ctx(EVP_PKEY_CTX_new(my_privkey.get(), nullptr));
        if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx.get()) <= 0 ||
            EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_pkey.get()) <= 0) {
            throw std::runtime_error("ecdh setup failed");
        }

        size_t x_secret_len = 0;
        EVP_PKEY_derive(derive_ctx.get(), nullptr, &x_secret_len);
        secure_vector x_shared_secret(x_secret_len);
        EVP_PKEY_derive(derive_ctx.get(), x_shared_secret.data(), &x_secret_len);

        // perform mlkem768 encapsulation
        oqs_kem_ptr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768));
        std::vector<uint8_t> oqs_ct(kem->length_ciphertext);
        secure_vector oqs_shared_secret(kem->length_shared_secret);

        if (OQS_KEM_encaps(kem.get(), oqs_ct.data(), oqs_shared_secret.data(), peer_oqs_pub.data()) != OQS_SUCCESS) {
            throw std::runtime_error("mlkem768 encaps failed");
        }

        // combine ciphertexts and derive session key
        encapsulated_secret enc_out;
        enc_out.ciphertext.reserve(x25519_pub_len + oqs_ct.size());
        enc_out.ciphertext.insert(enc_out.ciphertext.end(), eph_x.public_key.begin(), eph_x.public_key.begin() + x25519_pub_len);
        enc_out.ciphertext.insert(enc_out.ciphertext.end(), oqs_ct.begin(), oqs_ct.end());

        secure_vector combined_ikm;
        combined_ikm.reserve(x_shared_secret.size() + oqs_shared_secret.size());
        combined_ikm.insert(combined_ikm.end(), x_shared_secret.begin(), x_shared_secret.end());
        combined_ikm.insert(combined_ikm.end(), oqs_shared_secret.begin(), oqs_shared_secret.end());

        enc_out.shared_secret = derive_hkdf(combined_ikm);
        return enc_out;
    }

    [[nodiscard]] secure_vector decapsulate(std::span<const uint8_t> ciphertext, std::span<const uint8_t> secret_key) override {
        // ecdh decapsulation
        auto eph_x_pub = ciphertext.subspan(0, x25519_pub_len);
        auto oqs_ct = ciphertext.subspan(x25519_pub_len);

        auto x_priv = secret_key.subspan(0, x25519_priv_len);
        auto oqs_priv = secret_key.subspan(x25519_priv_len);

        evp_pkey_ptr peer_pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, eph_x_pub.data(), eph_x_pub.size()));
        evp_pkey_ptr my_privkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, x_priv.data(), x_priv.size()));

        evp_pkey_ctx_ptr derive_ctx(EVP_PKEY_CTX_new(my_privkey.get(), nullptr));
        if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx.get()) <= 0 ||
            EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_pkey.get()) <= 0) {
            throw std::runtime_error("ecdh decapsulation setup failed");
        }

        size_t x_secret_len = 0;
        EVP_PKEY_derive(derive_ctx.get(), nullptr, &x_secret_len);
        secure_vector x_shared_secret(x_secret_len);
        EVP_PKEY_derive(derive_ctx.get(), x_shared_secret.data(), &x_secret_len);

        // mlkem768 decapsulation
        oqs_kem_ptr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768));
        secure_vector oqs_shared_secret(kem->length_shared_secret);

        if (OQS_KEM_decaps(kem.get(), oqs_shared_secret.data(), oqs_ct.data(), oqs_priv.data()) != OQS_SUCCESS) {
            throw std::runtime_error("mlkem768 decapsulation failed");
        }

        secure_vector combined_ikm;
        combined_ikm.reserve(x_shared_secret.size() + oqs_shared_secret.size());
        combined_ikm.insert(combined_ikm.end(), x_shared_secret.begin(), x_shared_secret.end());
        combined_ikm.insert(combined_ikm.end(), oqs_shared_secret.begin(), oqs_shared_secret.end());

        return derive_hkdf(combined_ikm);
    }
};

std::unique_ptr<ikem_engine> create_hybrid_kem() {
    return std::make_unique<hybrid_kem_x25519_mlkem768>();
}

} // namespace aegis::crypto