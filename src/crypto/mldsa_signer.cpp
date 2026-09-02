#include "aegis/crypto_interface.hpp"
#include <stdexcept>

namespace aegis::crypto {

class mldsa_signer : public isignature_engine {
public:
    [[nodiscard]] key_pair generate_keypair() override {
        oqs_sig_ptr sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65));
        if (!sig) throw std::runtime_error("mldsa65 init failed");

        key_pair pair;
        pair.public_key.resize(sig->length_public_key);
        pair.secret_key.resize(sig->length_secret_key);

        if (OQS_SIG_keypair(sig.get(), pair.public_key.data(), pair.secret_key.data()) != OQS_SUCCESS) {
            throw std::runtime_error("mldsa65 keygen failed");
        }

        return pair;
    }

    [[nodiscard]] std::vector<uint8_t> sign(std::span<const uint8_t> message, std::span<const uint8_t> secret_key) override {
        oqs_sig_ptr sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65));
        if (!sig) throw std::runtime_error("mldsa65 init failed");

        std::vector<uint8_t> signature(sig->length_signature);
        size_t sig_len = 0;

        if (OQS_SIG_sign(sig.get(), signature.data(), &sig_len, message.data(), message.size(), secret_key.data()) != OQS_SUCCESS) {
            throw std::runtime_error("mldsa65 signing failed");
        }

        signature.resize(sig_len);
        return signature;
    }

    [[nodiscard]] bool verify(std::span<const uint8_t> message, std::span<const uint8_t> signature, std::span<const uint8_t> public_key) override {
        oqs_sig_ptr sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65));
        if (!sig) return false;

        return OQS_SIG_verify(sig.get(), message.data(), message.size(), signature.data(), signature.size(), public_key.data()) == OQS_SUCCESS;
    }
};

} // namespace aegis::crypto