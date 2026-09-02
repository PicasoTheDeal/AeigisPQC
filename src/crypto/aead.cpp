#include "aegis/aead.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace aegis::crypto {

using evp_cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, raii_deleter<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>>;

aead_result aead_encrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad
) {
    if (key.size() != aes_gcm_key_len) {
        throw std::invalid_argument("invalid AEAD key length");
    }

    aead_result result;
    result.iv.resize(aes_gcm_iv_len);
    if (RAND_bytes(result.iv.data(), static_cast<int>(aes_gcm_iv_len)) != 1) {
        throw std::runtime_error("failed to generate random IV");
    }

    evp_cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("failed to allocate EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("failed to init AES-256-GCM");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(aes_gcm_iv_len), nullptr) != 1) {
        throw std::runtime_error("failed to set IV length");
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.iv.data()) != 1) {
        throw std::runtime_error("failed to set key and IV");
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("failed to set AAD");
        }
    }

    result.ciphertext.resize(plaintext.size());
    if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("failed to encrypt plaintext");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + len, &len) != 1) {
        throw std::runtime_error("failed to finalize encryption");
    }
    ciphertext_len += len;
    result.ciphertext.resize(ciphertext_len);

    result.tag.resize(aes_gcm_tag_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(aes_gcm_tag_len), result.tag.data()) != 1) {
        throw std::runtime_error("failed to get authentication tag");
    }

    return result;
}

secure_vector aead_decrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> aad
) {
    if (key.size() != aes_gcm_key_len) {
        throw std::invalid_argument("invalid AEAD key length");
    }
    if (iv.size() != aes_gcm_iv_len || tag.size() != aes_gcm_tag_len) {
        throw std::invalid_argument("invalid IV or tag length");
    }

    evp_cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("failed to allocate EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("failed to init AES-256-GCM decrypt");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        throw std::runtime_error("failed to set IV length");
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("failed to set key and IV for decryption");
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("failed to set AAD");
        }
    }

    secure_vector plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw std::runtime_error("failed to decrypt ciphertext");
    }
    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
        throw std::runtime_error("failed to set expected tag");
    }

    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
    if (ret <= 0) {
        throw std::runtime_error("AEAD decryption failed: tag mismatch or payload tampered");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return plaintext;
}

} // namespace aegis::crypto