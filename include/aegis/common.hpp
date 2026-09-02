#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <span>
#include <openssl/evp.h>
#include <oqs/oqs.h>

namespace aegis {

enum class security_level {
    nist_level_1,
    nist_level_3,
    nist_level_5
};

struct key_pair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

struct encapsulated_secret {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> shared_secret;
};

constexpr size_t x25519_pub_len = 32;
constexpr size_t x25519_priv_len = 32;
constexpr size_t mlkem768_pub_len = 1184;
constexpr size_t mlkem768_priv_len = 2400;

template <typename T, void (*FreeFunc)(T*)>
struct raii_deleter {
    void operator()(T* ptr) const {
        if (ptr) FreeFunc(ptr);
    }
};

using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, raii_deleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, raii_deleter<EVP_PKEY, EVP_PKEY_free>>;
using oqs_kem_ptr = std::unique_ptr<OQS_KEM, raii_deleter<OQS_KEM, OQS_KEM_free>>;
using oqs_sig_ptr = std::unique_ptr<OQS_SIG, raii_deleter<OQS_SIG, OQS_SIG_free>>;

} // namespace aegis