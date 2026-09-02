#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <span>
#include <limits>
#include <new>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>

namespace aegis {

// Custom allocator that sanitizes memory with OPENSSL_cleanse upon deallocation
template <typename T>
struct secure_allocator {
    using value_type = T;

    secure_allocator() noexcept = default;
    template <typename U>
    constexpr secure_allocator(const secure_allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) {
            OPENSSL_cleanse(p, n * sizeof(T));
            ::operator delete(p);
        }
    }

    bool operator==(const secure_allocator&) const noexcept { return true; }
    bool operator!=(const secure_allocator&) const noexcept { return false; }
};

using secure_vector = std::vector<uint8_t, secure_allocator<uint8_t>>;

enum class security_level {
    nist_level_1,
    nist_level_3,
    nist_level_5
};

struct key_pair {
    std::vector<uint8_t> public_key;
    secure_vector secret_key; // Automatically zeroized on destruction
};

struct encapsulated_secret {
    std::vector<uint8_t> ciphertext;
    secure_vector shared_secret; // Automatically zeroized on destruction
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