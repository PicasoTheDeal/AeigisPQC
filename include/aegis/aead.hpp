#pragma once
#include "common.hpp"
#include <span>
#include <vector>
#include <cstdint>

namespace aegis::crypto {

constexpr size_t aes_gcm_key_len = 32;
constexpr size_t aes_gcm_iv_len = 12;
constexpr size_t aes_gcm_tag_len = 16;

struct aead_result {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

// Encrypt plaintext using AES-256-GCM
[[nodiscard]] aead_result aead_encrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad = {}
);

// Decrypt ciphertext using AES-256-GCM (returns zeroizing secure_vector)
[[nodiscard]] secure_vector aead_decrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> aad = {}
);

} // namespace aegis::crypto