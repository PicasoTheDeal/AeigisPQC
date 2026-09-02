#pragma once
#include "common.hpp"

namespace aegis::crypto {

class ikem_engine {
public:
    virtual ~ikem_engine() = default;
    [[nodiscard]] virtual key_pair generate_keypair() = 0;
    [[nodiscard]] virtual encapsulated_secret encapsulate(std::span<const uint8_t> peer_pubkey) = 0;
    [[nodiscard]] virtual std::vector<uint8_t> decapsulate(std::span<const uint8_t> ciphertext,  std::span<const uint8_t> secret_key) = 0;
};

class isignature_engine {
public:
    virtual ~isignature_engine() = default;
    [[nodiscard]] virtual key_pair generate_keypair() = 0;
    [[nodiscard]] virtual std::vector<uint8_t> sign(std::span<const uint8_t> message, std::span<const uint8_t> secret_key) = 0;
    [[nodiscard]] virtual bool verify(std::span<const uint8_t> message, std::span<const uint8_t> signature,  std::span<const uint8_t> public_key) = 0;
};

} // namespace aegis::crypto