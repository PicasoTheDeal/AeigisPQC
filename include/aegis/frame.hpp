#pragma once
#include "common.hpp"
#include <span>
#include <vector>
#include <cstdint>

namespace aegis::net {

enum class frame_type : uint8_t {
    public_key_bundle = 0x01,
    handshake_ciphertext = 0x02,
    signature = 0x03,
    encrypted_payload = 0x04
};

constexpr size_t frame_header_size = 7; // 2 bytes magic + 1 byte type + 4 bytes length
constexpr uint16_t frame_magic = 0x4147; // 'A' 'G'

struct frame_view {
    frame_type type;
    std::span<const uint8_t> payload;
};

// pack payload into a binary network frame: [magic(2)][type(1)][length(4)][payload...]
[[nodiscard]] std::vector<uint8_t> pack_frame(frame_type type, std::span<const uint8_t> payload);

// zero-copy unpack: validates frame header and returns a span pointing directly into raw_bytes
[[nodiscard]] frame_view unpack_frame(std::span<const uint8_t> raw_bytes);

} // namespace aegis::net