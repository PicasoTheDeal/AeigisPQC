#include "aegis/frame.hpp"
#include <stdexcept>

namespace aegis::net {

std::vector<uint8_t> pack_frame(frame_type type, std::span<const uint8_t> payload) {
    const uint32_t len = static_cast<uint32_t>(payload.size());
    std::vector<uint8_t> frame;
    frame.reserve(frame_header_size + len);

    // magic bytes (big-endian)
    frame.push_back(static_cast<uint8_t>(frame_magic >> 8));
    frame.push_back(static_cast<uint8_t>(frame_magic & 0xFF));

    // frame type
    frame.push_back(static_cast<uint8_t>(type));

    // payload length (32-bit big-endian)
    frame.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    frame.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));

    // copy payload bytes
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

frame_view unpack_frame(std::span<const uint8_t> raw_bytes) {
    if (raw_bytes.size() < frame_header_size) {
        throw std::invalid_argument("frame buffer smaller than header size");
    }

    // validate magic bytes
    const uint16_t magic = (static_cast<uint16_t>(raw_bytes[0]) << 8) | raw_bytes[1];
    if (magic != frame_magic) {
        throw std::invalid_argument("invalid frame magic bytes");
    }

    const auto type = static_cast<frame_type>(raw_bytes[2]);

    // parse 32-bit payload length
    const uint32_t payload_len = (static_cast<uint32_t>(raw_bytes[3]) << 24) | (static_cast<uint32_t>(raw_bytes[4]) << 16) | (static_cast<uint32_t>(raw_bytes[5]) << 8) | static_cast<uint32_t>(raw_bytes[6]);

    if (raw_bytes.size() < frame_header_size + payload_len) {
        throw std::invalid_argument("frame truncated or length mismatch");
    }

    // return zero-copy span window into raw buffer
    return frame_view{
        .type = type,
        .payload = raw_bytes.subspan(frame_header_size, payload_len)
    };
}

} // namespace aegis::net