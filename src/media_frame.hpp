#pragma once

#include "pm/encryption/media.hpp"

namespace pm::encryption::detail {

struct MediaWindow {
    std::uint64_t highest = 0;
    std::uint64_t bits = 0;
    bool started = false;
};

Error note_media_sequence(MediaWindow& window, std::uint64_t sequence);
Error seal_media_frame(MediaKind kind, std::span<const std::uint8_t> key, std::uint32_t generation,
                       std::uint64_t sequence, std::uint32_t timestamp_ms,
                       std::span<const std::uint8_t> payload, std::vector<std::uint8_t>& packet);
Error open_media_frame(MediaKind kind, std::span<const std::uint8_t> key, std::uint32_t generation,
                       std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
                       std::uint32_t& timestamp_ms, std::uint64_t& sequence);

} // namespace pm::encryption::detail
