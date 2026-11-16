#pragma once

#include "pm/encryption/channel.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pm::encryption {

inline constexpr std::size_t k_media_key_bytes = 32;
inline constexpr std::size_t k_media_max_plaintext = 64U * 1024U;
inline constexpr int k_media_replay_window = 64;

enum class MediaKind : std::uint8_t {
    Audio = 1,
    Video = 2,
};

/**
 * One generation of a media track key.
 *
 * The signal session wraps these 32 bytes once. Each later packet uses
 * XChaCha20-Poly1305 under this key. A lost packet is a gap. The same
 * sequence in one generation is a replay. Audio and video keys are not
 * interchangeable. This is not SRTP and it is not a WebRTC transport.
 */
class TrackKey {
public:
    TrackKey();
    ~TrackKey();
    TrackKey(TrackKey&& other) noexcept;
    TrackKey& operator=(TrackKey&& other) noexcept;
    TrackKey(const TrackKey&) = delete;
    TrackKey& operator=(const TrackKey&) = delete;

    static TrackKey generate(MediaKind kind, std::uint32_t generation, Error& err);
    static TrackKey from_wrap(std::span<const std::uint8_t> wrap, Error& err);

    Error write_wrap(std::vector<std::uint8_t>& out) const;
    bool valid() const noexcept { return valid_; }
    MediaKind kind() const noexcept { return kind_; }
    std::uint32_t generation() const noexcept { return generation_; }

private:
    friend class AudioSender;
    friend class AudioReceiver;
    friend class VideoSender;
    friend class VideoReceiver;

    void wipe() noexcept;

    std::array<std::uint8_t, k_media_key_bytes> key_{};
    MediaKind kind_ = MediaKind::Audio;
    std::uint32_t generation_ = 0;
    bool valid_ = false;
};

} // namespace pm::encryption
