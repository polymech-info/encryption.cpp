#pragma once

#include "pm/encryption/media.hpp"

namespace pm::encryption {

class AudioSender {
public:
    AudioSender();
    ~AudioSender();
    AudioSender(AudioSender&& other) noexcept;
    AudioSender& operator=(AudioSender&& other) noexcept;
    AudioSender(const AudioSender&) = delete;
    AudioSender& operator=(const AudioSender&) = delete;

    static AudioSender adopt(TrackKey key, Error& err);
    bool valid() const noexcept { return key_.valid(); }

    Error seal(std::span<const std::uint8_t> payload, std::uint32_t timestamp_ms,
               std::vector<std::uint8_t>& packet);

private:
    TrackKey key_;
    std::uint64_t next_ = 0;
};

class AudioReceiver {
public:
    AudioReceiver();
    ~AudioReceiver();
    AudioReceiver(AudioReceiver&& other) noexcept;
    AudioReceiver& operator=(AudioReceiver&& other) noexcept;
    AudioReceiver(const AudioReceiver&) = delete;
    AudioReceiver& operator=(const AudioReceiver&) = delete;

    static AudioReceiver adopt(TrackKey key, Error& err);
    bool valid() const noexcept { return key_.valid(); }

    Error open(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
               std::uint32_t& timestamp_ms, std::uint64_t& sequence);

private:
    struct Window {
        std::uint64_t highest = 0;
        std::uint64_t bits = 0;
        bool started = false;
    };

    TrackKey key_;
    Window window_{};
};

} // namespace pm::encryption
