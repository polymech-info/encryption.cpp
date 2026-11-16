#pragma once

#include "pm/encryption/media.hpp"

namespace pm::encryption {

class VideoSender {
public:
    VideoSender();
    ~VideoSender();
    VideoSender(VideoSender&& other) noexcept;
    VideoSender& operator=(VideoSender&& other) noexcept;
    VideoSender(const VideoSender&) = delete;
    VideoSender& operator=(const VideoSender&) = delete;

    static VideoSender adopt(TrackKey key, Error& err);
    bool valid() const noexcept { return key_.valid(); }

    Error seal(std::span<const std::uint8_t> payload, std::uint32_t timestamp_ms,
               std::vector<std::uint8_t>& packet);

private:
    TrackKey key_;
    std::uint64_t next_ = 0;
};

class VideoReceiver {
public:
    VideoReceiver();
    ~VideoReceiver();
    VideoReceiver(VideoReceiver&& other) noexcept;
    VideoReceiver& operator=(VideoReceiver&& other) noexcept;
    VideoReceiver(const VideoReceiver&) = delete;
    VideoReceiver& operator=(const VideoReceiver&) = delete;

    static VideoReceiver adopt(TrackKey key, Error& err);
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
