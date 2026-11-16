#include "pm/encryption/video.hpp"

#include "media_frame.hpp"

#include <limits>

namespace pm::encryption {

VideoSender::VideoSender() = default;
VideoSender::~VideoSender() = default;
VideoSender::VideoSender(VideoSender&& other) noexcept
    : key_(std::move(other.key_)), next_(other.next_) {
    other.next_ = 0;
}
VideoSender& VideoSender::operator=(VideoSender&& other) noexcept {
    if (this == &other)
        return *this;
    key_ = std::move(other.key_);
    next_ = other.next_;
    other.next_ = 0;
    return *this;
}

VideoSender VideoSender::adopt(TrackKey key, Error& err) {
    err = {};
    if (!key.valid() || key.kind() != MediaKind::Video) {
        err = Error::make(ErrorCode::InvalidArgument, "video sender needs a video track key");
        return {};
    }
    VideoSender out;
    out.key_ = std::move(key);
    return out;
}

Error VideoSender::seal(std::span<const std::uint8_t> payload, std::uint32_t timestamp_ms,
                        std::vector<std::uint8_t>& packet) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "video sender is invalid");
    if (next_ == std::numeric_limits<std::uint64_t>::max())
        return Error::make(ErrorCode::InvalidArgument, "video sequence is exhausted");
    if (Error err = detail::seal_media_frame(MediaKind::Video, key_.key_, key_.generation_, next_, timestamp_ms,
                                             payload, packet))
        return err;
    ++next_;
    return {};
}

VideoReceiver::VideoReceiver() = default;
VideoReceiver::~VideoReceiver() = default;
VideoReceiver::VideoReceiver(VideoReceiver&& other) noexcept
    : key_(std::move(other.key_)), window_(other.window_) {
    other.window_ = {};
}
VideoReceiver& VideoReceiver::operator=(VideoReceiver&& other) noexcept {
    if (this == &other)
        return *this;
    key_ = std::move(other.key_);
    window_ = other.window_;
    other.window_ = {};
    return *this;
}

VideoReceiver VideoReceiver::adopt(TrackKey key, Error& err) {
    err = {};
    if (!key.valid() || key.kind() != MediaKind::Video) {
        err = Error::make(ErrorCode::InvalidArgument, "video receiver needs a video track key");
        return {};
    }
    VideoReceiver out;
    out.key_ = std::move(key);
    return out;
}

Error VideoReceiver::open(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
                          std::uint32_t& timestamp_ms, std::uint64_t& sequence) {
    payload.clear();
    timestamp_ms = 0;
    sequence = 0;
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "video receiver is invalid");
    std::uint32_t stamp = 0;
    std::uint64_t seq = 0;
    if (Error err = detail::open_media_frame(MediaKind::Video, key_.key_, key_.generation_, packet, payload, stamp,
                                             seq))
        return err;
    detail::MediaWindow trial{window_.highest, window_.bits, window_.started};
    if (Error err = detail::note_media_sequence(trial, seq)) {
        payload.clear();
        return err;
    }
    window_.highest = trial.highest;
    window_.bits = trial.bits;
    window_.started = trial.started;
    timestamp_ms = stamp;
    sequence = seq;
    return {};
}

} // namespace pm::encryption
