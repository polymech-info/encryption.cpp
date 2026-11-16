#include "pm/encryption/audio.hpp"

#include "media_frame.hpp"

#include <limits>

namespace pm::encryption {

AudioSender::AudioSender() = default;
AudioSender::~AudioSender() = default;
AudioSender::AudioSender(AudioSender&& other) noexcept
    : key_(std::move(other.key_)), next_(other.next_) {
    other.next_ = 0;
}
AudioSender& AudioSender::operator=(AudioSender&& other) noexcept {
    if (this == &other)
        return *this;
    key_ = std::move(other.key_);
    next_ = other.next_;
    other.next_ = 0;
    return *this;
}

AudioSender AudioSender::adopt(TrackKey key, Error& err) {
    err = {};
    if (!key.valid() || key.kind() != MediaKind::Audio) {
        err = Error::make(ErrorCode::InvalidArgument, "audio sender needs an audio track key");
        return {};
    }
    AudioSender out;
    out.key_ = std::move(key);
    return out;
}

Error AudioSender::seal(std::span<const std::uint8_t> payload, std::uint32_t timestamp_ms,
                        std::vector<std::uint8_t>& packet) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "audio sender is invalid");
    if (next_ == std::numeric_limits<std::uint64_t>::max())
        return Error::make(ErrorCode::InvalidArgument, "audio sequence is exhausted");
    if (Error err = detail::seal_media_frame(MediaKind::Audio, key_.key_, key_.generation_, next_, timestamp_ms,
                                             payload, packet))
        return err;
    ++next_;
    return {};
}

AudioReceiver::AudioReceiver() = default;
AudioReceiver::~AudioReceiver() = default;
AudioReceiver::AudioReceiver(AudioReceiver&& other) noexcept
    : key_(std::move(other.key_)), window_(other.window_) {
    other.window_ = {};
}
AudioReceiver& AudioReceiver::operator=(AudioReceiver&& other) noexcept {
    if (this == &other)
        return *this;
    key_ = std::move(other.key_);
    window_ = other.window_;
    other.window_ = {};
    return *this;
}

AudioReceiver AudioReceiver::adopt(TrackKey key, Error& err) {
    err = {};
    if (!key.valid() || key.kind() != MediaKind::Audio) {
        err = Error::make(ErrorCode::InvalidArgument, "audio receiver needs an audio track key");
        return {};
    }
    AudioReceiver out;
    out.key_ = std::move(key);
    return out;
}

Error AudioReceiver::open(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
                          std::uint32_t& timestamp_ms, std::uint64_t& sequence) {
    payload.clear();
    timestamp_ms = 0;
    sequence = 0;
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "audio receiver is invalid");
    std::uint32_t stamp = 0;
    std::uint64_t seq = 0;
    if (Error err = detail::open_media_frame(MediaKind::Audio, key_.key_, key_.generation_, packet, payload, stamp,
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
