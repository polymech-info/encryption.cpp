#include "pm/encryption/channel.hpp"

namespace pm::encryption {

ReplayWindow::ReplayWindow(Rule rule, int width) noexcept
    : rule_(rule), width_(width < 1 ? 1 : (width > 64 ? 64 : width)) {}

Error ReplayWindow::preview(std::uint64_t sequence, ReplayWindow& next) const {
    next = *this;
    if (!started_) {
        if (rule_ == Rule::SequenceZeroThenWindow && sequence != 0)
            return Error::make(ErrorCode::Stale, "encrypted frame arrived before sequence 0");
        next.started_ = true;
        next.highest_ = sequence;
        next.bits_ = 1;
        return {};
    }
    if (sequence > highest_) {
        const std::uint64_t shift = sequence - highest_;
        if (shift >= static_cast<std::uint64_t>(width_))
            next.bits_ = 0;
        else
            next.bits_ <<= shift;
        next.bits_ |= 1ull;
        next.highest_ = sequence;
        return {};
    }
    const std::uint64_t behind = highest_ - sequence;
    if (behind >= static_cast<std::uint64_t>(width_)) {
        const char* message = rule_ == Rule::SequenceZeroThenWindow
            ? "encrypted frame is outside the replay window"
            : "datagram sequence is outside the loss window";
        return Error::make(ErrorCode::Stale, message);
    }
    const std::uint64_t mask = 1ull << behind;
    if ((bits_ & mask) != 0) {
        const char* message = rule_ == Rule::SequenceZeroThenWindow
            ? "encrypted frame was already accepted"
            : "datagram sequence was already opened";
        return Error::make(ErrorCode::Replay, message);
    }
    next.bits_ |= mask;
    return {};
}

} // namespace pm::encryption
