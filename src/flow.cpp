#include "pm/encryption/flow.hpp"

#include <sodium.h>

#include <utility>

namespace pm::encryption {
namespace {

void wipe(std::vector<std::uint8_t>& bytes) {
    if (!bytes.empty())
        sodium_memzero(bytes.data(), bytes.size());
    bytes.clear();
}

} // namespace

SecureFlow::SecureFlow() = default;
SecureFlow::~SecureFlow() = default;
SecureFlow::SecureFlow(SecureFlow&& other) noexcept
    : sender_(std::move(other.sender_)), receiver_(std::move(other.receiver_)), retained_(std::move(other.retained_)) {}
SecureFlow& SecureFlow::operator=(SecureFlow&& other) noexcept {
    if (this == &other)
        return *this;
    sender_ = std::move(other.sender_);
    receiver_ = std::move(other.receiver_);
    retained_ = std::move(other.retained_);
    return *this;
}

SecureFlow SecureFlow::accept(std::span<const std::uint8_t> wrap, Error& err) {
    err = {};
    FlowKey retained = FlowKey::from_wrap(wrap, err);
    if (err)
        return {};
    FlowKey recv = retained.clone();
    SecureFlow out;
    out.receiver_ = DatagramReceiver::adopt(std::move(recv), err);
    if (err)
        return {};
    out.retained_ = std::move(retained);
    return out;
}

Error SecureFlow::seal(std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& ciphertext) {
    if (!receiver_.valid())
        return Error::make(ErrorCode::InvalidArgument, "flow is not open");
    if (!sender_.valid())
        return Error::make(ErrorCode::UnexpectedState, "only the flow's sender seals packets");
    return sender_.seal(plaintext, 0, ciphertext);
}

Error SecureFlow::open(std::span<const std::uint8_t> ciphertext, std::vector<std::uint8_t>& plaintext) {
    std::uint32_t timestamp = 0;
    std::uint64_t sequence = 0;
    return receiver_.open(ciphertext, plaintext, timestamp, sequence);
}

Error SecureFlow::export_key(std::vector<std::uint8_t>& wrap) const {
    return retained_.write_wrap(wrap);
}

Error SecureFlow::rekey(std::vector<std::uint8_t>& wrap) {
    wrap.clear();
    if (!sender_.valid() || !retained_.valid())
        return Error::make(ErrorCode::UnexpectedState, "only the flow's sender advances the epoch");
    if (retained_.epoch() == std::uint32_t{0xffffffffu})
        return Error::make(ErrorCode::InvalidArgument, "flow epoch is exhausted");
    Error err;
    FlowKey next = FlowKey::generate(retained_.id(), retained_.scope(), retained_.epoch() + 1, err);
    if (err)
        return err;
    if (Error write = next.write_wrap(wrap))
        return write;
    sender_ = DatagramSender::adopt(next.clone(), err);
    receiver_ = DatagramReceiver::adopt(next.clone(), err);
    retained_ = std::move(next);
    if (err) {
        wipe(wrap);
        close();
    }
    return err;
}

Error SecureFlow::accept_next(std::span<const std::uint8_t> wrap) {
    if (sender_.valid())
        return Error::make(ErrorCode::UnexpectedState, "the sender advances an epoch with rekey");
    if (!receiver_.valid() || !retained_.valid())
        return Error::make(ErrorCode::InvalidArgument, "flow is not open");
    Error err;
    FlowKey next = FlowKey::from_wrap(wrap, err);
    if (err)
        return err;
    if (next.id() != retained_.id() || next.scope() != retained_.scope())
        return Error::make(ErrorCode::WrongSession, "datagram wrap is for another flow");
    if (next.epoch() <= retained_.epoch())
        return Error::make(ErrorCode::Stale, "datagram wrap epoch is not newer");
    receiver_ = DatagramReceiver::adopt(next.clone(), err);
    if (err)
        return err;
    retained_ = std::move(next);
    return {};
}

void SecureFlow::close() {
    sender_ = {};
    receiver_ = {};
    retained_ = {};
}

SecureEndpoint SecureEndpoint::open(Error& err) {
    err = {};
    if (sodium_init() < 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "libsodium initialization failed");
        return {};
    }
    return {};
}

SecureFlow SecureEndpoint::open_flow(const FlowOptions& options, Error& err) const {
    err = {};
    if (options.delivery != Delivery::Datagram) {
        err = Error::make(ErrorCode::InvalidArgument,
                          "this endpoint opens datagram flows; reliable and durable use their own engines");
        return {};
    }
    FlowKey key = FlowKey::generate(options.id, options.scope, options.epoch, err);
    if (err)
        return {};
    SecureFlow flow;
    flow.sender_ = DatagramSender::adopt(key.clone(), err);
    if (err)
        return {};
    flow.receiver_ = DatagramReceiver::adopt(key.clone(), err);
    if (err)
        return {};
    flow.retained_ = std::move(key);
    return flow;
}

} // namespace pm::encryption
