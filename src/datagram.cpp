#include "pm/encryption/datagram.hpp"

#include <sodium.h>

#include <cstring>
#include <limits>

namespace pm::encryption {
namespace {

constexpr std::uint8_t k_magic[] = {'P', 'M', 'D', '1'};
constexpr std::uint8_t k_version = 1;
constexpr std::uint8_t k_wrap_version = 1;
constexpr std::size_t k_tag = crypto_aead_xchacha20poly1305_ietf_ABYTES;

bool init_crypto(Error& err) {
    if (sodium_init() < 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "libsodium initialization failed");
        return false;
    }
    return true;
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>(value >> shift));
}

bool take_u32(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint32_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 4)
        return false;
    out = (std::uint32_t{bytes[pos]} << 24) | (std::uint32_t{bytes[pos + 1]} << 16)
        | (std::uint32_t{bytes[pos + 2]} << 8) | std::uint32_t{bytes[pos + 3]};
    pos += 4;
    return true;
}

bool take_u64(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint64_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 8)
        return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out = (out << 8) | bytes[pos + static_cast<std::size_t>(i)];
    pos += 8;
    return true;
}

bool take_block(std::span<const std::uint8_t> bytes, std::size_t& pos, std::size_t max,
                std::vector<std::uint8_t>& out) {
    if (pos >= bytes.size())
        return false;
    const std::size_t len = bytes[pos++];
    if (len == 0 || len > max || pos > bytes.size() || bytes.size() - pos < len)
        return false;
    out.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
               bytes.begin() + static_cast<std::ptrdiff_t>(pos + len));
    pos += len;
    return true;
}

bool same(const std::vector<std::uint8_t>& left, const std::vector<std::uint8_t>& right) {
    return left.size() == right.size() && (left.empty() || std::memcmp(left.data(), right.data(), left.size()) == 0);
}

void nonce_for(std::uint32_t epoch, std::uint64_t sequence, std::span<const std::uint8_t> id,
               std::span<const std::uint8_t> scope, std::array<std::uint8_t, 24>& nonce) {
    nonce.fill(0);
    nonce[0] = static_cast<std::uint8_t>(epoch >> 24);
    nonce[1] = static_cast<std::uint8_t>(epoch >> 16);
    nonce[2] = static_cast<std::uint8_t>(epoch >> 8);
    nonce[3] = static_cast<std::uint8_t>(epoch);
    for (int i = 0; i < 8; ++i)
        nonce[static_cast<std::size_t>(4 + i)] = static_cast<std::uint8_t>(sequence >> (56 - 8 * i));
    std::vector<std::uint8_t> material;
    material.push_back(static_cast<std::uint8_t>(id.size()));
    material.insert(material.end(), id.begin(), id.end());
    material.push_back(static_cast<std::uint8_t>(scope.size()));
    material.insert(material.end(), scope.begin(), scope.end());
    std::array<std::uint8_t, 32> digest{};
    crypto_generichash(digest.data(), digest.size(), material.data(), material.size(), nullptr, 0);
    std::memcpy(nonce.data() + 12, digest.data(), 12);
}

bool label_ok(std::span<const std::uint8_t> id, std::span<const std::uint8_t> scope, Error& err) {
    if (id.empty() || id.size() > k_flow_id_max || scope.size() > k_flow_scope_max) {
        err = Error::make(ErrorCode::InvalidArgument, "flow id or scope length is invalid");
        return false;
    }
    return true;
}

} // namespace

void FlowKey::wipe() noexcept {
    sodium_memzero(key_.data(), key_.size());
    if (!id_.empty())
        sodium_memzero(id_.data(), id_.size());
    if (!scope_.empty())
        sodium_memzero(scope_.data(), scope_.size());
    id_.clear();
    scope_.clear();
    epoch_ = 0;
    sendable_ = false;
    valid_ = false;
}

FlowKey FlowKey::clone() const {
    FlowKey out;
    if (!valid_)
        return out;
    out.key_ = key_;
    out.id_ = id_;
    out.scope_ = scope_;
    out.epoch_ = epoch_;
    out.sendable_ = sendable_;
    out.valid_ = true;
    return out;
}

FlowKey::FlowKey() = default;
FlowKey::~FlowKey() { wipe(); }

FlowKey::FlowKey(FlowKey&& other) noexcept
    : key_(other.key_), id_(std::move(other.id_)), scope_(std::move(other.scope_)), epoch_(other.epoch_),
      sendable_(other.sendable_), valid_(other.valid_) {
    other.wipe();
}

FlowKey& FlowKey::operator=(FlowKey&& other) noexcept {
    if (this == &other)
        return *this;
    wipe();
    key_ = other.key_;
    id_ = std::move(other.id_);
    scope_ = std::move(other.scope_);
    epoch_ = other.epoch_;
    sendable_ = other.sendable_;
    valid_ = other.valid_;
    other.wipe();
    return *this;
}

FlowKey FlowKey::generate(std::span<const std::uint8_t> id, std::span<const std::uint8_t> scope,
                          std::uint32_t epoch, Error& err) {
    err = {};
    if (!init_crypto(err) || !label_ok(id, scope, err))
        return {};
    FlowKey out;
    randombytes_buf(out.key_.data(), out.key_.size());
    out.id_.assign(id.begin(), id.end());
    out.scope_.assign(scope.begin(), scope.end());
    out.epoch_ = epoch;
    out.sendable_ = true;
    out.valid_ = true;
    return out;
}

FlowKey FlowKey::from_wrap(std::span<const std::uint8_t> wrap, Error& err) {
    err = {};
    if (!init_crypto(err))
        return {};
    if (wrap.size() < 7 || wrap[0] != k_wrap_version) {
        err = Error::make(ErrorCode::InvalidArgument, "flow key wrap is invalid");
        return {};
    }
    std::size_t pos = 1;
    std::uint32_t epoch = 0;
    std::vector<std::uint8_t> id;
    std::vector<std::uint8_t> scope;
    if (!take_u32(wrap, pos, epoch) || !take_block(wrap, pos, k_flow_id_max, id)) {
        err = Error::make(ErrorCode::InvalidArgument, "flow key wrap is invalid");
        return {};
    }
    if (pos >= wrap.size()) {
        err = Error::make(ErrorCode::InvalidArgument, "flow key wrap is invalid");
        return {};
    }
    const std::size_t scope_len = wrap[pos++];
    if (scope_len > k_flow_scope_max || wrap.size() - pos < scope_len + 32) {
        err = Error::make(ErrorCode::InvalidArgument, "flow key wrap is invalid");
        return {};
    }
    scope.assign(wrap.begin() + static_cast<std::ptrdiff_t>(pos),
                 wrap.begin() + static_cast<std::ptrdiff_t>(pos + scope_len));
    pos += scope_len;
    if (wrap.size() - pos != 32) {
        err = Error::make(ErrorCode::InvalidArgument, "flow key wrap is invalid");
        return {};
    }
    FlowKey out;
    std::memcpy(out.key_.data(), wrap.data() + pos, 32);
    out.id_ = std::move(id);
    out.scope_ = std::move(scope);
    out.epoch_ = epoch;
    out.valid_ = true;
    return out;
}

Error FlowKey::write_wrap(std::vector<std::uint8_t>& out) const {
    out.clear();
    if (!valid_)
        return Error::make(ErrorCode::InvalidArgument, "flow key is invalid");
    out.push_back(k_wrap_version);
    append_u32(out, epoch_);
    out.push_back(static_cast<std::uint8_t>(id_.size()));
    out.insert(out.end(), id_.begin(), id_.end());
    out.push_back(static_cast<std::uint8_t>(scope_.size()));
    out.insert(out.end(), scope_.begin(), scope_.end());
    out.insert(out.end(), key_.begin(), key_.end());
    return {};
}

DatagramSender::DatagramSender() = default;
DatagramSender::~DatagramSender() = default;
DatagramSender::DatagramSender(DatagramSender&& other) noexcept
    : key_(std::move(other.key_)), next_(other.next_) {
    other.next_ = 0;
}
DatagramSender& DatagramSender::operator=(DatagramSender&& other) noexcept {
    if (this == &other)
        return *this;
    key_ = std::move(other.key_);
    next_ = other.next_;
    other.next_ = 0;
    return *this;
}

DatagramSender DatagramSender::adopt(FlowKey key, Error& err) {
    err = {};
    if (!key.valid() || !key.sendable_) {
        err = Error::make(ErrorCode::UnexpectedState, "a wrapped datagram key does not seal");
        return {};
    }
    DatagramSender out;
    out.key_ = std::move(key);
    return out;
}

Error DatagramSender::seal(std::span<const std::uint8_t> payload, std::uint32_t timestamp_ms,
                           std::vector<std::uint8_t>& packet) {
    packet.clear();
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "datagram sender is invalid");
    if (next_ == std::numeric_limits<std::uint64_t>::max())
        return Error::make(ErrorCode::InvalidArgument, "datagram sequence is exhausted");
    if (payload.size() > k_datagram_max_plaintext)
        return Error::make(ErrorCode::PlaintextTooLarge, "datagram exceeds 64 KiB");
    Error err;
    if (!init_crypto(err))
        return err;
    packet.insert(packet.end(), k_magic, k_magic + 4);
    packet.push_back(k_version);
    append_u32(packet, key_.epoch_);
    append_u64(packet, next_);
    append_u32(packet, timestamp_ms);
    packet.push_back(static_cast<std::uint8_t>(key_.id_.size()));
    packet.insert(packet.end(), key_.id_.begin(), key_.id_.end());
    packet.push_back(static_cast<std::uint8_t>(key_.scope_.size()));
    packet.insert(packet.end(), key_.scope_.begin(), key_.scope_.end());
    std::array<std::uint8_t, 24> nonce{};
    nonce_for(key_.epoch_, next_, key_.id_, key_.scope_, nonce);
    const std::size_t header = packet.size();
    packet.resize(header + payload.size() + k_tag);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            packet.data() + header, &written, payload.data(), payload.size(), packet.data(), header, nullptr,
            nonce.data(), key_.key_.data())
        != 0) {
        packet.clear();
        return Error::make(ErrorCode::CryptoUnavailable, "datagram seal failed");
    }
    ++next_;
    return {};
}

DatagramReceiver::DatagramReceiver() = default;
DatagramReceiver::~DatagramReceiver() = default;
DatagramReceiver::DatagramReceiver(DatagramReceiver&& other) noexcept
    : key_(std::move(other.key_)), window_(other.window_) {
    other.window_ = ReplayWindow{ReplayWindow::Rule::AnySequenceThenWindow, k_datagram_replay_window};
}
DatagramReceiver& DatagramReceiver::operator=(DatagramReceiver&& other) noexcept {
    if (this == &other)
        return *this;
    key_ = std::move(other.key_);
    window_ = other.window_;
    other.window_ = ReplayWindow{ReplayWindow::Rule::AnySequenceThenWindow, k_datagram_replay_window};
    return *this;
}

DatagramReceiver DatagramReceiver::adopt(FlowKey key, Error& err) {
    err = {};
    if (!key.valid()) {
        err = Error::make(ErrorCode::InvalidArgument, "datagram receiver needs a flow key");
        return {};
    }
    DatagramReceiver out;
    out.key_ = std::move(key);
    return out;
}

Error DatagramReceiver::open(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
                             std::uint32_t& timestamp_ms, std::uint64_t& sequence) {
    payload.clear();
    timestamp_ms = 0;
    sequence = 0;
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "datagram receiver is invalid");
    if (packet.size() < 4 + 1 + 4 + 8 + 4 + 1 + 1 + k_tag)
        return Error::make(ErrorCode::FrameTooSmall, "datagram is too small");
    if (std::memcmp(packet.data(), k_magic, 4) != 0 || packet[4] != k_version)
        return Error::make(ErrorCode::InvalidFrame, "datagram version is wrong");
    std::size_t pos = 5;
    std::uint32_t epoch = 0;
    std::vector<std::uint8_t> id;
    std::vector<std::uint8_t> scope;
    if (!take_u32(packet, pos, epoch) || !take_u64(packet, pos, sequence) || !take_u32(packet, pos, timestamp_ms)
        || !take_block(packet, pos, k_flow_id_max, id))
        return Error::make(ErrorCode::InvalidFrame, "datagram header is invalid");
    if (pos >= packet.size())
        return Error::make(ErrorCode::InvalidFrame, "datagram header is invalid");
    const std::size_t scope_len = packet[pos++];
    if (scope_len > k_flow_scope_max || pos > packet.size() || packet.size() - pos < scope_len + k_tag)
        return Error::make(ErrorCode::InvalidFrame, "datagram header is invalid");
    scope.assign(packet.begin() + static_cast<std::ptrdiff_t>(pos),
                 packet.begin() + static_cast<std::ptrdiff_t>(pos + scope_len));
    pos += scope_len;
    if (epoch != key_.epoch_ || !same(id, key_.id_) || !same(scope, key_.scope_))
        return Error::make(ErrorCode::WrongSession, "datagram flow id, scope, or epoch does not match");
    std::array<std::uint8_t, 24> nonce{};
    nonce_for(epoch, sequence, id, scope, nonce);
    const std::size_t cipher_len = packet.size() - pos;
    payload.resize(cipher_len - k_tag);
    unsigned long long opened = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            payload.empty() ? nullptr : payload.data(), &opened, nullptr, packet.data() + pos, cipher_len,
            packet.data(), pos, nonce.data(), key_.key_.data())
        != 0) {
        payload.clear();
        return Error::make(ErrorCode::AuthenticationFailed, "datagram failed authentication");
    }
    payload.resize(static_cast<std::size_t>(opened));
    ReplayWindow next;
    if (Error err = window_.preview(sequence, next)) {
        payload.clear();
        return err;
    }
    window_ = next;
    return {};
}

Error datagram_id(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& id) {
    id.clear();
    if (packet.size() < 4 + 1 + 4 + 8 + 4 + 1 || std::memcmp(packet.data(), k_magic, 4) != 0 || packet[4] != k_version)
        return Error::make(ErrorCode::InvalidFrame, "datagram version is wrong");
    std::size_t pos = 5;
    std::uint32_t epoch = 0;
    std::uint64_t sequence = 0;
    std::uint32_t timestamp = 0;
    if (!take_u32(packet, pos, epoch) || !take_u64(packet, pos, sequence) || !take_u32(packet, pos, timestamp)
        || !take_block(packet, pos, k_flow_id_max, id))
        return Error::make(ErrorCode::InvalidFrame, "datagram header is invalid");
    return {};
}

} // namespace pm::encryption
