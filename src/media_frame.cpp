#include "media_frame.hpp"

#include <sodium.h>

#include <cstring>
#include <limits>

namespace pm::encryption {
namespace {

constexpr std::uint8_t k_audio_magic[] = {'P', 'M', 'A', '1'};
constexpr std::uint8_t k_video_magic[] = {'P', 'M', 'V', '1'};
constexpr std::uint8_t k_version = 1;
constexpr std::uint8_t k_wrap_version = 1;
constexpr std::size_t k_header = 4 + 1 + 1 + 4 + 8 + 4;
constexpr std::size_t k_wrap_bytes = 1 + 1 + 4 + k_media_key_bytes;

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
    if (bytes.size() - pos < 4)
        return false;
    out = (std::uint32_t{bytes[pos]} << 24) | (std::uint32_t{bytes[pos + 1]} << 16)
        | (std::uint32_t{bytes[pos + 2]} << 8) | std::uint32_t{bytes[pos + 3]};
    pos += 4;
    return true;
}

bool take_u64(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint64_t& out) {
    if (bytes.size() - pos < 8)
        return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out = (out << 8) | bytes[pos + static_cast<std::size_t>(i)];
    pos += 8;
    return true;
}

const std::uint8_t* magic_of(MediaKind kind) {
    return kind == MediaKind::Video ? k_video_magic : k_audio_magic;
}

} // namespace

void TrackKey::wipe() noexcept {
    sodium_memzero(key_.data(), key_.size());
    kind_ = MediaKind::Audio;
    generation_ = 0;
    valid_ = false;
}

TrackKey::TrackKey() = default;

TrackKey::~TrackKey() {
    wipe();
}

TrackKey::TrackKey(TrackKey&& other) noexcept
    : key_(other.key_), kind_(other.kind_), generation_(other.generation_), valid_(other.valid_) {
    other.wipe();
}

TrackKey& TrackKey::operator=(TrackKey&& other) noexcept {
    if (this == &other)
        return *this;
    wipe();
    key_ = other.key_;
    kind_ = other.kind_;
    generation_ = other.generation_;
    valid_ = other.valid_;
    other.wipe();
    return *this;
}

TrackKey TrackKey::generate(MediaKind kind, std::uint32_t generation, Error& err) {
    err = {};
    if (!init_crypto(err))
        return {};
    if (kind != MediaKind::Audio && kind != MediaKind::Video) {
        err = Error::make(ErrorCode::InvalidArgument, "media track kind is invalid");
        return {};
    }
    TrackKey out;
    randombytes_buf(out.key_.data(), out.key_.size());
    out.kind_ = kind;
    out.generation_ = generation;
    out.valid_ = true;
    return out;
}

TrackKey TrackKey::from_wrap(std::span<const std::uint8_t> wrap, Error& err) {
    err = {};
    if (!init_crypto(err))
        return {};
    if (wrap.size() != k_wrap_bytes || wrap[0] != k_wrap_version) {
        err = Error::make(ErrorCode::InvalidArgument, "media key wrap is invalid");
        return {};
    }
    const auto kind = static_cast<MediaKind>(wrap[1]);
    if (kind != MediaKind::Audio && kind != MediaKind::Video) {
        err = Error::make(ErrorCode::InvalidArgument, "media key wrap kind is invalid");
        return {};
    }
    std::uint32_t generation = (std::uint32_t{wrap[2]} << 24) | (std::uint32_t{wrap[3]} << 16)
        | (std::uint32_t{wrap[4]} << 8) | std::uint32_t{wrap[5]};
    TrackKey out;
    std::memcpy(out.key_.data(), wrap.data() + 6, out.key_.size());
    out.kind_ = kind;
    out.generation_ = generation;
    out.valid_ = true;
    return out;
}

Error TrackKey::write_wrap(std::vector<std::uint8_t>& out) const {
    out.clear();
    if (!valid_)
        return Error::make(ErrorCode::InvalidArgument, "media track key is invalid");
    out.reserve(k_wrap_bytes);
    out.push_back(k_wrap_version);
    out.push_back(static_cast<std::uint8_t>(kind_));
    append_u32(out, generation_);
    out.insert(out.end(), key_.begin(), key_.end());
    return {};
}

namespace detail {

Error note_media_sequence(MediaWindow& window, std::uint64_t sequence) {
    constexpr unsigned k_window = static_cast<unsigned>(k_media_replay_window);
    if (!window.started) {
        window.started = true;
        window.highest = sequence;
        window.bits = 1;
        return {};
    }
    if (sequence > window.highest) {
        const std::uint64_t shift = sequence - window.highest;
        if (shift >= k_window)
            window.bits = 0;
        else
            window.bits <<= shift;
        window.bits |= 1ull;
        window.highest = sequence;
        return {};
    }
    const std::uint64_t behind = window.highest - sequence;
    if (behind >= k_window)
        return Error::make(ErrorCode::Stale, "media sequence is outside the loss window");
    const std::uint64_t mask = 1ull << behind;
    if ((window.bits & mask) != 0)
        return Error::make(ErrorCode::Replay, "media sequence was already opened");
    window.bits |= mask;
    return {};
}

Error seal_media_frame(MediaKind kind, std::span<const std::uint8_t> key, std::uint32_t generation,
                       std::uint64_t sequence, std::uint32_t timestamp_ms,
                       std::span<const std::uint8_t> payload, std::vector<std::uint8_t>& packet) {
    packet.clear();
    Error err;
    if (!init_crypto(err))
        return err;
    if (key.size() != k_media_key_bytes)
        return Error::make(ErrorCode::InvalidArgument, "media key length is invalid");
    if (payload.size() > k_media_max_plaintext)
        return Error::make(ErrorCode::PlaintextTooLarge, "media frame exceeds 64 KiB");
    const std::size_t tag = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    packet.reserve(k_header + payload.size() + tag);
    const std::uint8_t* magic = magic_of(kind);
    packet.insert(packet.end(), magic, magic + 4);
    packet.push_back(k_version);
    packet.push_back(static_cast<std::uint8_t>(kind));
    append_u32(packet, generation);
    append_u64(packet, sequence);
    append_u32(packet, timestamp_ms);

    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    nonce[0] = static_cast<std::uint8_t>(kind);
    nonce[1] = static_cast<std::uint8_t>(generation >> 24);
    nonce[2] = static_cast<std::uint8_t>(generation >> 16);
    nonce[3] = static_cast<std::uint8_t>(generation >> 8);
    nonce[4] = static_cast<std::uint8_t>(generation);
    for (int i = 0; i < 8; ++i)
        nonce[static_cast<std::size_t>(5 + i)] = static_cast<std::uint8_t>(sequence >> (56 - 8 * i));

    const std::size_t cipher_pos = packet.size();
    packet.resize(cipher_pos + payload.size() + tag);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            packet.data() + cipher_pos, &written, payload.data(), payload.size(), packet.data(), k_header,
            nullptr, nonce.data(), key.data())
        != 0) {
        packet.clear();
        return Error::make(ErrorCode::CryptoUnavailable, "media frame seal failed");
    }
    return {};
}

Error open_media_frame(MediaKind kind, std::span<const std::uint8_t> key, std::uint32_t generation,
                       std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
                       std::uint32_t& timestamp_ms, std::uint64_t& sequence) {
    payload.clear();
    timestamp_ms = 0;
    sequence = 0;
    Error err;
    if (!init_crypto(err))
        return err;
    if (key.size() != k_media_key_bytes)
        return Error::make(ErrorCode::InvalidArgument, "media key length is invalid");
    const std::size_t tag = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (packet.size() < k_header + tag)
        return Error::make(ErrorCode::FrameTooSmall, "media frame is too small");
    const std::uint8_t* magic = magic_of(kind);
    if (std::memcmp(packet.data(), magic, 4) != 0 || packet[4] != k_version
        || packet[5] != static_cast<std::uint8_t>(kind))
        return Error::make(ErrorCode::InvalidFrame, "media frame kind or version is wrong");
    std::size_t pos = 6;
    std::uint32_t frame_generation = 0;
    if (!take_u32(packet, pos, frame_generation) || !take_u64(packet, pos, sequence)
        || !take_u32(packet, pos, timestamp_ms) || frame_generation != generation)
        return Error::make(ErrorCode::WrongSession, "media frame generation does not match the key");

    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    nonce[0] = static_cast<std::uint8_t>(kind);
    nonce[1] = static_cast<std::uint8_t>(generation >> 24);
    nonce[2] = static_cast<std::uint8_t>(generation >> 16);
    nonce[3] = static_cast<std::uint8_t>(generation >> 8);
    nonce[4] = static_cast<std::uint8_t>(generation);
    for (int i = 0; i < 8; ++i)
        nonce[static_cast<std::size_t>(5 + i)] = static_cast<std::uint8_t>(sequence >> (56 - 8 * i));

    const std::size_t cipher_len = packet.size() - k_header;
    payload.resize(cipher_len - tag);
    unsigned long long opened = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            payload.data(), &opened, nullptr, packet.data() + k_header, cipher_len, packet.data(), k_header,
            nonce.data(), key.data())
        != 0) {
        payload.clear();
        return Error::make(ErrorCode::AuthenticationFailed, "media frame failed authentication");
    }
    payload.resize(static_cast<std::size_t>(opened));
    return {};
}

} // namespace detail
} // namespace pm::encryption
