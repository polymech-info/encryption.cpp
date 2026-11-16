#include "pm/encryption/channel.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace pm::encryption {
namespace {

constexpr std::uint8_t k_magic[] = {'P', 'M', 'E', '2'};
constexpr std::uint8_t k_version = 1;
constexpr std::size_t k_nonce_bytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t k_tag_bytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::size_t k_fixed_header =
    sizeof(k_magic) + 1 + 1 + 2 + 8 + k_session_id_bytes + k_nonce_bytes + 4;
constexpr std::size_t k_max_content_type = 128;
constexpr std::size_t k_max_context = 4096;

bool init_crypto(Error& err) {
    if (sodium_init() < 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "libsodium initialization failed");
        return false;
    }
    return true;
}

void wipe(void* data, std::size_t size) {
    if (data && size)
        sodium_memzero(data, size);
}

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

bool take_u16(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint16_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 2)
        return false;
    out = (static_cast<std::uint16_t>(bytes[pos]) << 8)
        | static_cast<std::uint16_t>(bytes[pos + 1]);
    pos += 2;
    return true;
}

bool take_u32(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint32_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 4)
        return false;
    out = 0;
    for (int i = 0; i < 4; ++i)
        out = (out << 8) | bytes[pos++];
    return true;
}

bool take_u64(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint64_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 8)
        return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out = (out << 8) | bytes[pos++];
    return true;
}

std::uint8_t tx_direction(EndpointRole role) {
    return role == EndpointRole::Initiator ? 1 : 2;
}

std::uint8_t rx_direction(EndpointRole role) {
    return role == EndpointRole::Initiator ? 2 : 1;
}

std::vector<std::uint8_t> make_aad(std::span<const std::uint8_t> wire_header_and_type,
                                   std::string_view context) {
    std::vector<std::uint8_t> aad;
    aad.reserve(wire_header_and_type.size() + 4 + context.size());
    aad.insert(aad.end(), wire_header_and_type.begin(), wire_header_and_type.end());
    append_u32(aad, static_cast<std::uint32_t>(context.size()));
    aad.insert(aad.end(), context.begin(), context.end());
    return aad;
}

Error validate_setup(const KeyPair& local, const PublicKey& remote,
                     const SessionId& session_id, std::string_view context) {
    Error err;
    if (!init_crypto(err))
        return err;
    if (!local.valid())
        return Error::make(ErrorCode::InvalidArgument, "local key pair is invalid");
    PublicKey zero_public{};
    if (sodium_memcmp(remote.data(), zero_public.data(), remote.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "remote public key is empty");
    SessionId zero_session{};
    if (sodium_memcmp(session_id.data(), zero_session.data(), session_id.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "session id is empty");
    if (context.empty() || context.size() > k_max_context)
        return Error::make(ErrorCode::InvalidArgument, "context length is invalid");
    return {};
}

} // namespace

Error Error::make(ErrorCode code, std::string message) {
    return Error{code, std::move(message)};
}

const char* error_code_name(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::Ok: return "ok";
    case ErrorCode::InvalidArgument: return "invalid_argument";
    case ErrorCode::CryptoUnavailable: return "crypto_unavailable";
    case ErrorCode::KeyAgreementFailed: return "key_agreement_failed";
    case ErrorCode::PlaintextTooLarge: return "plaintext_too_large";
    case ErrorCode::FrameTooSmall: return "frame_too_small";
    case ErrorCode::FrameTooLarge: return "frame_too_large";
    case ErrorCode::InvalidFrame: return "invalid_frame";
    case ErrorCode::UnsupportedVersion: return "unsupported_version";
    case ErrorCode::WrongDirection: return "wrong_direction";
    case ErrorCode::WrongSession: return "wrong_session";
    case ErrorCode::WrongContentType: return "wrong_content_type";
    case ErrorCode::Replay: return "replay";
    case ErrorCode::Stale: return "stale";
    case ErrorCode::AuthenticationFailed: return "authentication_failed";
    case ErrorCode::IdentityMismatch: return "identity_mismatch";
    case ErrorCode::BadSignature: return "bad_signature";
    case ErrorCode::UnexpectedState: return "unexpected_state";
    case ErrorCode::NotRecipient: return "not_recipient";
    }
    return "unknown";
}

KeyPair::KeyPair() = default;

KeyPair::~KeyPair() {
    wipe(secret_.data(), secret_.size());
}

KeyPair::KeyPair(KeyPair&& other) noexcept
    : public_(other.public_), secret_(other.secret_), valid_(other.valid_) {
    wipe(other.secret_.data(), other.secret_.size());
    other.public_.fill(0);
    other.valid_ = false;
}

KeyPair& KeyPair::operator=(KeyPair&& other) noexcept {
    if (this == &other)
        return *this;
    wipe(secret_.data(), secret_.size());
    public_ = other.public_;
    secret_ = other.secret_;
    valid_ = other.valid_;
    wipe(other.secret_.data(), other.secret_.size());
    other.public_.fill(0);
    other.valid_ = false;
    return *this;
}

KeyPair KeyPair::generate(Error& err) {
    err = {};
    KeyPair out;
    if (!init_crypto(err))
        return out;
    if (crypto_kx_keypair(out.public_.data(), out.secret_.data()) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "key generation failed");
        return out;
    }
    out.valid_ = true;
    return out;
}

KeyPair KeyPair::from_seed(const Seed& seed, Error& err) {
    err = {};
    KeyPair out;
    if (!init_crypto(err))
        return out;
    if (crypto_kx_seed_keypair(out.public_.data(), out.secret_.data(), seed.data()) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "seeded key generation failed");
        return out;
    }
    out.valid_ = true;
    return out;
}

SessionId random_session_id(Error& err) {
    err = {};
    SessionId out{};
    if (!init_crypto(err))
        return out;
    randombytes_buf(out.data(), out.size());
    return out;
}

std::string encode_base64(std::span<const std::uint8_t> bytes) {
    Error err;
    if (!init_crypto(err))
        return {};
    std::string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING),
                    '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(),
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

bool decode_base64(std::string_view text, std::span<std::uint8_t> out, Error& err) {
    err = {};
    if (!init_crypto(err))
        return false;
    std::size_t actual = 0;
    const char* end = nullptr;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr,
                         &actual, &end, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
        || actual != out.size() || end != text.data() + text.size()) {
        err = Error::make(ErrorCode::InvalidArgument, "invalid base64 or decoded length");
        return false;
    }
    return true;
}

bool decode_base64(std::string_view text, std::vector<std::uint8_t>& out,
                   std::size_t max_decoded, Error& err) {
    out.clear();
    err = {};
    if (!init_crypto(err))
        return false;
    if (text.size() > max_decoded * 2 + 8) {
        err = Error::make(ErrorCode::FrameTooLarge, "base64 input exceeds the configured limit");
        return false;
    }
    out.resize(std::min(max_decoded, text.size()));
    std::size_t actual = 0;
    const char* end = nullptr;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr,
                         &actual, &end, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
        || end != text.data() + text.size()) {
        out.clear();
        err = Error::make(ErrorCode::InvalidArgument, "invalid base64");
        return false;
    }
    out.resize(actual);
    return true;
}

SecureChannel::SecureChannel() = default;

SecureChannel::~SecureChannel() {
    wipe(rx_key_.data(), rx_key_.size());
    wipe(tx_key_.data(), tx_key_.size());
}

SecureChannel::SecureChannel(SecureChannel&& other) noexcept
    : role_(other.role_),
      session_id_(other.session_id_),
      context_(std::move(other.context_)),
      rx_key_(other.rx_key_),
      tx_key_(other.tx_key_),
      next_tx_(other.next_tx_),
      rx_highest_(other.rx_highest_),
      rx_bitmap_(other.rx_bitmap_),
      rx_initialized_(other.rx_initialized_),
      valid_(other.valid_) {
    wipe(other.rx_key_.data(), other.rx_key_.size());
    wipe(other.tx_key_.data(), other.tx_key_.size());
    other.valid_ = false;
}

SecureChannel& SecureChannel::operator=(SecureChannel&& other) noexcept {
    if (this == &other)
        return *this;
    wipe(rx_key_.data(), rx_key_.size());
    wipe(tx_key_.data(), tx_key_.size());
    role_ = other.role_;
    session_id_ = other.session_id_;
    context_ = std::move(other.context_);
    rx_key_ = other.rx_key_;
    tx_key_ = other.tx_key_;
    next_tx_ = other.next_tx_;
    rx_highest_ = other.rx_highest_;
    rx_bitmap_ = other.rx_bitmap_;
    rx_initialized_ = other.rx_initialized_;
    valid_ = other.valid_;
    wipe(other.rx_key_.data(), other.rx_key_.size());
    wipe(other.tx_key_.data(), other.tx_key_.size());
    other.valid_ = false;
    return *this;
}

SecureChannel SecureChannel::from_authenticated_exchange(
    EndpointRole role, KeyPair local_ephemeral, const PublicKey& remote_ephemeral,
    const SessionId& session_id, std::span<const std::uint8_t> transcript, Error& err) {
    err = {};
    SecureChannel out;
    if (!local_ephemeral.valid()) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake ephemeral is invalid");
        return out;
    }
    if (transcript.empty() || transcript.size() > 8192) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake transcript length is invalid");
        return out;
    }
    PublicKey zero_public{};
    if (sodium_memcmp(remote_ephemeral.data(), zero_public.data(), zero_public.size()) == 0
        || sodium_is_zero(session_id.data(), session_id.size()) == 1) {
        err = Error::make(ErrorCode::InvalidArgument,
                          "handshake peer ephemeral or session is empty");
        return out;
    }

    std::array<std::uint8_t, 32> raw_rx{};
    std::array<std::uint8_t, 32> raw_tx{};
    const int agreed = role == EndpointRole::Initiator
        ? crypto_kx_client_session_keys(raw_rx.data(), raw_tx.data(),
                                        local_ephemeral.public_.data(),
                                        local_ephemeral.secret_.data(),
                                        remote_ephemeral.data())
        : crypto_kx_server_session_keys(raw_rx.data(), raw_tx.data(),
                                        local_ephemeral.public_.data(),
                                        local_ephemeral.secret_.data(),
                                        remote_ephemeral.data());
    if (agreed != 0) {
        wipe(raw_rx.data(), raw_rx.size());
        wipe(raw_tx.data(), raw_tx.size());
        err = Error::make(ErrorCode::KeyAgreementFailed, "authenticated key agreement failed");
        return out;
    }

    std::array<std::uint8_t, 32> salt{};
    if (crypto_generichash(salt.data(), salt.size(),
                           transcript.data(),
                           static_cast<unsigned long long>(transcript.size()),
                           nullptr, 0) != 0) {
        wipe(raw_rx.data(), raw_rx.size());
        wipe(raw_tx.data(), raw_tx.size());
        err = Error::make(ErrorCode::CryptoUnavailable, "handshake transcript hash failed");
        return out;
    }

    auto derive_key = [&](std::array<std::uint8_t, 32>& dest,
                          const std::array<std::uint8_t, 32>& ikm,
                          const char* info) {
        unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
        if (crypto_kdf_hkdf_sha256_extract(prk, salt.data(), salt.size(),
                                           ikm.data(), ikm.size()) != 0) {
            sodium_memzero(prk, sizeof(prk));
            return false;
        }
        const bool ok = crypto_kdf_hkdf_sha256_expand(
                            dest.data(), dest.size(), info, std::strlen(info), prk) == 0;
        sodium_memzero(prk, sizeof(prk));
        return ok;
    };

    std::array<std::uint8_t, 32> rx{};
    std::array<std::uint8_t, 32> tx{};
    const bool derived = role == EndpointRole::Initiator
        ? derive_key(tx, raw_tx, "pm.encryption.channel.i2r.v1")
            && derive_key(rx, raw_rx, "pm.encryption.channel.r2i.v1")
        : derive_key(tx, raw_tx, "pm.encryption.channel.r2i.v1")
            && derive_key(rx, raw_rx, "pm.encryption.channel.i2r.v1");
    wipe(raw_rx.data(), raw_rx.size());
    wipe(raw_tx.data(), raw_tx.size());
    if (!derived) {
        wipe(rx.data(), rx.size());
        wipe(tx.data(), tx.size());
        wipe(salt.data(), salt.size());
        err = Error::make(ErrorCode::KeyAgreementFailed, "authenticated key derivation failed");
        return out;
    }

    out.role_ = role;
    out.session_id_ = session_id;
    out.context_.assign(reinterpret_cast<const char*>(salt.data()), salt.size());
    out.rx_key_ = rx;
    out.tx_key_ = tx;
    out.valid_ = true;
    wipe(rx.data(), rx.size());
    wipe(tx.data(), tx.size());
    wipe(salt.data(), salt.size());
    return out;
}

#if PM_ENCRYPTION_UNAUTHENTICATED_KX
SecureChannel SecureChannel::initiator(KeyPair local, const PublicKey& responder_public,
                                       const SessionId& session_id, std::string context,
                                       Error& err) {
    err = validate_setup(local, responder_public, session_id, context);
    SecureChannel out;
    if (err)
        return out;
    if (crypto_kx_client_session_keys(out.rx_key_.data(), out.tx_key_.data(),
                                      local.public_.data(), local.secret_.data(),
                                      responder_public.data()) != 0) {
        err = Error::make(ErrorCode::KeyAgreementFailed, "initiator key agreement failed");
        return out;
    }
    out.role_ = EndpointRole::Initiator;
    out.session_id_ = session_id;
    out.context_ = std::move(context);
    out.valid_ = true;
    return out;
}

SecureChannel SecureChannel::responder(KeyPair local, const PublicKey& initiator_public,
                                       const SessionId& session_id, std::string context,
                                       Error& err) {
    err = validate_setup(local, initiator_public, session_id, context);
    SecureChannel out;
    if (err)
        return out;
    if (crypto_kx_server_session_keys(out.rx_key_.data(), out.tx_key_.data(),
                                      local.public_.data(), local.secret_.data(),
                                      initiator_public.data()) != 0) {
        err = Error::make(ErrorCode::KeyAgreementFailed, "responder key agreement failed");
        return out;
    }
    out.role_ = EndpointRole::Responder;
    out.session_id_ = session_id;
    out.context_ = std::move(context);
    out.valid_ = true;
    return out;
}
#endif

Error SecureChannel::seal(std::span<const std::uint8_t> plaintext,
                          std::string_view content_type,
                          std::vector<std::uint8_t>& frame,
                          std::size_t max_plaintext) {
    frame.clear();
    if (!valid_)
        return Error::make(ErrorCode::InvalidArgument, "channel is invalid");
    if (plaintext.size() > max_plaintext
        || plaintext.size() > std::numeric_limits<std::uint32_t>::max() - k_tag_bytes)
        return Error::make(ErrorCode::PlaintextTooLarge, "plaintext exceeds the configured limit");
    if (content_type.empty() || content_type.size() > k_max_content_type)
        return Error::make(ErrorCode::InvalidArgument, "content type length is invalid");
    if (next_tx_ == std::numeric_limits<std::uint64_t>::max())
        return Error::make(ErrorCode::InvalidArgument, "send sequence is exhausted");

    const std::uint32_t cipher_size =
        static_cast<std::uint32_t>(plaintext.size() + k_tag_bytes);
    frame.reserve(k_fixed_header + content_type.size() + cipher_size);
    frame.insert(frame.end(), std::begin(k_magic), std::end(k_magic));
    frame.push_back(k_version);
    frame.push_back(tx_direction(role_));
    append_u16(frame, static_cast<std::uint16_t>(content_type.size()));
    append_u64(frame, next_tx_);
    frame.insert(frame.end(), session_id_.begin(), session_id_.end());
    const std::size_t nonce_pos = frame.size();
    frame.resize(frame.size() + k_nonce_bytes);
    randombytes_buf(frame.data() + nonce_pos, k_nonce_bytes);
    append_u32(frame, cipher_size);
    frame.insert(frame.end(), content_type.begin(), content_type.end());

    const auto aad = make_aad(frame, context_);
    const std::size_t cipher_pos = frame.size();
    frame.resize(cipher_pos + cipher_size);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            frame.data() + cipher_pos, &written,
            plaintext.empty() ? nullptr : plaintext.data(),
            static_cast<unsigned long long>(plaintext.size()),
            aad.data(), static_cast<unsigned long long>(aad.size()),
            nullptr, frame.data() + nonce_pos, tx_key_.data()) != 0
        || written != cipher_size) {
        frame.clear();
        return Error::make(ErrorCode::CryptoUnavailable, "frame encryption failed");
    }
    ++next_tx_;
    return {};
}

Error SecureChannel::open(std::span<const std::uint8_t> frame,
                          std::string_view expected_content_type,
                          std::vector<std::uint8_t>& plaintext,
                          std::size_t max_plaintext) {
    plaintext.clear();
    if (!valid_)
        return Error::make(ErrorCode::InvalidArgument, "channel is invalid");
    if (frame.size() < k_fixed_header + k_tag_bytes)
        return Error::make(ErrorCode::FrameTooSmall, "encrypted frame is truncated");
    if (frame.size() > k_fixed_header + k_max_content_type + max_plaintext + k_tag_bytes)
        return Error::make(ErrorCode::FrameTooLarge, "encrypted frame exceeds the configured limit");

    std::size_t pos = 0;
    if (std::memcmp(frame.data(), k_magic, sizeof(k_magic)) != 0)
        return Error::make(ErrorCode::InvalidFrame, "encrypted frame magic is invalid");
    pos += sizeof(k_magic);
    if (frame[pos++] != k_version)
        return Error::make(ErrorCode::UnsupportedVersion, "encrypted frame version is unsupported");
    if (frame[pos++] != rx_direction(role_))
        return Error::make(ErrorCode::WrongDirection, "encrypted frame direction is invalid");

    std::uint16_t content_type_size = 0;
    std::uint64_t sequence = 0;
    if (!take_u16(frame, pos, content_type_size) || content_type_size == 0
        || content_type_size > k_max_content_type || !take_u64(frame, pos, sequence))
        return Error::make(ErrorCode::InvalidFrame, "encrypted frame header is invalid");

    if (pos > frame.size() || frame.size() - pos < session_id_.size())
        return Error::make(ErrorCode::FrameTooSmall, "encrypted frame session is truncated");
    if (sodium_memcmp(frame.data() + pos, session_id_.data(), session_id_.size()) != 0)
        return Error::make(ErrorCode::WrongSession, "encrypted frame belongs to another session");
    pos += session_id_.size();

    if (pos > frame.size() || frame.size() - pos < k_nonce_bytes)
        return Error::make(ErrorCode::FrameTooSmall, "encrypted frame nonce is truncated");
    const std::size_t nonce_pos = pos;
    pos += k_nonce_bytes;

    std::uint32_t cipher_size = 0;
    if (!take_u32(frame, pos, cipher_size) || cipher_size < k_tag_bytes
        || cipher_size - k_tag_bytes > max_plaintext)
        return Error::make(ErrorCode::InvalidFrame, "encrypted frame ciphertext length is invalid");
    if (pos > frame.size() || frame.size() - pos < content_type_size)
        return Error::make(ErrorCode::FrameTooSmall, "encrypted frame content type is truncated");
    const std::string_view content_type(
        reinterpret_cast<const char*>(frame.data() + pos), content_type_size);
    pos += content_type_size;
    if (content_type != expected_content_type)
        return Error::make(ErrorCode::WrongContentType, "encrypted frame content type is unexpected");
    if (pos > frame.size() || frame.size() - pos != cipher_size)
        return Error::make(ErrorCode::InvalidFrame, "encrypted frame size does not match its header");

    if (rx_initialized_ && sequence <= rx_highest_) {
        const std::uint64_t delta = rx_highest_ - sequence;
        if (delta >= 64)
            return Error::make(ErrorCode::Stale, "encrypted frame is outside the replay window");
        if ((rx_bitmap_ & (std::uint64_t{1} << delta)) != 0)
            return Error::make(ErrorCode::Replay, "encrypted frame was already accepted");
    }

    const auto aad = make_aad(frame.first(pos), context_);
    plaintext.resize(cipher_size - k_tag_bytes);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.empty() ? nullptr : plaintext.data(), &written, nullptr,
            frame.data() + pos, cipher_size,
            aad.data(), static_cast<unsigned long long>(aad.size()),
            frame.data() + nonce_pos, rx_key_.data()) != 0) {
        plaintext.clear();
        return Error::make(ErrorCode::AuthenticationFailed,
                           "encrypted frame authentication failed");
    }
    plaintext.resize(static_cast<std::size_t>(written));

    if (!rx_initialized_) {
        rx_initialized_ = true;
        rx_highest_ = sequence;
        rx_bitmap_ = 1;
    } else if (sequence > rx_highest_) {
        const std::uint64_t shift = sequence - rx_highest_;
        rx_bitmap_ = shift >= 64 ? 1 : ((rx_bitmap_ << shift) | 1);
        rx_highest_ = sequence;
    } else {
        rx_bitmap_ |= std::uint64_t{1} << (rx_highest_ - sequence);
    }
    return {};
}

} // namespace pm::encryption
