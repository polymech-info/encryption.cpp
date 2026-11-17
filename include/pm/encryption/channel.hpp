#pragma once

#include "pm/encryption/features.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pm::encryption {

inline constexpr std::size_t k_public_key_bytes = 32;
inline constexpr std::size_t k_secret_key_bytes = 32;
inline constexpr std::size_t k_session_id_bytes = 16;
inline constexpr std::size_t k_default_max_plaintext = 64U * 1024U * 1024U;
inline constexpr int k_replay_window = 64;
inline constexpr std::uint64_t k_first_sequence = 0;
inline constexpr bool k_channel_ratchet = false;

using PublicKey = std::array<std::uint8_t, k_public_key_bytes>;
using SessionId = std::array<std::uint8_t, k_session_id_bytes>;
using Seed = std::array<std::uint8_t, 32>;

enum class ErrorCode {
    Ok = 0,
    InvalidArgument,
    CryptoUnavailable,
    KeyAgreementFailed,
    PlaintextTooLarge,
    FrameTooSmall,
    FrameTooLarge,
    InvalidFrame,
    UnsupportedVersion,
    WrongDirection,
    WrongSession,
    WrongContentType,
    Replay,
    Stale,
    AuthenticationFailed,
    IdentityMismatch,
    BadSignature,
    UnexpectedState,
    NotRecipient,
};

struct Error {
    ErrorCode code = ErrorCode::Ok;
    std::string message;

    explicit operator bool() const noexcept { return code != ErrorCode::Ok; }
    static Error make(ErrorCode code, std::string message);
};

const char* error_code_name(ErrorCode code) noexcept;

/**
 * Bounded replay bitmap shared by the online channel and datagram flows.
 * SequenceZeroThenWindow rejects every sequence until 0 has been accepted.
 * AnySequenceThenWindow accepts whatever arrives first. A failed preview
 * does not change the window.
 */
class ReplayWindow {
public:
    enum class Rule : std::uint8_t {
        SequenceZeroThenWindow = 1,
        AnySequenceThenWindow = 2,
    };

    ReplayWindow() = default;
    ReplayWindow(Rule rule, int width) noexcept;

    Rule rule() const noexcept { return rule_; }
    int width() const noexcept { return width_; }
    Error preview(std::uint64_t sequence, ReplayWindow& next) const;

private:
    Rule rule_ = Rule::SequenceZeroThenWindow;
    int width_ = 64;
    std::uint64_t highest_ = 0;
    std::uint64_t bits_ = 0;
    bool started_ = false;
};

enum class EndpointRole : std::uint8_t {
    Initiator = 1,
    Responder = 2,
};

class KeyPair {
public:
    KeyPair();
    ~KeyPair();
    KeyPair(KeyPair&& other) noexcept;
    KeyPair& operator=(KeyPair&& other) noexcept;
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;

    static KeyPair generate(Error& err);
    static KeyPair from_seed(const Seed& seed, Error& err);

    const PublicKey& public_key() const noexcept { return public_; }
    bool valid() const noexcept { return valid_; }

private:
    PublicKey public_{};
    std::array<std::uint8_t, k_secret_key_bytes> secret_{};
    bool valid_ = false;

    friend class SecureChannel;
};

SessionId random_session_id(Error& err);
std::string encode_base64(std::span<const std::uint8_t> bytes);
bool decode_base64(std::string_view text, std::span<std::uint8_t> out, Error& err);
bool decode_base64(std::string_view text, std::vector<std::uint8_t>& out,
                   std::size_t max_decoded, Error& err);

/**
 * Transport-neutral online bidirectional encrypted channel.
 *
 * initiator() and responder() derive keys from the supplied X25519 publics and
 * do not authenticate a device identity. Handshake is the path that pins both
 * Ed25519 identities into the transcript and the derived keys.
 *
 * One transmit key and one receive key live for the process. k_channel_ratchet
 * is false: a copy of either key decrypts every frame in that direction, past
 * and future, until the process exits. This channel does not keep history.
 * Callers that need a transcript store it somewhere else.
 *
 * The first accepted sequence is k_first_sequence (0). A higher sequence
 * before that does not move the window. After 0, k_replay_window frames may
 * arrive out of order. SecureChannel does not own transport, persistence,
 * authorization, or application payload semantics.
 */
class SecureChannel {
public:
    SecureChannel();
    ~SecureChannel();
    SecureChannel(SecureChannel&& other) noexcept;
    SecureChannel& operator=(SecureChannel&& other) noexcept;
    SecureChannel(const SecureChannel&) = delete;
    SecureChannel& operator=(const SecureChannel&) = delete;

#if PM_ENCRYPTION_UNAUTHENTICATED_KX
    static SecureChannel initiator(KeyPair local, const PublicKey& responder_public,
                                   const SessionId& session_id, std::string context,
                                   Error& err);
    static SecureChannel responder(KeyPair local, const PublicKey& initiator_public,
                                   const SessionId& session_id, std::string context,
                                   Error& err);
#endif

    bool valid() const noexcept { return valid_; }
    EndpointRole role() const noexcept { return role_; }
    const SessionId& session_id() const noexcept { return session_id_; }
    std::uint64_t next_send_sequence() const noexcept { return next_tx_; }

    Error seal(std::span<const std::uint8_t> plaintext,
               std::string_view content_type,
               std::vector<std::uint8_t>& frame,
               std::size_t max_plaintext = k_default_max_plaintext);

    Error open(std::span<const std::uint8_t> frame,
               std::string_view expected_content_type,
               std::vector<std::uint8_t>& plaintext,
               std::size_t max_plaintext = k_default_max_plaintext);

private:
    friend class Handshake;

    static SecureChannel from_authenticated_exchange(
        EndpointRole role, KeyPair local_ephemeral, const PublicKey& remote_ephemeral,
        const SessionId& session_id, std::span<const std::uint8_t> transcript, Error& err);

    EndpointRole role_ = EndpointRole::Initiator;
    SessionId session_id_{};
    std::string context_;
    std::array<std::uint8_t, 32> rx_key_{};
    std::array<std::uint8_t, 32> tx_key_{};
    std::uint64_t next_tx_ = 0;
    ReplayWindow replay_{};
    bool valid_ = false;
};

} // namespace pm::encryption
