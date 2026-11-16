#pragma once

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
};

struct Error {
    ErrorCode code = ErrorCode::Ok;
    std::string message;

    explicit operator bool() const noexcept { return code != ErrorCode::Ok; }
    static Error make(ErrorCode code, std::string message);
};

const char* error_code_name(ErrorCode code) noexcept;

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
 * The caller authenticates the peer public key. SecureChannel derives
 * independent initiator-to-responder and responder-to-initiator keys, binds
 * every frame to a session id and caller context, and rejects replayed or stale
 * frames. It does not own transport, identity, persistence, authorization, or
 * application payload semantics.
 */
class SecureChannel {
public:
    SecureChannel();
    ~SecureChannel();
    SecureChannel(SecureChannel&& other) noexcept;
    SecureChannel& operator=(SecureChannel&& other) noexcept;
    SecureChannel(const SecureChannel&) = delete;
    SecureChannel& operator=(const SecureChannel&) = delete;

    static SecureChannel initiator(KeyPair local, const PublicKey& responder_public,
                                   const SessionId& session_id, std::string context,
                                   Error& err);
    static SecureChannel responder(KeyPair local, const PublicKey& initiator_public,
                                   const SessionId& session_id, std::string context,
                                   Error& err);

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
    EndpointRole role_ = EndpointRole::Initiator;
    SessionId session_id_{};
    std::string context_;
    std::array<std::uint8_t, 32> rx_key_{};
    std::array<std::uint8_t, 32> tx_key_{};
    std::uint64_t next_tx_ = 0;
    std::uint64_t rx_highest_ = 0;
    std::uint64_t rx_bitmap_ = 0;
    bool rx_initialized_ = false;
    bool valid_ = false;
};

} // namespace pm::encryption
