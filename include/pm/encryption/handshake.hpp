#pragma once

#include "pm/encryption/identity.hpp"

#include <string>
#include <vector>

namespace pm::encryption {

/**
 * Mutually authenticated online handshake for peers that already pinned each
 * other's Ed25519 identity.
 *
 * Three messages, in the shape of SIGMA-I:
 *   1. initiator ephemeral
 *   2. responder ephemeral and responder signature
 *   3. initiator signature
 *
 * Both signatures cover the version, suite, context, session id, both
 * identities, and both ephemerals. Channel keys are HKDF-SHA256 of the X25519
 * exchange, salted with that transcript. Identity public keys are visible to
 * the transport. This is not Signal, Noise, or TLS, and it does not create
 * trust by itself.
 */
class Handshake {
public:
    Handshake();
    ~Handshake();
    Handshake(Handshake&& other) noexcept;
    Handshake& operator=(Handshake&& other) noexcept;
    Handshake(const Handshake&) = delete;
    Handshake& operator=(const Handshake&) = delete;

    static Handshake initiator(Identity local, const IdentityPublic& responder,
                               std::string context, Error& err);
    static Handshake initiator(Identity local, const IdentityPublic& responder,
                               std::string context, KeyPair ephemeral,
                               SessionId session_id, Error& err);
    static Handshake responder(Identity local, const IdentityPublic& initiator,
                               std::string context, Error& err);
    static Handshake responder(Identity local, const IdentityPublic& initiator,
                               std::string context, KeyPair ephemeral, Error& err);

    Error write_message(std::vector<std::uint8_t>& message);
    Error read_message(std::span<const std::uint8_t> message);
    bool complete() const noexcept;
    SecureChannel take_channel(Error& err);

private:
    enum class Phase : std::uint8_t {
        Empty = 0,
        InitiatorSend1,
        InitiatorRecv2,
        InitiatorSend3,
        InitiatorDone,
        ResponderRecv1,
        ResponderSend2,
        ResponderRecv3,
        ResponderDone,
        Failed,
    };

    std::vector<std::uint8_t> key_transcript() const;
    Error sign_role(EndpointRole role, Signature& signature) const;
    Error verify_role(EndpointRole role, std::span<const std::uint8_t> signature) const;
    Error derive();
    void fail();

    Phase phase_ = Phase::Empty;
    EndpointRole role_ = EndpointRole::Initiator;
    Identity local_{};
    std::string context_;
    SessionId session_id_{};
    KeyPair ephemeral_{};
    IdentityPublic initiator_identity_{};
    IdentityPublic responder_identity_{};
    PublicKey initiator_ephemeral_{};
    PublicKey responder_ephemeral_{};
    SecureChannel channel_{};
    bool channel_ready_ = false;
};

} // namespace pm::encryption
