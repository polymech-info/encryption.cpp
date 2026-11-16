#include "pm/encryption/handshake.hpp"

#include <sodium.h>

#include <cstring>
#include <utility>

namespace pm::encryption {
namespace {

constexpr std::uint8_t k_magic[] = {'P', 'M', 'E', 'H'};
constexpr std::uint8_t k_version = 1;
constexpr std::uint8_t k_suite = 1;
constexpr std::uint8_t k_message_1 = 1;
constexpr std::uint8_t k_message_2 = 2;
constexpr std::uint8_t k_message_3 = 3;
constexpr std::size_t k_header = sizeof(k_magic) + 3;
constexpr std::size_t k_message_1_size = k_header + k_session_id_bytes + 32 + 32;
constexpr std::size_t k_message_2_size = k_message_1_size + k_signature_bytes;
constexpr std::size_t k_message_3_size = k_header + k_session_id_bytes + k_signature_bytes;
constexpr std::size_t k_max_context = 4096;
constexpr char k_domain[] = "pm.encryption.handshake.sigma-i.v1";

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

bool zero_bytes(std::span<const std::uint8_t> bytes) {
    return sodium_is_zero(bytes.data(), bytes.size()) == 1;
}

void append_header(std::vector<std::uint8_t>& out, std::uint8_t type) {
    out.insert(out.end(), std::begin(k_magic), std::end(k_magic));
    out.push_back(k_version);
    out.push_back(k_suite);
    out.push_back(type);
}

struct Header {
    std::uint8_t version = 0;
    std::uint8_t suite = 0;
    std::uint8_t type = 0;
};

Error parse_header(std::span<const std::uint8_t> message, Header& out) {
    if (message.size() < k_header)
        return Error::make(ErrorCode::FrameTooSmall, "handshake message is truncated");
    if (std::memcmp(message.data(), k_magic, sizeof(k_magic)) != 0)
        return Error::make(ErrorCode::InvalidFrame, "handshake magic is invalid");
    out.version = message[4];
    out.suite = message[5];
    out.type = message[6];
    if (out.version != k_version || out.suite != k_suite)
        return Error::make(ErrorCode::UnsupportedVersion, "handshake version or suite is unsupported");
    return {};
}

} // namespace

Handshake::Handshake() = default;
Handshake::~Handshake() = default;
Handshake::Handshake(Handshake&&) noexcept = default;
Handshake& Handshake::operator=(Handshake&&) noexcept = default;

Handshake Handshake::initiator(Identity local, const IdentityPublic& responder,
                               std::string context, Error& err) {
    auto ephemeral = KeyPair::generate(err);
    if (err)
        return {};
    auto session_id = random_session_id(err);
    if (err)
        return {};
    return initiator(std::move(local), responder, std::move(context),
                     std::move(ephemeral), session_id, err);
}

Handshake Handshake::initiator(Identity local, const IdentityPublic& responder,
                               std::string context, KeyPair ephemeral,
                               SessionId session_id, Error& err) {
    err = {};
    Handshake out;
    if (!local.valid() || !ephemeral.valid()) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake identity or ephemeral is invalid");
        return {};
    }
    if (context.empty() || context.size() > k_max_context) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake context length is invalid");
        return {};
    }
    if (zero_bytes(responder) || zero_bytes(session_id)) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake peer identity or session is empty");
        return {};
    }
    if (sodium_memcmp(local.public_key().data(), responder.data(), responder.size()) == 0) {
        err = Error::make(ErrorCode::InvalidArgument, "local and peer identities are the same");
        return {};
    }
    out.role_ = EndpointRole::Initiator;
    out.phase_ = Phase::InitiatorSend1;
    out.initiator_identity_ = local.public_key();
    out.responder_identity_ = responder;
    out.initiator_ephemeral_ = ephemeral.public_key();
    out.local_ = std::move(local);
    out.ephemeral_ = std::move(ephemeral);
    out.context_ = std::move(context);
    out.session_id_ = session_id;
    return out;
}

Handshake Handshake::responder(Identity local, const IdentityPublic& initiator,
                               std::string context, Error& err) {
    auto ephemeral = KeyPair::generate(err);
    if (err)
        return {};
    return responder(std::move(local), initiator, std::move(context), std::move(ephemeral), err);
}

Handshake Handshake::responder(Identity local, const IdentityPublic& initiator,
                               std::string context, KeyPair ephemeral, Error& err) {
    err = {};
    Handshake out;
    if (!local.valid() || !ephemeral.valid()) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake identity or ephemeral is invalid");
        return {};
    }
    if (context.empty() || context.size() > k_max_context) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake context length is invalid");
        return {};
    }
    if (zero_bytes(initiator)) {
        err = Error::make(ErrorCode::InvalidArgument, "handshake peer identity is empty");
        return {};
    }
    if (sodium_memcmp(local.public_key().data(), initiator.data(), initiator.size()) == 0) {
        err = Error::make(ErrorCode::InvalidArgument, "local and peer identities are the same");
        return {};
    }
    out.role_ = EndpointRole::Responder;
    out.phase_ = Phase::ResponderRecv1;
    out.responder_identity_ = local.public_key();
    out.initiator_identity_ = initiator;
    out.responder_ephemeral_ = ephemeral.public_key();
    out.local_ = std::move(local);
    out.ephemeral_ = std::move(ephemeral);
    out.context_ = std::move(context);
    return out;
}

std::vector<std::uint8_t> Handshake::key_transcript() const {
    std::vector<std::uint8_t> out;
    out.reserve(sizeof(k_domain) + context_.size() + 128);
    out.insert(out.end(), k_domain, k_domain + sizeof(k_domain) - 1);
    out.push_back(k_version);
    out.push_back(k_suite);
    append_u32(out, static_cast<std::uint32_t>(context_.size()));
    out.insert(out.end(), context_.begin(), context_.end());
    out.insert(out.end(), session_id_.begin(), session_id_.end());
    out.insert(out.end(), initiator_identity_.begin(), initiator_identity_.end());
    out.insert(out.end(), responder_identity_.begin(), responder_identity_.end());
    out.insert(out.end(), initiator_ephemeral_.begin(), initiator_ephemeral_.end());
    out.insert(out.end(), responder_ephemeral_.begin(), responder_ephemeral_.end());
    return out;
}

Error Handshake::sign_role(EndpointRole role, Signature& signature) const {
    auto transcript = key_transcript();
    transcript.push_back(static_cast<std::uint8_t>(role));
    return local_.sign(transcript, signature);
}

Error Handshake::verify_role(EndpointRole role, std::span<const std::uint8_t> signature) const {
    auto transcript = key_transcript();
    transcript.push_back(static_cast<std::uint8_t>(role));
    const IdentityPublic& key =
        role == EndpointRole::Initiator ? initiator_identity_ : responder_identity_;
    return Identity::verify(key, transcript, signature);
}

Error Handshake::derive() {
    if (zero_bytes(initiator_ephemeral_) || zero_bytes(responder_ephemeral_)
        || zero_bytes(session_id_))
        return Error::make(ErrorCode::InvalidArgument, "handshake transcript is incomplete");
    Error err;
    channel_ = SecureChannel::from_authenticated_exchange(
        role_, std::move(ephemeral_),
        role_ == EndpointRole::Initiator ? responder_ephemeral_ : initiator_ephemeral_,
        session_id_, key_transcript(), err);
    if (err)
        return err;
    channel_ready_ = channel_.valid();
    if (!channel_ready_)
        return Error::make(ErrorCode::KeyAgreementFailed, "authenticated channel derivation failed");
    return {};
}

void Handshake::fail() {
    phase_ = Phase::Failed;
    channel_ready_ = false;
    local_ = Identity{};
    ephemeral_ = KeyPair{};
    channel_ = SecureChannel{};
}

Error Handshake::write_message(std::vector<std::uint8_t>& message) {
    message.clear();
    if (phase_ == Phase::InitiatorSend1) {
        append_header(message, k_message_1);
        message.insert(message.end(), session_id_.begin(), session_id_.end());
        message.insert(message.end(), initiator_identity_.begin(), initiator_identity_.end());
        message.insert(message.end(), initiator_ephemeral_.begin(), initiator_ephemeral_.end());
        phase_ = Phase::InitiatorRecv2;
        return {};
    }
    if (phase_ == Phase::ResponderSend2) {
        Signature signature{};
        if (Error err = sign_role(EndpointRole::Responder, signature)) {
            fail();
            return err;
        }
        append_header(message, k_message_2);
        message.insert(message.end(), session_id_.begin(), session_id_.end());
        message.insert(message.end(), responder_identity_.begin(), responder_identity_.end());
        message.insert(message.end(), responder_ephemeral_.begin(), responder_ephemeral_.end());
        message.insert(message.end(), signature.begin(), signature.end());
        phase_ = Phase::ResponderRecv3;
        return {};
    }
    if (phase_ == Phase::InitiatorSend3) {
        Signature signature{};
        if (Error err = sign_role(EndpointRole::Initiator, signature)) {
            fail();
            return err;
        }
        append_header(message, k_message_3);
        message.insert(message.end(), session_id_.begin(), session_id_.end());
        message.insert(message.end(), signature.begin(), signature.end());
        if (Error err = derive()) {
            message.clear();
            fail();
            return err;
        }
        phase_ = Phase::InitiatorDone;
        return {};
    }
    return Error::make(ErrorCode::UnexpectedState, "handshake cannot write a message in this state");
}

Error Handshake::read_message(std::span<const std::uint8_t> message) {
    Header header;
    if (Error err = parse_header(message, header)) {
        fail();
        return err;
    }

    if (phase_ == Phase::ResponderRecv1) {
        if (header.type != k_message_1 || message.size() != k_message_1_size) {
            fail();
            return Error::make(ErrorCode::InvalidFrame, "handshake message 1 is invalid");
        }
        std::size_t pos = k_header;
        SessionId session_id{};
        IdentityPublic initiator{};
        PublicKey ephemeral{};
        std::memcpy(session_id.data(), message.data() + pos, session_id.size());
        pos += session_id.size();
        std::memcpy(initiator.data(), message.data() + pos, initiator.size());
        pos += initiator.size();
        std::memcpy(ephemeral.data(), message.data() + pos, ephemeral.size());
        if (zero_bytes(session_id) || zero_bytes(ephemeral)) {
            fail();
            return Error::make(ErrorCode::InvalidFrame, "handshake message 1 contains an empty field");
        }
        if (sodium_memcmp(initiator.data(), initiator_identity_.data(), initiator.size()) != 0) {
            fail();
            return Error::make(ErrorCode::IdentityMismatch,
                               "initiator identity does not match the pinned identity");
        }
        session_id_ = session_id;
        initiator_ephemeral_ = ephemeral;
        phase_ = Phase::ResponderSend2;
        return {};
    }

    if (phase_ == Phase::InitiatorRecv2) {
        if (header.type != k_message_2 || message.size() != k_message_2_size) {
            fail();
            return Error::make(ErrorCode::InvalidFrame, "handshake message 2 is invalid");
        }
        std::size_t pos = k_header;
        SessionId session_id{};
        IdentityPublic responder{};
        PublicKey ephemeral{};
        std::memcpy(session_id.data(), message.data() + pos, session_id.size());
        pos += session_id.size();
        std::memcpy(responder.data(), message.data() + pos, responder.size());
        pos += responder.size();
        std::memcpy(ephemeral.data(), message.data() + pos, ephemeral.size());
        pos += ephemeral.size();
        const auto signature = message.subspan(pos, k_signature_bytes);
        if (sodium_memcmp(session_id.data(), session_id_.data(), session_id.size()) != 0) {
            fail();
            return Error::make(ErrorCode::WrongSession, "handshake session id does not match");
        }
        if (sodium_memcmp(responder.data(), responder_identity_.data(), responder.size()) != 0) {
            fail();
            return Error::make(ErrorCode::IdentityMismatch,
                               "responder identity does not match the pinned identity");
        }
        if (zero_bytes(ephemeral)) {
            fail();
            return Error::make(ErrorCode::InvalidFrame, "responder ephemeral is empty");
        }
        responder_ephemeral_ = ephemeral;
        if (Error err = verify_role(EndpointRole::Responder, signature)) {
            responder_ephemeral_.fill(0);
            fail();
            return err;
        }
        phase_ = Phase::InitiatorSend3;
        return {};
    }

    if (phase_ == Phase::ResponderRecv3) {
        if (header.type != k_message_3 || message.size() != k_message_3_size) {
            fail();
            return Error::make(ErrorCode::InvalidFrame, "handshake message 3 is invalid");
        }
        std::size_t pos = k_header;
        SessionId session_id{};
        std::memcpy(session_id.data(), message.data() + pos, session_id.size());
        pos += session_id.size();
        if (sodium_memcmp(session_id.data(), session_id_.data(), session_id.size()) != 0) {
            fail();
            return Error::make(ErrorCode::WrongSession, "handshake session id does not match");
        }
        if (Error err = verify_role(EndpointRole::Initiator, message.subspan(pos, k_signature_bytes))) {
            fail();
            return err;
        }
        if (Error err = derive()) {
            fail();
            return err;
        }
        phase_ = Phase::ResponderDone;
        return {};
    }

    fail();
    return Error::make(ErrorCode::UnexpectedState, "handshake cannot read a message in this state");
}

bool Handshake::complete() const noexcept {
    return channel_ready_ && channel_.valid();
}

SecureChannel Handshake::take_channel(Error& err) {
    err = {};
    if (!complete()) {
        err = Error::make(ErrorCode::UnexpectedState, "handshake channel is not ready");
        return {};
    }
    channel_ready_ = false;
    return std::move(channel_);
}

} // namespace pm::encryption
