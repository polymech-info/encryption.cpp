#include "pm/encryption/text_session.hpp"

#include "pm/encryption/features.hpp"

#if PM_ENCRYPTION_LIVE_SESSION
#include "pm/encryption/handshake.hpp"
#endif
#if PM_ENCRYPTION_LIBSIGNAL
#include "pm/encryption/signal_session.hpp"
#endif

#include <sodium.h>

#include <cstring>
#include <utility>

namespace pm::encryption {
namespace {

constexpr std::size_t k_signal_name_max = 64;
constexpr std::string_view k_text_type = "text/plain";

bool zero_key(const IdentityPublic& key) {
    IdentityPublic zero{};
    return sodium_memcmp(key.data(), zero.data(), key.size()) == 0;
}

} // namespace

struct TextSession::State {
    enum class Phase : std::uint8_t {
        LiveSend1 = 1,
        LiveRecv2,
        LiveSend3,
        LiveRecv1,
        LiveSend2,
        LiveRecv3,
        SignalExport,
        SignalInitiate,
        Ready,
        Failed,
    };

    PolicyId policy = PolicyId::LiveSession;
    EndpointRole role = EndpointRole::Initiator;
    Phase phase = Phase::Failed;
    bool opened_once = false;
    std::string signal_peer;
#if PM_ENCRYPTION_LIVE_SESSION
    Handshake handshake;
    SecureChannel channel;
#endif
#if PM_ENCRYPTION_LIBSIGNAL
    SignalEndpoint signal;
#endif
};

TextSession::TextSession() = default;
TextSession::~TextSession() = default;
TextSession::TextSession(TextSession&&) noexcept = default;
TextSession& TextSession::operator=(TextSession&&) noexcept = default;

EndpointRole TextSession::role_for(const IdentityPublic& self, const IdentityPublic& peer) {
    // Public keys only. This picks who sends the first setup message.
    if (std::memcmp(self.data(), peer.data(), self.size()) < 0)
        return EndpointRole::Initiator;
    return EndpointRole::Responder;
}

Error TextSession::open(PolicyId policy, EndpointRole role, const Identity& self, const IdentityPublic& peer,
                        std::string context, std::string signal_name, std::string signal_peer, TextSession& out) {
    out = TextSession{};
    if (policy == PolicyId::UnauthenticatedKx)
        return Error::make(ErrorCode::InvalidArgument, "chat refuses an unauthenticated channel");
    if (policy == PolicyId::Mls)
        return Error::make(ErrorCode::InvalidArgument, "chat refuses a group ratchet");
    if (policy != PolicyId::LiveSession && policy != PolicyId::Signal)
        return Error::make(ErrorCode::InvalidArgument, "chat policy is unknown");
    if (!policy_enabled(policy))
        return Error::make(ErrorCode::UnexpectedState, "chat policy is not compiled");
    if (!self.valid() || zero_key(peer) || sodium_memcmp(self.public_key().data(), peer.data(), peer.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "text session identity is invalid");
    if (policy == PolicyId::Signal
        && (signal_name.empty() || signal_peer.empty() || signal_name.size() > k_signal_name_max
            || signal_peer.size() > k_signal_name_max || signal_name == signal_peer))
        return Error::make(ErrorCode::InvalidArgument, "signal text names are invalid");

    auto state = std::make_unique<State>();
    state->policy = policy;
    state->role = role;
    state->signal_peer = std::move(signal_peer);

    if (policy == PolicyId::LiveSession) {
#if PM_ENCRYPTION_LIVE_SESSION
        Error err;
        Identity signing = self.duplicate(err);
        if (err)
            return err;
        if (role == EndpointRole::Initiator) {
            state->handshake = Handshake::initiator(std::move(signing), peer, std::move(context), err);
            state->phase = State::Phase::LiveSend1;
        } else {
            state->handshake = Handshake::responder(std::move(signing), peer, std::move(context), err);
            state->phase = State::Phase::LiveRecv1;
        }
        if (err)
            return err;
#else
        (void)role;
        (void)context;
        return Error::make(ErrorCode::UnexpectedState, "chat policy is not compiled");
#endif
    } else {
#if PM_ENCRYPTION_LIBSIGNAL
        Error err;
        state->signal = SignalEndpoint::open(std::move(signal_name), err);
        if (err)
            return err;
        state->phase = role == EndpointRole::Responder ? State::Phase::SignalExport : State::Phase::SignalInitiate;
#else
        (void)signal_name;
        return Error::make(ErrorCode::UnexpectedState, "chat policy is not compiled");
#endif
    }

    out.state_ = std::move(state);
    return {};
}

PolicyId TextSession::policy() const noexcept {
    return state_ ? state_->policy : PolicyId::LiveSession;
}

bool TextSession::wants_pull() const noexcept {
    if (!state_)
        return false;
    switch (state_->phase) {
    case State::Phase::LiveSend1:
    case State::Phase::LiveSend3:
    case State::Phase::LiveSend2:
    case State::Phase::SignalExport:
        return true;
    default:
        return false;
    }
}

bool TextSession::wants_push() const noexcept {
    if (!state_)
        return false;
    switch (state_->phase) {
    case State::Phase::LiveRecv2:
    case State::Phase::LiveRecv1:
    case State::Phase::LiveRecv3:
    case State::Phase::SignalInitiate:
        return true;
    default:
        return false;
    }
}

bool TextSession::ready() const noexcept {
    return state_ && state_->phase == State::Phase::Ready;
}

bool TextSession::can_seal() const noexcept {
    if (!ready())
        return false;
    if (state_->policy == PolicyId::Signal && state_->role == EndpointRole::Responder)
        return state_->opened_once;
    return true;
}

bool TextSession::can_open() const noexcept {
    return ready();
}

Error TextSession::pull(std::vector<std::uint8_t>& frame) {
    frame.clear();
    if (!wants_pull())
        return Error::make(ErrorCode::UnexpectedState, "text session is waiting");
#if PM_ENCRYPTION_LIVE_SESSION
    if (state_->policy == PolicyId::LiveSession) {
        if (Error err = state_->handshake.write_message(frame)) {
            state_->phase = State::Phase::Failed;
            return err;
        }
        if (state_->handshake.complete()) {
            Error err;
            state_->channel = state_->handshake.take_channel(err);
            state_->phase = err ? State::Phase::Failed : State::Phase::Ready;
            return err;
        }
        if (state_->phase == State::Phase::LiveSend1)
            state_->phase = State::Phase::LiveRecv2;
        else if (state_->phase == State::Phase::LiveSend2)
            state_->phase = State::Phase::LiveRecv3;
        else
            state_->phase = State::Phase::Failed;
        return {};
    }
#endif
#if PM_ENCRYPTION_LIBSIGNAL
    if (Error err = state_->signal.export_bundle(frame, true)) {
        state_->phase = State::Phase::Failed;
        return err;
    }
    state_->phase = State::Phase::Ready;
    return {};
#else
    return Error::make(ErrorCode::UnexpectedState, "text session is waiting");
#endif
}

Error TextSession::push(std::span<const std::uint8_t> frame) {
    if (!wants_push())
        return Error::make(ErrorCode::UnexpectedState, "text session is waiting");
#if PM_ENCRYPTION_LIVE_SESSION
    if (state_->policy == PolicyId::LiveSession) {
        if (Error err = state_->handshake.read_message(frame)) {
            state_->phase = State::Phase::Failed;
            return err;
        }
        if (state_->handshake.complete()) {
            Error err;
            state_->channel = state_->handshake.take_channel(err);
            state_->phase = err ? State::Phase::Failed : State::Phase::Ready;
            return err;
        }
        if (state_->phase == State::Phase::LiveRecv1)
            state_->phase = State::Phase::LiveSend2;
        else if (state_->phase == State::Phase::LiveRecv2)
            state_->phase = State::Phase::LiveSend3;
        else
            state_->phase = State::Phase::Failed;
        return {};
    }
#endif
#if PM_ENCRYPTION_LIBSIGNAL
    if (Error err = state_->signal.initiate(state_->signal_peer, frame)) {
        state_->phase = State::Phase::Failed;
        return err;
    }
    state_->phase = State::Phase::Ready;
    return {};
#else
    (void)frame;
    return Error::make(ErrorCode::UnexpectedState, "text session is waiting");
#endif
}

Error TextSession::seal(std::span<const std::uint8_t> text, std::vector<std::uint8_t>& frame) {
    frame.clear();
    if (text.empty() || text.size() > k_text_max_plaintext)
        return Error::make(ErrorCode::InvalidArgument, "text is empty or over 12288 bytes");
    if (!can_seal())
        return Error::make(ErrorCode::UnexpectedState, "text session cannot seal yet");
#if PM_ENCRYPTION_LIVE_SESSION
    if (state_->policy == PolicyId::LiveSession)
        return state_->channel.seal(text, k_text_type, frame, k_text_max_plaintext);
#endif
#if PM_ENCRYPTION_LIBSIGNAL
    return state_->signal.encrypt(state_->signal_peer, text, frame);
#else
    return Error::make(ErrorCode::UnexpectedState, "text session cannot seal yet");
#endif
}

Error TextSession::open_text(std::span<const std::uint8_t> frame, std::vector<std::uint8_t>& text) {
    text.clear();
    if (!can_open())
        return Error::make(ErrorCode::UnexpectedState, "text session cannot open yet");
#if PM_ENCRYPTION_LIVE_SESSION
    if (state_->policy == PolicyId::LiveSession)
        return state_->channel.open(frame, k_text_type, text, k_text_max_plaintext);
#endif
#if PM_ENCRYPTION_LIBSIGNAL
    if (Error err = state_->signal.decrypt(state_->signal_peer, frame, text)) {
        text.clear();
        return err;
    }
    state_->opened_once = true;
    return {};
#else
    (void)frame;
    return Error::make(ErrorCode::UnexpectedState, "text session cannot open yet");
#endif
}

} // namespace pm::encryption
