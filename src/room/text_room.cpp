#include "pm/room/text_room.hpp"

#include "pm/room/broker.hpp"

#include <sodium.h>

#include <cstring>
#include <utility>

namespace pm::room {
namespace {

constexpr std::size_t k_address = 32;
constexpr std::size_t k_max_peers = 32;

bool same_key(const pm::encryption::IdentityPublic& left, const pm::encryption::IdentityPublic& right) {
    return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

pm::encryption::Error address(const pm::encryption::IdentityPublic& recipient, std::span<const std::uint8_t> body,
                              std::vector<std::uint8_t>& frame) {
    if (body.empty() || body.size() > pm::room::k_max_room_frame - k_address)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::FrameTooLarge,
                                           "text frame does not fit a room post");
    frame.resize(k_address + body.size());
    std::memcpy(frame.data(), recipient.data(), k_address);
    std::memcpy(frame.data() + k_address, body.data(), body.size());
    return {};
}

} // namespace

struct TextRoom::Peer {
    pm::encryption::IdentityPublic id{};
    pm::encryption::TextSession session;
};

struct TextRoom::State {
    pm::encryption::PolicyId policy = pm::encryption::PolicyId::LiveSession;
    pm::encryption::Identity self;
    std::string context;
    std::string signal_name;
    std::vector<Peer> peers;
};

TextRoom::TextRoom() = default;
TextRoom::~TextRoom() = default;
TextRoom::TextRoom(TextRoom&&) noexcept = default;
TextRoom& TextRoom::operator=(TextRoom&&) noexcept = default;

pm::encryption::Error TextRoom::open(pm::encryption::PolicyId policy, const pm::encryption::Identity& self,
                                     std::string context, std::string signal_name, TextRoom& out) {
    out = TextRoom{};
    if (!self.valid())
        return pm::encryption::Error::make(pm::encryption::ErrorCode::InvalidArgument, "text room identity is invalid");
    pm::encryption::Error err;
    auto state = std::make_unique<State>();
    state->policy = policy;
    state->self = self.duplicate(err);
    if (err)
        return err;
    state->context = std::move(context);
    state->signal_name = std::move(signal_name);
    out.state_ = std::move(state);
    return {};
}

pm::encryption::Error TextRoom::add_peer(const pm::encryption::IdentityPublic& peer, std::string signal_peer) {
    if (!state_)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "text room is closed");
    if (state_->peers.size() >= k_max_peers)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::InvalidArgument, "text room has too many peers");
    if (same_key(state_->self.public_key(), peer))
        return pm::encryption::Error::make(pm::encryption::ErrorCode::InvalidArgument, "text peer is the local device");
    for (const Peer& existing : state_->peers) {
        if (same_key(existing.id, peer))
            return pm::encryption::Error::make(pm::encryption::ErrorCode::InvalidArgument, "text peer is already in the room");
    }
    Peer added;
    added.id = peer;
    const pm::encryption::EndpointRole role = pm::encryption::TextSession::role_for(state_->self.public_key(), peer);
    if (pm::encryption::Error err = pm::encryption::TextSession::open(
            state_->policy, role, state_->self, peer, state_->context, state_->signal_name, std::move(signal_peer),
            added.session))
        return err;
    state_->peers.push_back(std::move(added));
    return {};
}

std::size_t TextRoom::peers() const noexcept {
    return state_ ? state_->peers.size() : 0;
}

TextRoom::Peer* TextRoom::find(const pm::encryption::IdentityPublic& id) {
    if (!state_)
        return nullptr;
    for (Peer& peer : state_->peers) {
        if (same_key(peer.id, id))
            return &peer;
    }
    return nullptr;
}

const TextRoom::Peer* TextRoom::find(const pm::encryption::IdentityPublic& id) const {
    if (!state_)
        return nullptr;
    for (const Peer& peer : state_->peers) {
        if (same_key(peer.id, id))
            return &peer;
    }
    return nullptr;
}

bool TextRoom::wants_pull(const pm::encryption::IdentityPublic& peer) const {
    const Peer* found = find(peer);
    return found && found->session.wants_pull();
}

bool TextRoom::ready(const pm::encryption::IdentityPublic& peer) const {
    const Peer* found = find(peer);
    return found && found->session.ready();
}

pm::encryption::Error TextRoom::pull(const pm::encryption::IdentityPublic& peer, std::vector<std::uint8_t>& frame) {
    frame.clear();
    if (!state_)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "text room is closed");
    Peer* found = find(peer);
    if (!found)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "no text session for that peer");
    std::vector<std::uint8_t> body;
    if (pm::encryption::Error err = found->session.pull(body))
        return err;
    return address(peer, body, frame);
}

pm::encryption::Error TextRoom::push(const pm::encryption::IdentityPublic& sender, std::span<const std::uint8_t> frame) {
    if (!state_)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "text room is closed");
    if (frame.size() <= k_address)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::InvalidFrame, "text frame is too small");
    pm::encryption::IdentityPublic recipient{};
    std::memcpy(recipient.data(), frame.data(), recipient.size());
    if (!same_key(state_->self.public_key(), recipient))
        return pm::encryption::Error::make(pm::encryption::ErrorCode::NotRecipient, "text frame is for another device");
    Peer* found = find(sender);
    if (!found)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "no text session for that peer");
    return found->session.push(frame.subspan(k_address));
}

pm::encryption::Error TextRoom::seal(const pm::encryption::IdentityPublic& peer, std::span<const std::uint8_t> text,
                                     std::vector<std::uint8_t>& frame) {
    frame.clear();
    if (!state_)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "text room is closed");
    Peer* found = find(peer);
    if (!found)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "no text session for that peer");
    std::vector<std::uint8_t> body;
    if (pm::encryption::Error err = found->session.seal(text, body))
        return err;
    return address(peer, body, frame);
}

pm::encryption::Error TextRoom::open_frame(const pm::encryption::IdentityPublic& sender,
                                           std::span<const std::uint8_t> frame, std::vector<std::uint8_t>& text) {
    text.clear();
    if (!state_)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "text room is closed");
    if (frame.size() <= k_address)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::InvalidFrame, "text frame is too small");
    pm::encryption::IdentityPublic recipient{};
    std::memcpy(recipient.data(), frame.data(), recipient.size());
    if (!same_key(state_->self.public_key(), recipient))
        return pm::encryption::Error::make(pm::encryption::ErrorCode::NotRecipient, "text frame is for another device");
    Peer* found = find(sender);
    if (!found)
        return pm::encryption::Error::make(pm::encryption::ErrorCode::UnexpectedState, "no text session for that peer");
    return found->session.open_text(frame.subspan(k_address), text);
}

} // namespace pm::room
