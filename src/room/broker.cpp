#include "pm/room/broker.hpp"

#include <sodium.h>

#include <cstring>
#include <vector>

namespace pm::room {
namespace {

using pm::encryption::Error;
using pm::encryption::ErrorCode;
using pm::encryption::IdentityPublic;

constexpr char k_room_domain[] = "pm.room.create.v1";
constexpr char k_invite_domain[] = "pm.room.invite.v1";
constexpr char k_join_domain[] = "pm.room.join.v1";
constexpr char k_frame_domain[] = "pm.room.frame.v1";

void append(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

bool same_key(const IdentityPublic& left, const IdentityPublic& right) {
    return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool same_id(const Id& left, const Id& right) {
    return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool member_of(const Room& room, const IdentityPublic& key) {
    for (const IdentityPublic& member : room.members) {
        if (same_key(member, key))
            return true;
    }
    return false;
}

std::vector<std::uint8_t> room_bytes(const Room& room) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), k_room_domain, k_room_domain + sizeof(k_room_domain) - 1);
    append(out, room.id);
    append_u32(out, room.epoch);
    append(out, room.owner);
    return out;
}

std::vector<std::uint8_t> invite_bytes(const Invite& invite) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), k_invite_domain, k_invite_domain + sizeof(k_invite_domain) - 1);
    append(out, invite.room);
    append_u32(out, invite.epoch);
    append(out, invite.owner);
    append(out, invite.invitee);
    append_u32(out, invite.grants);
    return out;
}

std::vector<std::uint8_t> join_bytes(const Invite& invite) {
    auto out = invite_bytes(invite);
    out.insert(out.end(), k_join_domain, k_join_domain + sizeof(k_join_domain) - 1);
    append(out, invite.invitee);
    return out;
}

std::vector<std::uint8_t> frame_bytes(const Envelope& envelope) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), k_frame_domain, k_frame_domain + sizeof(k_frame_domain) - 1);
    append(out, envelope.room);
    append_u32(out, envelope.epoch);
    append_u64(out, envelope.sequence);
    append(out, envelope.sender);
    append_u32(out, static_cast<std::uint32_t>(envelope.frame.size()));
    append(out, envelope.frame);
    return out;
}

} // namespace

pm::encryption::Error Broker::put_offer(const PairOffer& offer) {
    if (Error err = verify_offer(offer))
        return err;
    for (const PairOffer& existing : offers_) {
        if (same_id(existing.pairing_id, offer.pairing_id))
            return Error::make(ErrorCode::Replay, "pairing offer was already stored");
    }
    offers_.push_back(offer);
    return {};
}

pm::encryption::Error Broker::get_offer(const Id& pairing_id, PairOffer& out) const {
    for (const PairOffer& offer : offers_) {
        if (same_id(offer.pairing_id, pairing_id)) {
            out = offer;
            return {};
        }
    }
    return Error::make(ErrorCode::UnexpectedState, "pairing offer is not at the broker");
}

pm::encryption::Error Broker::put_accept(const PairAccept& accept) {
    PairOffer offer;
    if (Error err = get_offer(accept.pairing_id, offer))
        return err;
    if (!same_key(offer.initiator, accept.initiator))
        return Error::make(ErrorCode::IdentityMismatch, "pairing accept does not match the offer");
    if (Error err = pm::encryption::Identity::verify(
            accept.responder,
            [&] {
                std::vector<std::uint8_t> out;
                constexpr char k_accept_domain[] = "pm.room.pair.accept.v1";
                out.insert(out.end(), k_accept_domain, k_accept_domain + sizeof(k_accept_domain) - 1);
                append(out, accept.pairing_id);
                append(out, accept.initiator);
                append(out, accept.responder);
                return out;
            }(),
            accept.signature))
        return err;
    for (const PairAccept& existing : accepts_) {
        if (same_id(existing.pairing_id, accept.pairing_id))
            return Error::make(ErrorCode::Replay, "pairing accept was already stored");
    }
    accepts_.push_back(accept);
    return {};
}

pm::encryption::Error Broker::get_accept(const Id& pairing_id, PairAccept& out) const {
    for (const PairAccept& accept : accepts_) {
        if (same_id(accept.pairing_id, pairing_id)) {
            out = accept;
            return {};
        }
    }
    return Error::make(ErrorCode::UnexpectedState, "pairing accept is not at the broker");
}

Broker::StoredRoom* Broker::find_room(const Id& room_id) {
    for (StoredRoom& room : rooms_) {
        if (same_id(room.room.id, room_id))
            return &room;
    }
    return nullptr;
}

const Broker::StoredRoom* Broker::find_room(const Id& room_id) const {
    for (const StoredRoom& room : rooms_) {
        if (same_id(room.room.id, room_id))
            return &room;
    }
    return nullptr;
}

pm::encryption::Error Broker::create_room(const pm::encryption::Identity& owner, const Id& room_id, Room& out) {
    out = {};
    if (!owner.valid() || sodium_is_zero(room_id.data(), room_id.size()) == 1)
        return Error::make(ErrorCode::InvalidArgument, "room needs an owner and an id");
    if (find_room(room_id))
        return Error::make(ErrorCode::Replay, "room id is already in use");
    Room room;
    room.id = room_id;
    room.epoch = 1;
    room.owner = owner.public_key();
    room.members.push_back(room.owner);
    room.grants = k_grant_chat;
    pm::encryption::Signature signature{};
    if (Error err = owner.sign(room_bytes(room), signature))
        return err;
    if (Error err = pm::encryption::Identity::verify(room.owner, room_bytes(room), signature))
        return err;
    rooms_.push_back(StoredRoom{std::move(room), {}, 1, {}});
    out = rooms_.back().room;
    return {};
}

pm::encryption::Error Broker::invite(const pm::encryption::Identity& owner, const Id& room_id,
                                     const IdentityPublic& invitee, std::uint32_t grants, Invite& out) {
    out = {};
    StoredRoom* stored = find_room(room_id);
    if (!stored)
        return Error::make(ErrorCode::UnexpectedState, "room is not at the broker");
    if (!same_key(stored->room.owner, owner.public_key()))
        return Error::make(ErrorCode::IdentityMismatch, "only the room owner can invite");
    if ((grants & ~k_grant_chat) != 0)
        return Error::make(ErrorCode::InvalidArgument, "this broker grants chat only");
    if (member_of(stored->room, invitee))
        return Error::make(ErrorCode::Replay, "invitee is already a member");
    if (stored->room.members.size() >= k_max_room_members)
        return Error::make(ErrorCode::InvalidArgument, "room is full");
    Invite invite;
    invite.room = room_id;
    invite.epoch = stored->room.epoch;
    invite.owner = stored->room.owner;
    invite.invitee = invitee;
    invite.grants = grants == 0 ? k_grant_chat : grants;
    if (Error err = owner.sign(invite_bytes(invite), invite.signature))
        return err;
    out = invite;
    return {};
}

pm::encryption::Error Broker::join(const pm::encryption::Identity& member, const Invite& invite, Room& out) {
    out = {};
    if (!member.valid())
        return Error::make(ErrorCode::InvalidArgument, "joining identity is invalid");
    if (!same_key(member.public_key(), invite.invitee))
        return Error::make(ErrorCode::IdentityMismatch, "invite is for a different device");
    StoredRoom* stored = find_room(invite.room);
    if (!stored)
        return Error::make(ErrorCode::UnexpectedState, "room is not at the broker");
    if (invite.epoch != stored->room.epoch || !same_key(invite.owner, stored->room.owner))
        return Error::make(ErrorCode::Stale, "invite is for a different room epoch");
    if (Error err = pm::encryption::Identity::verify(invite.owner, invite_bytes(invite), invite.signature))
        return err;
    pm::encryption::Signature join_signature{};
    if (Error err = member.sign(join_bytes(invite), join_signature))
        return err;
    if (Error err = pm::encryption::Identity::verify(invite.invitee, join_bytes(invite), join_signature))
        return err;
    for (const Invite& used : stored->used_invites) {
        if (same_key(used.invitee, invite.invitee))
            return Error::make(ErrorCode::Replay, "invite was already used");
    }
    if (member_of(stored->room, invite.invitee))
        return Error::make(ErrorCode::Replay, "device is already a member");
    stored->used_invites.push_back(invite);
    stored->room.members.push_back(invite.invitee);
    out = stored->room;
    return {};
}

pm::encryption::Error Broker::post(const pm::encryption::Identity& sender, const Id& room_id,
                                   std::span<const std::uint8_t> frame, Envelope& out) {
    out = {};
    StoredRoom* stored = find_room(room_id);
    if (!stored)
        return Error::make(ErrorCode::UnexpectedState, "room is not at the broker");
    if (!sender.valid() || !member_of(stored->room, sender.public_key()))
        return Error::make(ErrorCode::NotRecipient, "sender is not a member of the room");
    if (frame.empty() || frame.size() > k_max_room_frame)
        return Error::make(ErrorCode::FrameTooLarge, "room frame exceeds 16384 bytes");
    if (stored->envelopes.size() >= k_max_room_frames)
        return Error::make(ErrorCode::InvalidArgument, "room frame log is full");
    Envelope envelope;
    envelope.room = room_id;
    envelope.epoch = stored->room.epoch;
    envelope.sequence = stored->next_sequence;
    envelope.sender = sender.public_key();
    envelope.frame.assign(frame.begin(), frame.end());
    if (Error err = sender.sign(frame_bytes(envelope), envelope.signature))
        return err;
    ++stored->next_sequence;
    stored->envelopes.push_back(envelope);
    out = envelope;
    return {};
}

pm::encryption::Error Broker::fetch(const Id& room_id, std::uint64_t after_sequence,
                                    std::vector<Envelope>& out) const {
    out.clear();
    const StoredRoom* stored = find_room(room_id);
    if (!stored)
        return Error::make(ErrorCode::UnexpectedState, "room is not at the broker");
    for (const Envelope& envelope : stored->envelopes) {
        if (envelope.sequence <= after_sequence)
            continue;
        if (Error err = pm::encryption::Identity::verify(envelope.sender, frame_bytes(envelope),
                                                         envelope.signature))
            return err;
        out.push_back(envelope);
    }
    return {};
}

} // namespace pm::room
