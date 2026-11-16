#pragma once

#include "pm/room/pairing.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace pm::room {

inline constexpr std::size_t k_max_room_members = 32;
inline constexpr std::size_t k_max_room_frames = 256;
inline constexpr std::size_t k_max_room_frame = 16U * 1024U;

struct Room {
    Id id{};
    std::uint32_t epoch = 1;
    pm::encryption::IdentityPublic owner{};
    std::vector<pm::encryption::IdentityPublic> members;
    std::uint32_t grants = k_grant_chat;
};

struct Invite {
    Id room{};
    std::uint32_t epoch = 1;
    pm::encryption::IdentityPublic owner{};
    pm::encryption::IdentityPublic invitee{};
    std::uint32_t grants = k_grant_chat;
    pm::encryption::Signature signature{};
};

struct Envelope {
    Id room{};
    std::uint32_t epoch = 1;
    std::uint64_t sequence = 0;
    pm::encryption::IdentityPublic sender{};
    std::vector<std::uint8_t> frame;
    pm::encryption::Signature signature{};
};

/**
 * In-process stand-in for the Android room process.
 *
 * The broker stores pairing messages, membership, and opaque frames. It checks
 * signatures and membership. It does not decrypt, and it does not decide that
 * a Tailscale node is a user. The host serializes calls. Voice, video, and
 * file bytes stay outside; a chat frame may name a manifest id.
 *
 * These types are the contract a later packages/room.cpp, the Android JNI
 * host, and tanit-cli would call. They do not depend on a socket.
 */
class Broker {
public:
    pm::encryption::Error put_offer(const PairOffer& offer);
    pm::encryption::Error get_offer(const Id& pairing_id, PairOffer& out) const;
    pm::encryption::Error put_accept(const PairAccept& accept);
    pm::encryption::Error get_accept(const Id& pairing_id, PairAccept& out) const;

    pm::encryption::Error create_room(const pm::encryption::Identity& owner, const Id& room_id, Room& out);
    pm::encryption::Error invite(const pm::encryption::Identity& owner, const Id& room_id,
                                 const pm::encryption::IdentityPublic& invitee, std::uint32_t grants,
                                 Invite& out);
    pm::encryption::Error join(const pm::encryption::Identity& member, const Invite& invite, Room& out);
    pm::encryption::Error post(const pm::encryption::Identity& sender, const Id& room_id,
                               std::span<const std::uint8_t> frame, Envelope& out);
    pm::encryption::Error fetch(const Id& room_id, std::uint64_t after_sequence,
                                std::vector<Envelope>& out) const;

private:
    struct StoredRoom {
        Room room;
        std::vector<Invite> used_invites;
        std::uint64_t next_sequence = 1;
        std::vector<Envelope> envelopes;
    };

    StoredRoom* find_room(const Id& room_id);
    const StoredRoom* find_room(const Id& room_id) const;

    std::vector<PairOffer> offers_;
    std::vector<PairAccept> accepts_;
    std::vector<StoredRoom> rooms_;
};

} // namespace pm::room
