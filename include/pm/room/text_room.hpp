#pragma once

#include "pm/encryption/text_session.hpp"

#include <string>
#include <vector>

namespace pm::room {

/**
 * One TextSession per peer. Not a group key.
 *
 * Setup frames and text frames are both `recipient identity || session bytes`.
 * The host posts that buffer through Broker and fetches it back. The prefix
 * lets the other members ignore a frame that is not theirs. Membership,
 * grants, and what happens when someone leaves stay with the host.
 */
class TextRoom {
public:
    TextRoom();
    ~TextRoom();
    TextRoom(TextRoom&& other) noexcept;
    TextRoom& operator=(TextRoom&& other) noexcept;
    TextRoom(const TextRoom&) = delete;
    TextRoom& operator=(const TextRoom&) = delete;

    static pm::encryption::Error open(pm::encryption::PolicyId policy, const pm::encryption::Identity& self,
                                      std::string context, std::string signal_name, TextRoom& out);

    pm::encryption::Error add_peer(const pm::encryption::IdentityPublic& peer, std::string signal_peer);
    std::size_t peers() const noexcept;
    bool wants_pull(const pm::encryption::IdentityPublic& peer) const;
    bool ready(const pm::encryption::IdentityPublic& peer) const;

    pm::encryption::Error pull(const pm::encryption::IdentityPublic& peer, std::vector<std::uint8_t>& frame);
    pm::encryption::Error push(const pm::encryption::IdentityPublic& sender, std::span<const std::uint8_t> frame);
    pm::encryption::Error seal(const pm::encryption::IdentityPublic& peer, std::span<const std::uint8_t> text,
                               std::vector<std::uint8_t>& frame);
    pm::encryption::Error open_frame(const pm::encryption::IdentityPublic& sender, std::span<const std::uint8_t> frame,
                                     std::vector<std::uint8_t>& text);

private:
    struct Peer;
    struct State;
    Peer* find(const pm::encryption::IdentityPublic& id);
    const Peer* find(const pm::encryption::IdentityPublic& id) const;
    std::unique_ptr<State> state_;
};

} // namespace pm::room
