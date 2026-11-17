#pragma once

#include "pm/encryption/identity.hpp"
#include "pm/encryption/policy.hpp"

#include <memory>
#include <string>
#include <vector>

namespace pm::encryption {

inline constexpr std::size_t k_text_max_plaintext = 12U * 1024U;

/**
 * One pairwise text session. The host chooses the policy and moves the bytes.
 *
 * live_session is the pinned LAN channel. signal is the optional offline
 * ratchet, and only when that build compiled it. An unauthenticated channel
 * and MLS are refused. The signal name is not an Ed25519 binding.
 *
 * There is no socket here. A desktop process and an Android host call the
 * same functions. A restart of live_session is a new handshake.
 */
class TextSession {
public:
    TextSession();
    ~TextSession();
    TextSession(TextSession&& other) noexcept;
    TextSession& operator=(TextSession&& other) noexcept;
    TextSession(const TextSession&) = delete;
    TextSession& operator=(const TextSession&) = delete;

    static EndpointRole role_for(const IdentityPublic& self, const IdentityPublic& peer);

    static Error open(PolicyId policy, EndpointRole role, const Identity& self, const IdentityPublic& peer,
                      std::string context, std::string signal_name, std::string signal_peer, TextSession& out);

    PolicyId policy() const noexcept;
    bool wants_pull() const noexcept;
    bool wants_push() const noexcept;
    bool ready() const noexcept;
    bool can_seal() const noexcept;
    bool can_open() const noexcept;

    Error pull(std::vector<std::uint8_t>& frame);
    Error push(std::span<const std::uint8_t> frame);
    Error seal(std::span<const std::uint8_t> text, std::vector<std::uint8_t>& frame);
    Error open_text(std::span<const std::uint8_t> frame, std::vector<std::uint8_t>& text);

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace pm::encryption
