#pragma once

#include <cstdint>

namespace pm::encryption {

/**
 * Session policies are selectable features.
 *
 * LiveSession is the low-level online policy: pinned Ed25519 identities, a
 * SIGMA-I handshake, and one XChaCha20-Poly1305 channel for that process.
 * Signal and MLS are higher session policies and stay disabled until their
 * backends are compiled in.
 */
enum class PolicyId : std::uint8_t {
    LiveSession = 1,
    UnauthenticatedKx = 2,
    Signal = 3,
    Mls = 4,
};

bool policy_enabled(PolicyId id) noexcept;
const char* policy_id_name(PolicyId id) noexcept;

} // namespace pm::encryption
