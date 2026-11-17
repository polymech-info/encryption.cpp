#pragma once

#include <cstdint>

namespace pm::encryption {

/**
 * Session policies are selectable features.
 *
 * LiveSession is the low-level online policy: pinned Ed25519 identities, the
 * three-message handshake labeled sigma-i-v1, and one XChaCha20-Poly1305
 * channel for that process. Identities travel in the clear. Signal is an
 * optional session policy, on when PM_ENCRYPTION_LIBSIGNAL is compiled (the
 * dev preset). MLS stays compiled out.
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
