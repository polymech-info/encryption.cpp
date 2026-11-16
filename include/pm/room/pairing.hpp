#pragma once

#include "pm/encryption/identity.hpp"

#include <array>
#include <cstdint>

namespace pm::room {

inline constexpr std::uint32_t k_grant_chat = 1u;
inline constexpr std::uint32_t k_grant_files = 2u;
inline constexpr std::uint32_t k_grant_audio = 4u;
inline constexpr std::uint32_t k_grant_video = 8u;
inline constexpr std::size_t k_fingerprint_bytes = 8;

using Id = std::array<std::uint8_t, 16>;
using Fingerprint = std::array<std::uint8_t, k_fingerprint_bytes>;

enum class Trust : std::uint8_t {
    Unknown = 0,
    Verifying = 1,
    Paired = 2,
    Revoked = 3,
};

struct PairOffer {
    Id pairing_id{};
    pm::encryption::IdentityPublic initiator{};
    pm::encryption::Signature signature{};
};

struct PairAccept {
    Id pairing_id{};
    pm::encryption::IdentityPublic initiator{};
    pm::encryption::IdentityPublic responder{};
    pm::encryption::Signature signature{};
};

struct PairedDevice {
    pm::encryption::IdentityPublic peer{};
    Id pairing_id{};
    Trust trust = Trust::Unknown;
    std::uint32_t grants = k_grant_chat;
};

pm::encryption::Error create_offer(const pm::encryption::Identity& initiator, const Id& pairing_id,
                                   PairOffer& out);
pm::encryption::Error verify_offer(const PairOffer& offer);
Fingerprint fingerprint_of(const pm::encryption::IdentityPublic& first,
                           const pm::encryption::IdentityPublic& second, const Id& pairing_id,
                           pm::encryption::Error& err);
pm::encryption::Error accept_offer(const pm::encryption::Identity& responder, const PairOffer& offer,
                                   PairAccept& out);
pm::encryption::Error confirm_pairing(const pm::encryption::Identity& initiator, const PairAccept& accept,
                                      const Fingerprint& peer_displayed, PairedDevice& out);

} // namespace pm::room
