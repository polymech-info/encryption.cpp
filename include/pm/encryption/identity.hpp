#pragma once

#include "pm/encryption/channel.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace pm::encryption {

inline constexpr std::size_t k_signature_bytes = 64;

using IdentityPublic = std::array<std::uint8_t, k_public_key_bytes>;
using Signature = std::array<std::uint8_t, k_signature_bytes>;

/**
 * Long-term Ed25519 device identity.
 *
 * The identity signs handshakes and file manifests. It does not open file
 * content keys. Those are sealed to a separate FileKey. Callers pin the peer
 * IdentityPublic before trusting a signature. This type does not decide trust,
 * storage, or rotation.
 */
class Identity {
public:
    Identity();
    ~Identity();
    Identity(Identity&& other) noexcept;
    Identity& operator=(Identity&& other) noexcept;
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;

    static Identity generate(Error& err);
    static Identity from_seed(const Seed& seed, Error& err);

    const IdentityPublic& public_key() const noexcept { return public_; }
    bool valid() const noexcept { return valid_; }

    Error sign(std::span<const std::uint8_t> message, Signature& signature) const;
    static Error verify(const IdentityPublic& public_key,
                        std::span<const std::uint8_t> message,
                        std::span<const std::uint8_t> signature);

private:
    IdentityPublic public_{};
    std::array<std::uint8_t, 64> secret_{};
    bool valid_ = false;
};

} // namespace pm::encryption
