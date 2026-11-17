#pragma once

#include "pm/encryption/file.hpp"

namespace pm::encryption {

/**
 * A device's statement that one FileKey belongs to its Ed25519 identity.
 *
 * This is not part of the file envelope. create_file_offer still seals to
 * the public keys it is given. authorize_device_file_keys is the check that
 * those keys were signed by the pinned devices, for the pinned versions,
 * inside the statement's own time window. Membership does not set that window.
 */
struct DeviceFileKey {
    std::uint32_t version = 0;
    std::uint64_t not_before = 0;
    std::uint64_t not_after = 0;
    IdentityPublic device{};
    PublicKey file_key{};
    Signature signature{};
};

Error issue_device_file_key(const Identity& device, const FileKey& file_key, std::uint32_t version,
                             std::uint64_t not_before, std::uint64_t not_after, DeviceFileKey& out);

Error authorize_device_file_keys(std::span<const IdentityPublic> devices,
                                 std::span<const std::uint32_t> versions,
                                 std::span<const DeviceFileKey> statements, std::uint64_t now,
                                 std::vector<PublicKey>& file_keys);

Error encode_device_file_key(const DeviceFileKey& statement, std::vector<std::uint8_t>& out);
Error decode_device_file_key(std::span<const std::uint8_t> bytes, DeviceFileKey& out);

Error create_authorized_file_offer(const Identity& sender, const FileKey& sender_file_key,
                                   const FileId& transfer, const FileId& room, std::string name,
                                   std::string media_type, std::span<const std::uint8_t> plaintext,
                                   std::uint32_t chunk_size, std::span<const IdentityPublic> devices,
                                   std::span<const std::uint32_t> versions,
                                   std::span<const DeviceFileKey> statements, std::uint64_t now,
                                   FileOffer& out, std::uint32_t revision = 1);

} // namespace pm::encryption
