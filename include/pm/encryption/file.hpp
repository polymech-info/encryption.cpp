#pragma once

#include "pm/encryption/identity.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace pm::encryption {

inline constexpr std::size_t k_file_id_bytes = 16;
inline constexpr std::size_t k_file_hash_bytes = 32;
inline constexpr std::uint32_t k_max_file_chunks = 4096;
inline constexpr std::uint32_t k_max_file_chunk_size = 1024U * 1024U;
inline constexpr std::size_t k_max_file_recipients = 32;

using FileId = std::array<std::uint8_t, k_file_id_bytes>;
using FileHash = std::array<std::uint8_t, k_file_hash_bytes>;

/**
 * One member's wrapped copy of the file content key.
 *
 * The file itself is encrypted once. Each seal opens only for that member's
 * long-term identity. This is the bounded group-file envelope used before MLS:
 * it is not a group ratchet, and a stolen identity key opens every file sealed
 * to that member.
 */
struct RecipientSeal {
    IdentityPublic recipient{};
    std::array<std::uint8_t, 24> nonce{};
    std::vector<std::uint8_t> box;
};

struct FileManifest {
    std::uint8_t version = 1;
    FileId transfer{};
    FileId room{};
    IdentityPublic sender{};
    std::string name;
    std::string media_type;
    std::uint64_t size = 0;
    std::uint32_t chunk_size = 0;
    std::uint32_t revision = 1;
    FileHash content_hash{};
    std::vector<FileHash> chunk_hashes;
    FileHash seal_hash{};
    Signature signature{};
};

struct FileOffer {
    FileManifest manifest;
    std::vector<RecipientSeal> seals;
    std::vector<std::vector<std::uint8_t>> chunks;
};

struct FileSnapshot {
    std::vector<std::uint8_t> received;
    std::vector<std::vector<std::uint8_t>> plaintext;
};

Error create_file_offer(const Identity& sender,
                        const FileId& transfer,
                        const FileId& room,
                        std::string name,
                        std::string media_type,
                        std::span<const std::uint8_t> plaintext,
                        std::uint32_t chunk_size,
                        std::span<const IdentityPublic> recipients,
                        FileOffer& out);

Error encode_file_offer(const FileOffer& offer, std::vector<std::uint8_t>& out);
Error decode_file_offer(std::span<const std::uint8_t> bytes, FileOffer& out);

/**
 * Receiver for one sealed file.
 *
 * Chunks may arrive in any order. A chunk already accepted is a replay.
 * assemble() requires every chunk and the signed whole-content hash. The
 * snapshot is how a caller resumes after the inbox object is gone; pieces in
 * the snapshot are checked against the signed chunk hashes.
 */
class FileInbox {
public:
    FileInbox();
    ~FileInbox();
    FileInbox(FileInbox&& other) noexcept;
    FileInbox& operator=(FileInbox&& other) noexcept;
    FileInbox(const FileInbox&) = delete;
    FileInbox& operator=(const FileInbox&) = delete;

    static FileInbox open(Identity recipient, const FileManifest& manifest,
                          std::span<const RecipientSeal> seals, Error& err);
    static FileInbox resume(Identity recipient, const FileManifest& manifest,
                            std::span<const RecipientSeal> seals, FileSnapshot snapshot,
                            Error& err);

    bool valid() const noexcept { return open_; }
    const FileManifest& manifest() const noexcept { return manifest_; }
    bool has_chunk(std::uint32_t index) const;
    std::vector<std::uint32_t> missing() const;
    Error accept(std::uint32_t index, std::span<const std::uint8_t> ciphertext);
    bool complete() const;
    Error assemble(std::vector<std::uint8_t>& plaintext) const;
    FileSnapshot snapshot() const;

private:
    void wipe() noexcept;

    FileManifest manifest_{};
    std::array<std::uint8_t, 32> key_{};
    std::vector<std::vector<std::uint8_t>> pieces_;
    std::vector<std::uint8_t> have_;
    bool open_ = false;
};

} // namespace pm::encryption
