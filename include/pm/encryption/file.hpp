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

struct FileOffer;

/**
 * X25519 key used only to seal and open file content keys.
 *
 * This is not the Ed25519 signing identity. A signature compromise does not
 * open a file, and a file-key compromise does not sign a handshake.
 */
class FileKey {
public:
    FileKey();
    ~FileKey();
    FileKey(FileKey&& other) noexcept;
    FileKey& operator=(FileKey&& other) noexcept;
    FileKey(const FileKey&) = delete;
    FileKey& operator=(const FileKey&) = delete;

    static FileKey generate(Error& err);
    static FileKey from_seed(const Seed& seed, Error& err);

    const PublicKey& public_key() const noexcept { return public_; }
    bool valid() const noexcept { return valid_; }

private:
    friend Error create_file_offer(const Identity& sender, const FileKey& sender_file_key,
                                   const FileId& transfer, const FileId& room, std::string name,
                                   std::string media_type, std::span<const std::uint8_t> plaintext,
                                   std::uint32_t chunk_size, std::span<const PublicKey> recipients,
                                   FileOffer& out, std::uint32_t revision);
    friend class FileInbox;

    PublicKey public_{};
    std::array<std::uint8_t, 32> secret_{};
    bool valid_ = false;
};

/**
 * One member's wrapped copy of the file content key.
 *
 * The file itself is encrypted once. Each seal opens only for that member's
 * FileKey. Removing a member from a later revision does not make an older
 * ciphertext unreadable. This is not a group ratchet.
 */
struct RecipientSeal {
    PublicKey recipient{};
    std::array<std::uint8_t, 24> nonce{};
    std::vector<std::uint8_t> box;
};

struct FileManifest {
    std::uint8_t version = 1;
    FileId transfer{};
    FileId room{};
    IdentityPublic sender{};
    PublicKey sender_file{};
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

class FileSnapshot {
public:
    FileSnapshot();
    ~FileSnapshot();
    FileSnapshot(const FileSnapshot& other);
    FileSnapshot& operator=(const FileSnapshot& other);
    FileSnapshot(FileSnapshot&& other) noexcept;
    FileSnapshot& operator=(FileSnapshot&& other) noexcept;

    void wipe() noexcept;

    std::vector<std::uint8_t> received;
    std::vector<std::vector<std::uint8_t>> plaintext;
};

Error create_file_offer(const Identity& sender,
                        const FileKey& sender_file_key,
                        const FileId& transfer,
                        const FileId& room,
                        std::string name,
                        std::string media_type,
                        std::span<const std::uint8_t> plaintext,
                        std::uint32_t chunk_size,
                        std::span<const PublicKey> recipients,
                        FileOffer& out,
                        std::uint32_t revision = 1);

// There is no second plaintext under one content key at one chunk index.
// This function refuses that request and writes nothing.
Error reseal_file_chunk(std::uint32_t index,
                        std::span<const std::uint8_t> plaintext,
                        std::vector<std::uint8_t>& out);

Error encode_file_offer(const FileOffer& offer, std::vector<std::uint8_t>& out);
Error decode_file_offer(std::span<const std::uint8_t> bytes, FileOffer& out);

/**
 * Receiver for one sealed file.
 *
 * Chunks may arrive in any order. A chunk already accepted is a replay,
 * including a different ciphertext at that index. assemble() requires every
 * chunk and the signed whole-content hash. snapshot() copies plaintext and
 * wipes it when the snapshot is destroyed. Resume checks those pieces against
 * the signed chunk hashes. A later manifest that drops a recipient does not
 * erase a snapshot or ciphertext the recipient already holds.
 */
class FileInbox {
public:
    FileInbox();
    ~FileInbox();
    FileInbox(FileInbox&& other) noexcept;
    FileInbox& operator=(FileInbox&& other) noexcept;
    FileInbox(const FileInbox&) = delete;
    FileInbox& operator=(const FileInbox&) = delete;

    static FileInbox open(FileKey recipient, const FileManifest& manifest,
                          std::span<const RecipientSeal> seals, Error& err);
    static FileInbox resume(FileKey recipient, const FileManifest& manifest,
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
