#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"
#include "pm/encryption/file.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

#if PM_ENCRYPTION_VFS
#include "pm/vfs/store.hpp"

#include <sodium.h>

#include <cstring>
#include <filesystem>
#include <span>
#endif

namespace pm::encryption::cli {
namespace {

#if PM_ENCRYPTION_VFS

std::string hex_id(const FileId& id) {
    static constexpr char k_digits[] = "0123456789abcdef";
    std::string out(id.size() * 2, '0');
    for (std::size_t i = 0; i < id.size(); ++i) {
        out[i * 2] = k_digits[id[i] >> 4];
        out[i * 2 + 1] = k_digits[id[i] & 0x0f];
    }
    return out;
}

Identity keyed(std::uint8_t tag, Error& err) {
    Seed seed{};
    seed.fill(tag);
    return Identity::from_seed(seed, err);
}

FileKey file_keyed(std::uint8_t tag, Error& err) {
    Seed seed{};
    seed.fill(tag);
    seed[0] ^= 0x5a;
    return FileKey::from_seed(seed, err);
}

void wipe_plain(std::vector<std::uint8_t>& bytes) {
    if (!bytes.empty())
        sodium_memzero(bytes.data(), bytes.size());
    bytes.clear();
}

std::string as_text(std::span<const std::uint8_t> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool contains_span(std::span<const std::uint8_t> hay, std::span<const std::uint8_t> needle) {
    if (needle.empty() || hay.size() < needle.size())
        return false;
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0)
            return true;
    }
    return false;
}

bool same_bytes(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
    return left.size() == right.size()
        && (left.empty() || std::memcmp(left.data(), right.data(), left.size()) == 0);
}

pm::vfs::Error vfs_write(const pm::vfs::Store& store, const pm::vfs::Caller& caller,
                         std::string_view mount, std::string_view path,
                         std::span<const std::uint8_t> bytes) {
    return store.write(caller, mount, path, as_text(bytes)).error;
}

pm::vfs::ReadResult vfs_read(const pm::vfs::Store& store, const pm::vfs::Caller& caller,
                             std::string_view mount, std::string_view path) {
    return store.read(caller, mount, path, {});
}

#endif

} // namespace

int run_group_file_scenario(LogSink& log) {
#if !PM_ENCRYPTION_VFS
    log_warn(log, "scenario", "vfs file scenario is not compiled");
    std::cout << nlohmann::json{{"ok", false},
                                {"schema", "pm.encryption.file.v1"},
                                {"scenario", "group-file"},
                                {"code", "feature_disabled"},
                                {"error", "PM_ENCRYPTION_VFS is off"}}
                     .dump()
              << "\n";
    return 1;
#else
    Check check;
    Error err;
    auto transfer = random_session_id(err);
    auto room = random_session_id(err);
    check(!err, "transfer and room ids", err.message);

    Identity alice = keyed(0xA1, err);
    Identity bob_id = keyed(0xB2, err);
    Identity carol = keyed(0xC3, err);
    Identity dave_id = keyed(0xD4, err);
    FileKey alice_file = file_keyed(0xA1, err);
    FileKey bob_file = file_keyed(0xB2, err);
    FileKey dave_file = file_keyed(0xD4, err);
    check(alice.valid() && bob_id.valid() && carol.valid() && dave_id.valid()
              && alice_file.valid() && bob_file.valid() && dave_file.valid(),
          "four member identities and separate file keys", err.message);
    check(alice.public_key() != alice_file.public_key()
              && bob_id.public_key() != bob_file.public_key(),
          "a file key is not the Ed25519 signing key");

    const std::vector<std::uint8_t> plaintext = {
        'g', 'r', 'o', 'u', 'p', '\0', 'c', 'h', 'a', 't', '-', 'f', 'i', 'l', 'e', '!'};
    constexpr std::uint32_t k_chunk = 5;
    const PublicKey recipients[] = {bob_file.public_key(), dave_file.public_key()};

    FileOffer offer;
    err = create_file_offer(alice, alice_file, transfer, room, "note.bin", "application/octet-stream",
                            plaintext, k_chunk, recipients, offer);
    check(!err && offer.chunks.size() == 4, "one ciphertext, sealed to each recipient", err.message);

    std::vector<std::uint8_t> offer_blob;
    if (!err)
        err = encode_file_offer(offer, offer_blob);
    FileOffer decoded;
    if (!err)
        err = decode_file_offer(offer_blob, decoded);
    check(!err && decoded.chunks.empty() && decoded.seals.size() == 2,
          "manifest blob carries seals and not chunk bytes", err.message);
    check(!contains_span(offer_blob, plaintext), "manifest blob does not contain the plaintext");

    FileManifest tampered = offer.manifest;
    tampered.room[0] ^= 0x01;
    Error tamper_err;
    auto rejected = FileInbox::open(file_keyed(0xB2, tamper_err), tampered, offer.seals, tamper_err);
    check(!rejected.valid() && tamper_err.code == ErrorCode::BadSignature,
          "a changed room id fails the sender signature", error_code_name(tamper_err.code));

    Error carol_err;
    auto carol_file = file_keyed(0xC3, carol_err);
    auto carol_inbox = FileInbox::open(std::move(carol_file), offer.manifest, offer.seals, carol_err);
    check(!carol_inbox.valid() && carol_err.code == ErrorCode::NotRecipient,
          "a room member who is not a recipient cannot open the content key",
          error_code_name(carol_err.code));

    Error dup_err;
    auto dup_inbox = FileInbox::open(file_keyed(0xB2, dup_err), offer.manifest, offer.seals, dup_err);
    if (!dup_err)
        dup_err = dup_inbox.accept(0, offer.chunks[0]);
    Error replay_err = dup_inbox.accept(0, offer.chunks[0]);
    Error other_cipher = dup_inbox.accept(0, offer.chunks[1]);
    check(!dup_err && replay_err.code == ErrorCode::Replay && other_cipher.code == ErrorCode::Replay
              && dup_inbox.has_chunk(0),
          "a second ciphertext at the same index is a replay", error_code_name(other_cipher.code));
    std::vector<std::uint8_t> resealed;
    Error reseal_err = reseal_file_chunk(0, plaintext, resealed);
    check(reseal_err.code == ErrorCode::InvalidArgument && resealed.empty(),
          "one content key cannot seal a second plaintext at the same index",
          error_code_name(reseal_err.code));

    Error corrupt_err;
    auto corrupt_inbox = FileInbox::open(file_keyed(0xB2, corrupt_err), offer.manifest, offer.seals, corrupt_err);
    auto corrupt_chunk = offer.chunks[1];
    if (!corrupt_chunk.empty())
        corrupt_chunk.back() ^= 0x01;
    if (!corrupt_err)
        corrupt_err = corrupt_inbox.accept(1, corrupt_chunk);
    check(corrupt_err.code == ErrorCode::AuthenticationFailed && !corrupt_inbox.has_chunk(1),
          "a corrupted chunk fails authentication", error_code_name(corrupt_err.code));

    Error missing_err;
    auto missing_inbox = FileInbox::open(file_keyed(0xB2, missing_err), offer.manifest, offer.seals, missing_err);
    std::vector<std::uint8_t> too_early;
    if (!missing_err)
        missing_err = missing_inbox.assemble(too_early);
    check(missing_err.code == ErrorCode::UnexpectedState && too_early.empty(),
          "assembly waits until every chunk is present", error_code_name(missing_err.code));

    Error dave_err;
    auto dave = FileInbox::open(file_keyed(0xD4, dave_err), offer.manifest, offer.seals, dave_err);
    for (int index = static_cast<int>(offer.chunks.size()) - 1; index >= 0 && !dave_err; --index)
        dave_err = dave.accept(static_cast<std::uint32_t>(index), offer.chunks[static_cast<std::size_t>(index)]);
    std::vector<std::uint8_t> dave_plain;
    if (!dave_err)
        dave_err = dave.assemble(dave_plain);
    check(!dave_err && same_bytes(dave_plain, plaintext),
          "an offline member opens the same chunks in reverse order", dave_err.message);

    FileOffer revised;
    const PublicKey bob_only[] = {bob_file.public_key()};
    Error revise_err = create_file_offer(alice, alice_file, transfer, room, "note.bin",
                                         "application/octet-stream", plaintext, k_chunk, bob_only,
                                         revised, 2);
    Error dave_removed;
    auto dave_after = FileInbox::open(file_keyed(0xD4, dave_removed), revised.manifest, revised.seals,
                                      dave_removed);
    Error bob_still;
    auto bob_revised = FileInbox::open(file_keyed(0xB2, bob_still), revised.manifest, revised.seals,
                                       bob_still);
    if (!bob_still && !revised.chunks.empty())
        bob_still = bob_revised.accept(0, revised.chunks[0]);
    check(!revise_err && !dave_err && dave_removed.code == ErrorCode::NotRecipient
              && !dave_after.valid() && !bob_still && bob_revised.has_chunk(0),
          "dropping a recipient does not revoke the older ciphertext",
          dave_removed ? error_code_name(dave_removed.code) : bob_still.message);
    wipe_plain(dave_plain);

    FileOffer empty_offer;
    err = create_file_offer(alice, alice_file, transfer, room, "empty.bin", "application/octet-stream",
                            {}, k_chunk, recipients, empty_offer);
    Error empty_err;
    auto empty_inbox = FileInbox::open(file_keyed(0xB2, empty_err), empty_offer.manifest, empty_offer.seals, empty_err);
    std::vector<std::uint8_t> empty_plain;
    if (!empty_err)
        empty_err = empty_inbox.assemble(empty_plain);
    check(!err && !empty_err && empty_inbox.complete() && empty_plain.empty(),
          "an empty file completes with no chunks", empty_err ? empty_err.message : err.message);

    namespace fs = std::filesystem;
    fs::path temp = fs::temp_directory_path() / ("pm-enc-file-" + hex_id(transfer));
    struct TempDir {
        fs::path path;
        ~TempDir() {
            std::error_code ec;
            if (!path.empty())
                fs::remove_all(path, ec);
        }
    } cleanup{temp};
    std::error_code fs_ec;
    fs::create_directories(temp / "room", fs_ec);
    pm::vfs::Error vfs_err;
    const auto mounts = nlohmann::json::array({
        {{"name", "root"}, {"type", "fs"}, {"path", (temp / "root").string()}},
        {{"name", "room"}, {"type", "fs"}, {"path", (temp / "room").string()}},
    });
    fs::create_directories(temp / "root", fs_ec);
    auto store = pm::vfs::Store::open_json(mounts.dump(), "[]", temp, vfs_err);
    check(!vfs_err, "vfs jail opens for the room and member homes", vfs_err.message);
    if (vfs_err) {
        std::cout << nlohmann::json{{"ok", false},
                                    {"schema", "pm.encryption.file.v1"},
                                    {"scenario", "group-file"},
                                    {"passed", check.passed},
                                    {"failed", check.failed},
                                    {"failures", check.failures}}
                         .dump()
                  << "\n";
        return 1;
    }

    const pm::vfs::Caller alice_caller{"alice"};
    const pm::vfs::Caller bob_caller{"bob"};
    vfs_err = vfs_write(store, alice_caller, "home", "outbox/note.bin", plaintext);
    check(!vfs_err, "sender writes the source through her home mount", vfs_err.message);

    std::vector<std::uint8_t> ranged;
    bool ranges_ok = true;
    for (std::uint64_t offset = 0; offset < plaintext.size();) {
        const auto len = std::min<std::uint64_t>(k_chunk, plaintext.size() - offset);
        pm::vfs::Range range;
        range.active = true;
        range.start = offset;
        range.end = offset + len - 1;
        auto part = store.read(alice_caller, "home", "outbox/note.bin", range);
        if (part.error || part.body.size() != len) {
            ranges_ok = false;
            break;
        }
        ranged.insert(ranged.end(), part.body.begin(), part.body.end());
        offset += len;
    }
    check(ranges_ok && same_bytes(ranged, plaintext),
          "source bytes come back through ranged vfs reads");

    auto escaped = store.write(alice_caller, "room", "../escape.bin", "no");
    check(static_cast<bool>(escaped.error) && !fs::exists(temp / "escape.bin"),
          "a chunk path cannot climb out of the room mount", escaped.error.message);

    const std::string drop = "drops/" + hex_id(transfer);
    vfs_err = vfs_write(store, alice_caller, "room", drop + "/manifest.bin", offer_blob);
    for (std::size_t i = 0; !vfs_err && i < offer.chunks.size(); ++i)
        vfs_err = vfs_write(store, alice_caller, "room", drop + "/" + std::to_string(i), offer.chunks[i]);
    check(!vfs_err, "ciphertext chunks and the manifest sit on the shared mount", vfs_err.message);

    auto stored_chunk = vfs_read(store, bob_caller, "room", drop + "/0");
    const bool ciphertext = !stored_chunk.error
        && stored_chunk.body.size() == k_chunk + 16
        && std::memcmp(stored_chunk.body.data(), plaintext.data(), k_chunk) != 0;
    check(ciphertext, "the shared mount holds ciphertext, not the file bytes");

    Error resume_err;
    auto partial = FileInbox::open(file_keyed(0xB2, resume_err), decoded.manifest, decoded.seals, resume_err);
    for (std::uint32_t index = 0; !resume_err && index + 1 < offer.chunks.size(); ++index) {
        auto chunk = vfs_read(store, bob_caller, "room", drop + "/" + std::to_string(index));
        if (chunk.error) {
            resume_err = Error::make(ErrorCode::InvalidFrame, chunk.error.message);
            break;
        }
        resume_err = partial.accept(index, std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(chunk.body.data()), chunk.body.size()));
    }
    FileSnapshot saved = partial.snapshot();
    for (std::size_t i = 0; !resume_err && i < saved.plaintext.size(); ++i) {
        if (saved.received[i] == 0)
            continue;
        vfs_err = vfs_write(store, bob_caller, "home",
                            "staging/note.bin." + std::to_string(i), saved.plaintext[i]);
        if (vfs_err)
            resume_err = Error::make(ErrorCode::InvalidArgument, vfs_err.message);
    }
    {
        FileSnapshot bad = saved;
        if (!bad.plaintext.empty() && !bad.plaintext[0].empty())
            bad.plaintext[0][0] ^= 0x01;
        Error bad_err;
        auto bad_inbox = FileInbox::resume(file_keyed(0xB2, bad_err), decoded.manifest, decoded.seals,
                                           std::move(bad), bad_err);
        check(!bad_inbox.valid() && bad_err.code == ErrorCode::AuthenticationFailed,
              "a tampered staging piece is rejected on resume", error_code_name(bad_err.code));
    }
    partial = FileInbox{};

    FileSnapshot restored;
    restored.received = saved.received;
    restored.plaintext.resize(saved.plaintext.size());
    for (std::size_t i = 0; i < saved.received.size(); ++i) {
        if (saved.received[i] == 0)
            continue;
        auto piece = vfs_read(store, bob_caller, "home", "staging/note.bin." + std::to_string(i));
        if (piece.error) {
            resume_err = Error::make(ErrorCode::InvalidFrame, piece.error.message);
            break;
        }
        restored.plaintext[i].assign(piece.body.begin(), piece.body.end());
    }
    Error bob_err;
    auto bob = FileInbox::resume(file_keyed(0xB2, bob_err), decoded.manifest, decoded.seals,
                                 std::move(restored), bob_err);
    if (!bob_err && bob.missing().size() != 1)
        bob_err = Error::make(ErrorCode::UnexpectedState, "resume did not keep the missing chunk");
    auto hidden = store.stat(bob_caller, "home", "inbox/note.bin");
    check(static_cast<bool>(hidden.error), "the final name is absent until the content hash matches",
          hidden.error.message);
    const auto last = offer.chunks.size() - 1;
    auto last_chunk = vfs_read(store, bob_caller, "room", drop + "/" + std::to_string(last));
    if (!bob_err && (last_chunk.error || bob.missing().size() != 1))
        bob_err = Error::make(ErrorCode::InvalidFrame, "last chunk was not readable");
    if (!bob_err)
        bob_err = bob.accept(static_cast<std::uint32_t>(last), std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(last_chunk.body.data()), last_chunk.body.size()));
    std::vector<std::uint8_t> bob_plain;
    if (!bob_err)
        bob_err = bob.assemble(bob_plain);
    if (!bob_err)
        vfs_err = vfs_write(store, bob_caller, "home", "inbox/note.bin", bob_plain);
    auto final_read = vfs_read(store, bob_caller, "home", "inbox/note.bin");
    const bool published = !bob_err && !vfs_err && !final_read.error
        && same_bytes(std::span<const std::uint8_t>(
               reinterpret_cast<const std::uint8_t*>(final_read.body.data()), final_read.body.size()),
                      plaintext);
    check(!resume_err && published, "resume from the member home publishes the verified file",
          resume_err ? resume_err.message : bob_err.message);
    wipe_plain(bob_plain);
    bool staging_deleted = published;
    for (std::size_t i = 0; staging_deleted && i < saved.received.size(); ++i) {
        if (saved.received[i] == 0)
            continue;
        const std::string piece = "staging/note.bin." + std::to_string(i);
        auto removed = store.remove(bob_caller, "home", piece, false);
        auto still = store.stat(bob_caller, "home", piece);
        if (removed || !still.error)
            staging_deleted = false;
    }
    saved.wipe();
    check(staging_deleted, "staging plaintext is deleted after publish");

    vfs_err = vfs_write(store, alice_caller, "room", "drops/empty/manifest.bin", {});
    std::vector<std::uint8_t> empty_blob;
    err = encode_file_offer(empty_offer, empty_blob);
    if (!err)
        vfs_err = vfs_write(store, alice_caller, "room", "drops/empty/manifest.bin", empty_blob);
    auto empty_stored = vfs_read(store, bob_caller, "room", "drops/empty/manifest.bin");
    FileOffer empty_decoded;
    if (!empty_stored.error)
        err = decode_file_offer(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(empty_stored.body.data()), empty_stored.body.size()),
            empty_decoded);
    if (!err)
        vfs_err = vfs_write(store, bob_caller, "home", "inbox/empty.bin", {});
    auto empty_stat = store.stat(bob_caller, "home", "inbox/empty.bin");
    check(!err && !vfs_err && !empty_stat.error && empty_stat.node.size == 0,
          "the empty file is published through the inbox mount",
          err ? err.message : vfs_err.message);

    const bool ok = check.failed == 0;
    log_info(log, "scenario", ok ? "group-file passed" : "group-file failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", "pm.encryption.file.v1"},
                     {"scenario", "group-file"},
                     {"group_key", "per-recipient-seal"},
                     {"file_key", "separate-x25519"},
                     {"file_key_is_identity", false},
                     {"removal_revokes_old_ciphertext", false},
                     {"chunk_reseal", false},
                     {"staging_deleted", staging_deleted},
                     {"mls", false},
                     {"members", 4},
                     {"recipients", 2},
                     {"chunk_count", offer.chunks.size()},
                     {"shared_mount_holds_ciphertext", ciphertext},
                     {"outsider_rejected", carol_err.code == ErrorCode::NotRecipient},
                     {"resume", published},
                     {"passed", check.passed},
                     {"failed", check.failed},
                     {"failures", check.failures},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
