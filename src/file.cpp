#include "pm/encryption/file.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>

namespace pm::encryption {
namespace {

constexpr std::uint8_t k_manifest_magic[] = {'P', 'M', 'F', 'M'};
constexpr std::uint8_t k_offer_magic[] = {'P', 'M', 'F', 'O'};
constexpr std::uint8_t k_key_magic[] = {'P', 'M', 'F', 'K'};
constexpr std::uint8_t k_version = 1;
constexpr std::uint8_t k_suite = 1;
constexpr char k_chunk_domain[] = "pm.encryption.file.chunk.v1";
constexpr std::size_t k_box_payload = 4 + 1 + 16 + 16 + 32 + 32;
constexpr std::size_t k_box_bytes = k_box_payload + crypto_box_MACBYTES;

void wipe_bytes(void* data, std::size_t size) {
    if (data && size)
        sodium_memzero(data, size);
}

bool init_crypto(Error& err) {
    if (sodium_init() < 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "libsodium initialization failed");
        return false;
    }
    return true;
}

void append_bytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

bool take(std::span<const std::uint8_t> bytes, std::size_t& pos, std::size_t n,
          std::span<const std::uint8_t>& out) {
    if (pos > bytes.size() || bytes.size() - pos < n)
        return false;
    out = bytes.subspan(pos, n);
    pos += n;
    return true;
}

bool take_u16(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint16_t& out) {
    std::span<const std::uint8_t> raw;
    if (!take(bytes, pos, 2, raw))
        return false;
    out = (static_cast<std::uint16_t>(raw[0]) << 8) | static_cast<std::uint16_t>(raw[1]);
    return true;
}

bool take_u32(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint32_t& out) {
    std::span<const std::uint8_t> raw;
    if (!take(bytes, pos, 4, raw))
        return false;
    out = 0;
    for (std::uint8_t byte : raw)
        out = (out << 8) | byte;
    return true;
}

bool take_u64(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint64_t& out) {
    std::span<const std::uint8_t> raw;
    if (!take(bytes, pos, 8, raw))
        return false;
    out = 0;
    for (std::uint8_t byte : raw)
        out = (out << 8) | byte;
    return true;
}

bool take_array(std::span<const std::uint8_t> bytes, std::size_t& pos, std::span<std::uint8_t> dest) {
    std::span<const std::uint8_t> raw;
    if (!take(bytes, pos, dest.size(), raw))
        return false;
    std::copy(raw.begin(), raw.end(), dest.begin());
    return true;
}

bool name_ok(std::string_view name) {
    if (name.empty() || name.size() > 128 || name == "." || name == ".." || name.front() == '.')
        return false;
    for (unsigned char c : name) {
        if (c < 0x20 || c == '/' || c == '\\' || c == ':')
            return false;
    }
    return true;
}

bool media_ok(std::string_view media) {
    if (media.empty() || media.size() > 64)
        return false;
    for (unsigned char c : media) {
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    return true;
}

Error hash_bytes(std::span<const std::uint8_t> bytes, FileHash& out) {
    out.fill(0);
    if (crypto_generichash(out.data(), out.size(),
                           bytes.empty() ? nullptr : bytes.data(),
                           static_cast<unsigned long long>(bytes.size()),
                           nullptr, 0) != 0)
        return Error::make(ErrorCode::CryptoUnavailable, "content hash failed");
    return {};
}

void append_manifest_body(std::vector<std::uint8_t>& out, const FileManifest& manifest) {
    append_bytes(out, k_manifest_magic);
    out.push_back(manifest.version);
    out.push_back(k_suite);
    append_bytes(out, manifest.transfer);
    append_bytes(out, manifest.room);
    append_bytes(out, manifest.sender);
    append_bytes(out, manifest.sender_file);
    append_u16(out, static_cast<std::uint16_t>(manifest.name.size()));
    out.insert(out.end(), manifest.name.begin(), manifest.name.end());
    append_u16(out, static_cast<std::uint16_t>(manifest.media_type.size()));
    out.insert(out.end(), manifest.media_type.begin(), manifest.media_type.end());
    append_u64(out, manifest.size);
    append_u32(out, manifest.chunk_size);
    append_u32(out, manifest.revision);
    append_bytes(out, manifest.content_hash);
    append_u32(out, static_cast<std::uint32_t>(manifest.chunk_hashes.size()));
    for (const FileHash& hash : manifest.chunk_hashes)
        append_bytes(out, hash);
    append_bytes(out, manifest.seal_hash);
}

Error seal_hash_of(std::span<const RecipientSeal> seals, FileHash& out) {
    std::vector<std::uint8_t> body;
    body.reserve(seals.size() * (32 + 24 + 2 + k_box_bytes));
    for (const RecipientSeal& seal : seals) {
        append_bytes(body, seal.recipient);
        append_bytes(body, seal.nonce);
        append_u16(body, static_cast<std::uint16_t>(seal.box.size()));
        append_bytes(body, seal.box);
    }
    return hash_bytes(body, out);
}

std::vector<std::uint8_t> chunk_aad(const FileManifest& manifest, std::uint32_t index,
                                    std::uint32_t plaintext_len) {
    std::vector<std::uint8_t> aad;
    aad.insert(aad.end(), k_chunk_domain, k_chunk_domain + sizeof(k_chunk_domain) - 1);
    append_bytes(aad, manifest.transfer);
    append_bytes(aad, manifest.room);
    append_u32(aad, manifest.revision);
    append_u32(aad, index);
    append_u32(aad, plaintext_len);
    return aad;
}

std::array<std::uint8_t, 24> chunk_nonce(const FileManifest& manifest, std::uint32_t index) {
    std::array<std::uint8_t, 24> nonce{};
    std::copy(manifest.transfer.begin(), manifest.transfer.end(), nonce.begin());
    nonce[16] = static_cast<std::uint8_t>((manifest.revision >> 24) & 0xff);
    nonce[17] = static_cast<std::uint8_t>((manifest.revision >> 16) & 0xff);
    nonce[18] = static_cast<std::uint8_t>((manifest.revision >> 8) & 0xff);
    nonce[19] = static_cast<std::uint8_t>(manifest.revision & 0xff);
    nonce[20] = static_cast<std::uint8_t>((index >> 24) & 0xff);
    nonce[21] = static_cast<std::uint8_t>((index >> 16) & 0xff);
    nonce[22] = static_cast<std::uint8_t>((index >> 8) & 0xff);
    nonce[23] = static_cast<std::uint8_t>(index & 0xff);
    return nonce;
}

Error verify_manifest(const FileManifest& manifest, std::span<const RecipientSeal> seals) {
    if (manifest.version != k_version)
        return Error::make(ErrorCode::UnsupportedVersion, "file manifest version is not supported");
    if (!name_ok(manifest.name) || !media_ok(manifest.media_type))
        return Error::make(ErrorCode::InvalidArgument, "file manifest name or media type is invalid");
    if (manifest.chunk_size == 0 || manifest.chunk_size > k_max_file_chunk_size)
        return Error::make(ErrorCode::InvalidArgument, "file chunk size is invalid");
    if (manifest.revision == 0)
        return Error::make(ErrorCode::InvalidArgument, "file revision is invalid");
    if (manifest.chunk_hashes.size() > k_max_file_chunks)
        return Error::make(ErrorCode::InvalidArgument, "file has too many chunks");
    if (seals.empty() || seals.size() > k_max_file_recipients)
        return Error::make(ErrorCode::InvalidArgument, "recipient set size is invalid");
    for (std::size_t i = 1; i < seals.size(); ++i) {
        if (sodium_memcmp(seals[i - 1].recipient.data(), seals[i].recipient.data(), seals[i].recipient.size()) >= 0)
            return Error::make(ErrorCode::InvalidArgument, "recipient seals are not strictly increasing");
    }
    const std::uint64_t expected = manifest.size == 0
        ? 0
        : (manifest.size + manifest.chunk_size - 1) / manifest.chunk_size;
    if (expected != manifest.chunk_hashes.size())
        return Error::make(ErrorCode::InvalidFrame, "file chunk count does not match the size");
    FileHash seal_hash{};
    if (Error err = seal_hash_of(seals, seal_hash))
        return err;
    if (sodium_memcmp(seal_hash.data(), manifest.seal_hash.data(), seal_hash.size()) != 0)
        return Error::make(ErrorCode::BadSignature, "recipient seal hash does not match the manifest");
    std::vector<std::uint8_t> body;
    append_manifest_body(body, manifest);
    return Identity::verify(manifest.sender, body, manifest.signature);
}

Error open_content_key(const PublicKey& recipient_public,
                       std::span<const std::uint8_t, 32> recipient_secret,
                       const FileManifest& manifest,
                       std::span<const RecipientSeal> seals, std::array<std::uint8_t, 32>& key) {
    key.fill(0);
    const RecipientSeal* mine = nullptr;
    for (const RecipientSeal& seal : seals) {
        if (sodium_memcmp(seal.recipient.data(), recipient_public.data(),
                          seal.recipient.size()) == 0) {
            mine = &seal;
            break;
        }
    }
    if (!mine)
        return Error::make(ErrorCode::NotRecipient, "file key is not a recipient of this file");
    if (mine->box.size() != k_box_bytes)
        return Error::make(ErrorCode::InvalidFrame, "recipient seal length is invalid");
    PublicKey zero{};
    if (sodium_memcmp(manifest.sender_file.data(), zero.data(), zero.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "sender file key is empty");

    std::vector<std::uint8_t> opened(k_box_payload);
    Error err;
    if (crypto_box_open_easy(opened.data(), mine->box.data(), mine->box.size(),
                             mine->nonce.data(), manifest.sender_file.data(),
                             recipient_secret.data()) != 0)
        err = Error::make(ErrorCode::AuthenticationFailed, "recipient seal failed authentication");
    if (err) {
        wipe_bytes(opened.data(), opened.size());
        return err;
    }

    std::size_t pos = 0;
    std::span<const std::uint8_t> magic;
    std::span<const std::uint8_t> version;
    std::span<const std::uint8_t> transfer;
    std::span<const std::uint8_t> room;
    std::span<const std::uint8_t> who;
    std::span<const std::uint8_t> raw_key;
    const bool framed = take(opened, pos, 4, magic)
        && take(opened, pos, 1, version)
        && take(opened, pos, 16, transfer)
        && take(opened, pos, 16, room)
        && take(opened, pos, 32, who)
        && take(opened, pos, 32, raw_key)
        && pos == opened.size();
    if (!framed || std::memcmp(magic.data(), k_key_magic, 4) != 0 || version[0] != k_version
        || std::memcmp(transfer.data(), manifest.transfer.data(), transfer.size()) != 0
        || std::memcmp(room.data(), manifest.room.data(), room.size()) != 0
        || sodium_memcmp(who.data(), recipient_public.data(), who.size()) != 0) {
        wipe_bytes(opened.data(), opened.size());
        return Error::make(ErrorCode::AuthenticationFailed, "recipient seal is bound to another file");
    }
    std::copy(raw_key.begin(), raw_key.end(), key.begin());
    wipe_bytes(opened.data(), opened.size());
    return {};
}

} // namespace

FileKey::FileKey() = default;

FileKey::~FileKey() {
    wipe_bytes(secret_.data(), secret_.size());
}

FileKey::FileKey(FileKey&& other) noexcept
    : public_(other.public_), secret_(other.secret_), valid_(other.valid_) {
    wipe_bytes(other.secret_.data(), other.secret_.size());
    other.public_.fill(0);
    other.valid_ = false;
}

FileKey& FileKey::operator=(FileKey&& other) noexcept {
    if (this == &other)
        return *this;
    wipe_bytes(secret_.data(), secret_.size());
    public_ = other.public_;
    secret_ = other.secret_;
    valid_ = other.valid_;
    wipe_bytes(other.secret_.data(), other.secret_.size());
    other.public_.fill(0);
    other.valid_ = false;
    return *this;
}

FileKey FileKey::generate(Error& err) {
    err = {};
    FileKey out;
    if (!init_crypto(err))
        return out;
    if (crypto_box_keypair(out.public_.data(), out.secret_.data()) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "file key generation failed");
        return out;
    }
    out.valid_ = true;
    return out;
}

FileKey FileKey::from_seed(const Seed& seed, Error& err) {
    err = {};
    FileKey out;
    if (!init_crypto(err))
        return out;
    if (crypto_box_seed_keypair(out.public_.data(), out.secret_.data(), seed.data()) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "seeded file key generation failed");
        return out;
    }
    out.valid_ = true;
    return out;
}

FileSnapshot::FileSnapshot() = default;

FileSnapshot::~FileSnapshot() {
    wipe();
}

FileSnapshot::FileSnapshot(const FileSnapshot& other)
    : received(other.received), plaintext(other.plaintext) {}

FileSnapshot& FileSnapshot::operator=(const FileSnapshot& other) {
    if (this == &other)
        return *this;
    wipe();
    received = other.received;
    plaintext = other.plaintext;
    return *this;
}

FileSnapshot::FileSnapshot(FileSnapshot&& other) noexcept
    : received(std::move(other.received)), plaintext(std::move(other.plaintext)) {}

FileSnapshot& FileSnapshot::operator=(FileSnapshot&& other) noexcept {
    if (this == &other)
        return *this;
    wipe();
    received = std::move(other.received);
    plaintext = std::move(other.plaintext);
    return *this;
}

void FileSnapshot::wipe() noexcept {
    for (auto& piece : plaintext)
        wipe_bytes(piece.data(), piece.size());
    plaintext.clear();
    received.clear();
}

Error reseal_file_chunk(std::uint32_t, std::span<const std::uint8_t>, std::vector<std::uint8_t>& out) {
    out.clear();
    return Error::make(ErrorCode::InvalidArgument,
                       "a content key seals one plaintext per chunk index");
}

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
                        std::uint32_t revision) {
    out = {};
    Error err;
    if (!init_crypto(err))
        return err;
    if (!sender.valid())
        return Error::make(ErrorCode::InvalidArgument, "sender identity is invalid");
    if (!sender_file_key.valid())
        return Error::make(ErrorCode::InvalidArgument, "sender file key is invalid");
    if (revision == 0)
        return Error::make(ErrorCode::InvalidArgument, "file revision is invalid");
    FileId zero{};
    if (sodium_memcmp(transfer.data(), zero.data(), transfer.size()) == 0
        || sodium_memcmp(room.data(), zero.data(), room.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "transfer id and room id are required");
    if (!name_ok(name) || !media_ok(media_type))
        return Error::make(ErrorCode::InvalidArgument, "file name or media type is invalid");
    if (chunk_size == 0 || chunk_size > k_max_file_chunk_size)
        return Error::make(ErrorCode::InvalidArgument, "file chunk size is invalid");
    if (recipients.empty() || recipients.size() > k_max_file_recipients)
        return Error::make(ErrorCode::InvalidArgument, "recipient set size is invalid");

    std::vector<PublicKey> members(recipients.begin(), recipients.end());
    std::sort(members.begin(), members.end());
    for (std::size_t i = 1; i < members.size(); ++i) {
        if (sodium_memcmp(members[i - 1].data(), members[i].data(), members[i].size()) == 0)
            return Error::make(ErrorCode::InvalidArgument, "recipient set contains a duplicate");
    }
    const std::uint64_t chunk_count = plaintext.empty()
        ? 0
        : (static_cast<std::uint64_t>(plaintext.size()) + chunk_size - 1) / chunk_size;
    if (chunk_count > k_max_file_chunks)
        return Error::make(ErrorCode::PlaintextTooLarge, "file has too many chunks");

    std::array<std::uint8_t, 32> content_key{};
    randombytes_buf(content_key.data(), content_key.size());

    FileOffer offer;
    offer.manifest.version = k_version;
    offer.manifest.transfer = transfer;
    offer.manifest.room = room;
    offer.manifest.sender = sender.public_key();
    offer.manifest.sender_file = sender_file_key.public_key();
    offer.manifest.name = std::move(name);
    offer.manifest.media_type = std::move(media_type);
    offer.manifest.size = plaintext.size();
    offer.manifest.chunk_size = chunk_size;
    offer.manifest.revision = revision;
    offer.chunks.resize(static_cast<std::size_t>(chunk_count));
    offer.manifest.chunk_hashes.resize(static_cast<std::size_t>(chunk_count));

    for (std::uint64_t index = 0; !err && index < chunk_count; ++index) {
        const std::size_t offset = static_cast<std::size_t>(index * chunk_size);
        const std::size_t len = std::min(static_cast<std::size_t>(chunk_size), plaintext.size() - offset);
        const auto slice = plaintext.subspan(offset, len);
        if (Error hash_err = hash_bytes(slice, offer.manifest.chunk_hashes[static_cast<std::size_t>(index)]))
            err = hash_err;
        auto nonce = chunk_nonce(offer.manifest, static_cast<std::uint32_t>(index));
        auto aad = chunk_aad(offer.manifest, static_cast<std::uint32_t>(index),
                             static_cast<std::uint32_t>(len));
        auto& cipher = offer.chunks[static_cast<std::size_t>(index)];
        cipher.resize(len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long written = 0;
        if (!err && crypto_aead_xchacha20poly1305_ietf_encrypt(
                        cipher.data(), &written, slice.data(), slice.size(),
                        aad.data(), aad.size(), nullptr, nonce.data(), content_key.data()) != 0)
            err = Error::make(ErrorCode::CryptoUnavailable, "file chunk encryption failed");
        if (!err)
            cipher.resize(static_cast<std::size_t>(written));
    }
    if (!err)
        err = hash_bytes(plaintext, offer.manifest.content_hash);

    offer.seals.reserve(members.size());
    for (const PublicKey& member : members) {
        if (err)
            break;
        RecipientSeal seal;
        seal.recipient = member;
        randombytes_buf(seal.nonce.data(), seal.nonce.size());
        std::vector<std::uint8_t> payload;
        payload.reserve(k_box_payload);
        append_bytes(payload, k_key_magic);
        payload.push_back(k_version);
        append_bytes(payload, transfer);
        append_bytes(payload, room);
        append_bytes(payload, member);
        append_bytes(payload, content_key);
        seal.box.resize(k_box_bytes);
        if (!err && crypto_box_easy(seal.box.data(), payload.data(), payload.size(),
                                    seal.nonce.data(), member.data(),
                                    sender_file_key.secret_.data()) != 0)
            err = Error::make(ErrorCode::CryptoUnavailable, "recipient seal failed");
        wipe_bytes(payload.data(), payload.size());
        if (!err)
            offer.seals.push_back(std::move(seal));
    }
    if (!err)
        err = seal_hash_of(offer.seals, offer.manifest.seal_hash);
    std::vector<std::uint8_t> body;
    if (!err) {
        append_manifest_body(body, offer.manifest);
        err = sender.sign(body, offer.manifest.signature);
    }
    wipe_bytes(content_key.data(), content_key.size());
    wipe_bytes(body.data(), body.size());
    if (err)
        return err;
    out = std::move(offer);
    return {};
}

Error encode_file_offer(const FileOffer& offer, std::vector<std::uint8_t>& out) {
    out.clear();
    if (offer.seals.size() > k_max_file_recipients)
        return Error::make(ErrorCode::InvalidArgument, "recipient set size is invalid");
    append_bytes(out, k_offer_magic);
    out.push_back(k_version);
    append_manifest_body(out, offer.manifest);
    append_bytes(out, offer.manifest.signature);
    append_u16(out, static_cast<std::uint16_t>(offer.seals.size()));
    for (const RecipientSeal& seal : offer.seals) {
        if (seal.box.size() > 0xffff)
            return Error::make(ErrorCode::InvalidFrame, "recipient seal is too large");
        append_bytes(out, seal.recipient);
        append_bytes(out, seal.nonce);
        append_u16(out, static_cast<std::uint16_t>(seal.box.size()));
        append_bytes(out, seal.box);
    }
    return {};
}

Error decode_file_offer(std::span<const std::uint8_t> bytes, FileOffer& out) {
    out = {};
    Error err;
    if (!init_crypto(err))
        return err;
    std::size_t pos = 0;
    std::span<const std::uint8_t> magic;
    std::span<const std::uint8_t> version;
    if (!take(bytes, pos, 4, magic) || std::memcmp(magic.data(), k_offer_magic, 4) != 0)
        return Error::make(ErrorCode::InvalidFrame, "file offer magic is invalid");
    if (!take(bytes, pos, 1, version) || version[0] != k_version)
        return Error::make(ErrorCode::UnsupportedVersion, "file offer version is not supported");
    std::span<const std::uint8_t> body_magic;
    std::span<const std::uint8_t> body_version;
    std::span<const std::uint8_t> suite;
    if (!take(bytes, pos, 4, body_magic) || std::memcmp(body_magic.data(), k_manifest_magic, 4) != 0
        || !take(bytes, pos, 1, body_version) || body_version[0] != k_version
        || !take(bytes, pos, 1, suite) || suite[0] != k_suite)
        return Error::make(ErrorCode::InvalidFrame, "file manifest header is invalid");

    FileOffer offer;
    offer.manifest.version = k_version;
    std::uint16_t name_len = 0;
    std::uint16_t media_len = 0;
    std::uint32_t chunks = 0;
    std::span<const std::uint8_t> name;
    std::span<const std::uint8_t> media;
    if (!take_array(bytes, pos, offer.manifest.transfer)
        || !take_array(bytes, pos, offer.manifest.room)
        || !take_array(bytes, pos, offer.manifest.sender)
        || !take_array(bytes, pos, offer.manifest.sender_file)
        || !take_u16(bytes, pos, name_len)
        || !take(bytes, pos, name_len, name)
        || !take_u16(bytes, pos, media_len)
        || !take(bytes, pos, media_len, media)
        || !take_u64(bytes, pos, offer.manifest.size)
        || !take_u32(bytes, pos, offer.manifest.chunk_size)
        || !take_u32(bytes, pos, offer.manifest.revision)
        || !take_array(bytes, pos, offer.manifest.content_hash)
        || !take_u32(bytes, pos, chunks))
        return Error::make(ErrorCode::InvalidFrame, "file manifest is truncated");
    if (chunks > k_max_file_chunks)
        return Error::make(ErrorCode::InvalidFrame, "file has too many chunks");
    offer.manifest.name.assign(reinterpret_cast<const char*>(name.data()), name.size());
    offer.manifest.media_type.assign(reinterpret_cast<const char*>(media.data()), media.size());
    offer.manifest.chunk_hashes.resize(chunks);
    for (FileHash& hash : offer.manifest.chunk_hashes) {
        if (!take_array(bytes, pos, hash))
            return Error::make(ErrorCode::InvalidFrame, "file manifest is truncated");
    }
    std::uint16_t seal_count = 0;
    if (!take_array(bytes, pos, offer.manifest.seal_hash)
        || !take_array(bytes, pos, offer.manifest.signature)
        || !take_u16(bytes, pos, seal_count))
        return Error::make(ErrorCode::InvalidFrame, "file manifest is truncated");
    if (seal_count == 0 || seal_count > k_max_file_recipients)
        return Error::make(ErrorCode::InvalidFrame, "recipient set size is invalid");
    offer.seals.resize(seal_count);
    for (RecipientSeal& seal : offer.seals) {
        std::uint16_t box_len = 0;
        std::span<const std::uint8_t> box;
        if (!take_array(bytes, pos, seal.recipient)
            || !take_array(bytes, pos, seal.nonce)
            || !take_u16(bytes, pos, box_len)
            || !take(bytes, pos, box_len, box))
            return Error::make(ErrorCode::InvalidFrame, "recipient seal is truncated");
        seal.box.assign(box.begin(), box.end());
    }
    if (pos != bytes.size())
        return Error::make(ErrorCode::InvalidFrame, "file offer has trailing bytes");
    out = std::move(offer);
    return {};
}

FileInbox::FileInbox() = default;

FileInbox::~FileInbox() {
    wipe();
}

FileInbox::FileInbox(FileInbox&& other) noexcept
    : manifest_(std::move(other.manifest_)),
      key_(other.key_),
      pieces_(std::move(other.pieces_)),
      have_(std::move(other.have_)),
      open_(other.open_) {
    wipe_bytes(other.key_.data(), other.key_.size());
    other.open_ = false;
}

FileInbox& FileInbox::operator=(FileInbox&& other) noexcept {
    if (this == &other)
        return *this;
    wipe();
    manifest_ = std::move(other.manifest_);
    key_ = other.key_;
    pieces_ = std::move(other.pieces_);
    have_ = std::move(other.have_);
    open_ = other.open_;
    wipe_bytes(other.key_.data(), other.key_.size());
    other.open_ = false;
    return *this;
}

void FileInbox::wipe() noexcept {
    wipe_bytes(key_.data(), key_.size());
    for (auto& piece : pieces_)
        wipe_bytes(piece.data(), piece.size());
    open_ = false;
}

FileInbox FileInbox::open(FileKey recipient, const FileManifest& manifest,
                          std::span<const RecipientSeal> seals, Error& err) {
    err = {};
    FileInbox inbox;
    if (!init_crypto(err))
        return inbox;
    if (!recipient.valid()) {
        err = Error::make(ErrorCode::InvalidArgument, "recipient identity is invalid");
        return inbox;
    }
    if (Error verify_err = verify_manifest(manifest, seals)) {
        err = verify_err;
        return inbox;
    }
    if (Error key_err = open_content_key(recipient.public_key(), recipient.secret_, manifest, seals,
                                         inbox.key_)) {
        err = key_err;
        return inbox;
    }
    inbox.manifest_ = manifest;
    inbox.pieces_.resize(manifest.chunk_hashes.size());
    inbox.have_.assign(manifest.chunk_hashes.size(), 0);
    inbox.open_ = true;
    return inbox;
}

FileInbox FileInbox::resume(FileKey recipient, const FileManifest& manifest,
                            std::span<const RecipientSeal> seals, FileSnapshot snapshot, Error& err) {
    FileInbox inbox = open(std::move(recipient), manifest, seals, err);
    if (err)
        return inbox;
    if (snapshot.received.size() != inbox.have_.size()
        || snapshot.plaintext.size() != inbox.have_.size()) {
        err = Error::make(ErrorCode::InvalidArgument, "file resume snapshot does not match the manifest");
        inbox.wipe();
        return FileInbox{};
    }
    for (std::size_t i = 0; i < snapshot.received.size(); ++i) {
        if (snapshot.received[i] == 0) {
            if (!snapshot.plaintext[i].empty()) {
                err = Error::make(ErrorCode::InvalidArgument, "file resume snapshot has an unexpected piece");
                inbox.wipe();
                return FileInbox{};
            }
            continue;
        }
        if (snapshot.received[i] != 1) {
            err = Error::make(ErrorCode::InvalidArgument, "file resume map is invalid");
            inbox.wipe();
            return FileInbox{};
        }
        FileHash hash{};
        if (Error hash_err = hash_bytes(snapshot.plaintext[i], hash)) {
            err = hash_err;
            inbox.wipe();
            return FileInbox{};
        }
        if (sodium_memcmp(hash.data(), inbox.manifest_.chunk_hashes[i].data(), hash.size()) != 0) {
            err = Error::make(ErrorCode::AuthenticationFailed, "resumed chunk does not match the manifest");
            inbox.wipe();
            return FileInbox{};
        }
        inbox.pieces_[i] = snapshot.plaintext[i];
        wipe_bytes(snapshot.plaintext[i].data(), snapshot.plaintext[i].size());
        snapshot.plaintext[i].clear();
        inbox.have_[i] = 1;
    }
    snapshot.wipe();
    return inbox;
}

bool FileInbox::has_chunk(std::uint32_t index) const {
    return open_ && index < have_.size() && have_[index] != 0;
}

std::vector<std::uint32_t> FileInbox::missing() const {
    std::vector<std::uint32_t> out;
    for (std::uint32_t i = 0; i < have_.size(); ++i) {
        if (have_[i] == 0)
            out.push_back(i);
    }
    return out;
}

Error FileInbox::accept(std::uint32_t index, std::span<const std::uint8_t> ciphertext) {
    if (!open_)
        return Error::make(ErrorCode::UnexpectedState, "file inbox is not open");
    if (index >= have_.size())
        return Error::make(ErrorCode::InvalidArgument, "file chunk index is outside the manifest");
    if (have_[index])
        return Error::make(ErrorCode::Replay, "file chunk was already accepted");
    const std::uint64_t offset = static_cast<std::uint64_t>(index) * manifest_.chunk_size;
    if (offset >= manifest_.size)
        return Error::make(ErrorCode::InvalidFrame, "file chunk is outside the content");
    const std::uint32_t plain_len = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(manifest_.chunk_size, manifest_.size - offset));
    if (ciphertext.size() != static_cast<std::size_t>(plain_len) + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return Error::make(ErrorCode::InvalidFrame, "file chunk length is invalid");

    auto nonce = chunk_nonce(manifest_, index);
    auto aad = chunk_aad(manifest_, index, plain_len);
    std::vector<std::uint8_t> plain(plain_len);
    unsigned long long opened = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain.data(), &opened, nullptr,
            ciphertext.data(), ciphertext.size(),
            aad.data(), aad.size(), nonce.data(), key_.data()) != 0) {
        wipe_bytes(plain.data(), plain.size());
        return Error::make(ErrorCode::AuthenticationFailed, "file chunk failed authentication");
    }
    plain.resize(static_cast<std::size_t>(opened));
    FileHash hash{};
    if (Error err = hash_bytes(plain, hash)) {
        wipe_bytes(plain.data(), plain.size());
        return err;
    }
    if (sodium_memcmp(hash.data(), manifest_.chunk_hashes[index].data(), hash.size()) != 0) {
        wipe_bytes(plain.data(), plain.size());
        return Error::make(ErrorCode::AuthenticationFailed, "file chunk hash does not match the manifest");
    }
    pieces_[index] = std::move(plain);
    have_[index] = 1;
    return {};
}

bool FileInbox::complete() const {
    return open_ && std::find(have_.begin(), have_.end(), 0) == have_.end();
}

Error FileInbox::assemble(std::vector<std::uint8_t>& plaintext) const {
    plaintext.clear();
    if (!complete())
        return Error::make(ErrorCode::UnexpectedState, "file is missing chunks");
    plaintext.reserve(static_cast<std::size_t>(manifest_.size));
    for (const auto& piece : pieces_)
        plaintext.insert(plaintext.end(), piece.begin(), piece.end());
    if (plaintext.size() != manifest_.size)
        return Error::make(ErrorCode::AuthenticationFailed, "assembled file size does not match the manifest");
    FileHash hash{};
    if (Error err = hash_bytes(plaintext, hash)) {
        plaintext.clear();
        return err;
    }
    if (sodium_memcmp(hash.data(), manifest_.content_hash.data(), hash.size()) != 0) {
        plaintext.clear();
        return Error::make(ErrorCode::AuthenticationFailed, "assembled file hash does not match the manifest");
    }
    return {};
}

FileSnapshot FileInbox::snapshot() const {
    FileSnapshot out;
    if (!open_)
        return out;
    out.received = have_;
    out.plaintext = pieces_;
    return out;
}

} // namespace pm::encryption
