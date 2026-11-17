#include "pm/encryption/device_key.hpp"

#include <sodium.h>

#include <cstring>
#include <vector>

namespace pm::encryption {
namespace {

constexpr char k_domain[] = "pm.encryption.device-file-key.v1";
constexpr std::uint8_t k_magic[] = {'P', 'M', 'D', 'K'};
constexpr std::uint8_t k_version = 1;
constexpr std::size_t k_body = sizeof(k_domain) - 1 + 1 + 4 + 8 + 8 + 32 + 32;
constexpr std::size_t k_encoded = 4 + 1 + 4 + 8 + 8 + 32 + 32 + 64;

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

bool take_u32(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint32_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 4)
        return false;
    out = 0;
    for (int i = 0; i < 4; ++i)
        out = (out << 8) | bytes[pos++];
    return true;
}

bool take_u64(std::span<const std::uint8_t> bytes, std::size_t& pos, std::uint64_t& out) {
    if (pos > bytes.size() || bytes.size() - pos < 8)
        return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out = (out << 8) | bytes[pos++];
    return true;
}

std::vector<std::uint8_t> statement_body(const DeviceFileKey& statement) {
    std::vector<std::uint8_t> body;
    body.reserve(k_body);
    body.insert(body.end(), k_domain, k_domain + sizeof(k_domain) - 1);
    body.push_back(k_version);
    append_u32(body, statement.version);
    append_u64(body, statement.not_before);
    append_u64(body, statement.not_after);
    body.insert(body.end(), statement.device.begin(), statement.device.end());
    body.insert(body.end(), statement.file_key.begin(), statement.file_key.end());
    return body;
}

Error check_window(std::uint32_t version, std::uint64_t not_before, std::uint64_t not_after) {
    if (version == 0)
        return Error::make(ErrorCode::InvalidArgument, "device file key version is zero");
    if (not_after <= not_before)
        return Error::make(ErrorCode::InvalidArgument, "device file key window is empty");
    return {};
}

} // namespace

Error issue_device_file_key(const Identity& device, const FileKey& file_key, std::uint32_t version,
                             std::uint64_t not_before, std::uint64_t not_after, DeviceFileKey& out) {
    out = {};
    if (!device.valid() || !file_key.valid())
        return Error::make(ErrorCode::InvalidArgument, "device identity or file key is invalid");
    if (Error window = check_window(version, not_before, not_after))
        return window;
    out.version = version;
    out.not_before = not_before;
    out.not_after = not_after;
    out.device = device.public_key();
    out.file_key = file_key.public_key();
    const auto body = statement_body(out);
    return device.sign(body, out.signature);
}

Error authorize_device_file_keys(std::span<const IdentityPublic> devices,
                                 std::span<const std::uint32_t> versions,
                                 std::span<const DeviceFileKey> statements, std::uint64_t now,
                                 std::vector<PublicKey>& file_keys) {
    file_keys.clear();
    if (devices.empty() || devices.size() > k_max_file_recipients || devices.size() != versions.size()
        || devices.size() != statements.size())
        return Error::make(ErrorCode::InvalidArgument, "device file key set is invalid");
    for (std::size_t i = 0; i < devices.size(); ++i) {
        for (std::size_t j = 0; j < i; ++j) {
            if (sodium_memcmp(devices[i].data(), devices[j].data(), devices[i].size()) == 0)
                return Error::make(ErrorCode::InvalidArgument, "device file key set contains a duplicate");
        }
        const DeviceFileKey& statement = statements[i];
        if (Error window = check_window(statement.version, statement.not_before, statement.not_after))
            return window;
        if (sodium_memcmp(statement.device.data(), devices[i].data(), devices[i].size()) != 0)
            return Error::make(ErrorCode::IdentityMismatch, "device file key is not signed by the pinned device");
        if (statement.version != versions[i])
            return Error::make(ErrorCode::IdentityMismatch, "device file key version is not the pinned version");
        if (now < statement.not_before || now >= statement.not_after)
            return Error::make(ErrorCode::Stale, "device file key is outside its validity window");
        const auto body = statement_body(statement);
        if (Error sig = Identity::verify(devices[i], body, statement.signature))
            return sig;
    }
    file_keys.reserve(statements.size());
    for (const DeviceFileKey& statement : statements)
        file_keys.push_back(statement.file_key);
    return {};
}

Error encode_device_file_key(const DeviceFileKey& statement, std::vector<std::uint8_t>& out) {
    out.clear();
    if (Error window = check_window(statement.version, statement.not_before, statement.not_after))
        return window;
    out.reserve(k_encoded);
    out.insert(out.end(), k_magic, k_magic + 4);
    out.push_back(k_version);
    append_u32(out, statement.version);
    append_u64(out, statement.not_before);
    append_u64(out, statement.not_after);
    out.insert(out.end(), statement.device.begin(), statement.device.end());
    out.insert(out.end(), statement.file_key.begin(), statement.file_key.end());
    out.insert(out.end(), statement.signature.begin(), statement.signature.end());
    return {};
}

Error decode_device_file_key(std::span<const std::uint8_t> bytes, DeviceFileKey& out) {
    out = {};
    if (bytes.size() != k_encoded || std::memcmp(bytes.data(), k_magic, 4) != 0 || bytes[4] != k_version)
        return Error::make(ErrorCode::InvalidFrame, "device file key statement is invalid");
    std::size_t pos = 5;
    if (!take_u32(bytes, pos, out.version) || !take_u64(bytes, pos, out.not_before)
        || !take_u64(bytes, pos, out.not_after))
        return Error::make(ErrorCode::InvalidFrame, "device file key statement is invalid");
    std::memcpy(out.device.data(), bytes.data() + pos, out.device.size());
    pos += out.device.size();
    std::memcpy(out.file_key.data(), bytes.data() + pos, out.file_key.size());
    pos += out.file_key.size();
    std::memcpy(out.signature.data(), bytes.data() + pos, out.signature.size());
    return {};
}

Error create_authorized_file_offer(const Identity& sender, const FileKey& sender_file_key, const FileId& transfer,
                                   const FileId& room, std::string name, std::string media_type,
                                   std::span<const std::uint8_t> plaintext, std::uint32_t chunk_size,
                                   std::span<const IdentityPublic> devices, std::span<const std::uint32_t> versions,
                                   std::span<const DeviceFileKey> statements, std::uint64_t now, FileOffer& out,
                                   std::uint32_t revision) {
    std::vector<PublicKey> file_keys;
    if (Error err = authorize_device_file_keys(devices, versions, statements, now, file_keys))
        return err;
    return create_file_offer(sender, sender_file_key, transfer, room, std::move(name), std::move(media_type),
                             plaintext, chunk_size, file_keys, out, revision);
}

} // namespace pm::encryption
