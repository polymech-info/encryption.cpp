#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#if PM_ENCRYPTION_LIVE_SESSION
#include "pm/encryption/file.hpp"
#include "pm/encryption/handshake.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#endif

namespace pm::encryption::cli {
namespace {

#if PM_ENCRYPTION_LIVE_SESSION

std::uint8_t g_counter = 0;

void kat_buf(void* const buf, const size_t size) {
    auto* out = static_cast<unsigned char*>(buf);
    for (size_t i = 0; i < size; ++i)
        out[i] = g_counter++;
}

std::uint32_t kat_random() {
    std::uint32_t value = 0;
    kat_buf(&value, sizeof(value));
    return value;
}

void kat_stir() {}

std::uint32_t kat_uniform(const std::uint32_t upper) {
    if (upper < 2)
        return 0;
    return kat_random() % upper;
}

int kat_close() { return 0; }

const char* kat_name() { return "pm-encryption-kat-counter"; }

Seed filled(std::uint8_t first) {
    Seed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<std::uint8_t>(first + i);
    return seed;
}

#endif

} // namespace

int run_vectors() {
#if !PM_ENCRYPTION_LIVE_SESSION
    std::cout << nlohmann::json{{"ok", false},
                                {"schema", "pm.encryption.vectors.v1"},
                                {"code", "feature_disabled"},
                                {"error", "PM_ENCRYPTION_LIVE_SESSION is off"}}
                     .dump()
              << "\n";
    return 1;
#else
    randombytes_implementation implementation{
        kat_name, kat_random, kat_stir, kat_uniform, kat_buf, kat_close,
    };
    if (randombytes_set_implementation(&implementation) != 0) {
        std::cout << nlohmann::json{{"ok", false},
                                    {"schema", "pm.encryption.vectors.v1"},
                                    {"code", "crypto_unavailable"},
                                    {"error", "deterministic RNG could not be installed"}}
                         .dump()
                  << "\n";
        return 1;
    }

    Error err;
    const Seed identity_i = filled(0x01);
    const Seed identity_r = filled(0x40);
    const Seed ephemeral_i = filled(0x10);
    const Seed ephemeral_r = filled(0xc0);
    const Seed file_sender = filled(0x21);
    const Seed file_recipient = filled(0x61);
    const std::string context = "kat-v1";
    const SessionId session = test_session();
    const auto plaintext = bytes_of("kat");
    const auto file_plain = bytes_of("file-kat");

    auto left = Identity::from_seed(identity_i, err);
    auto right = Identity::from_seed(identity_r, err);
    auto left_ephemeral = KeyPair::from_seed(ephemeral_i, err);
    auto right_ephemeral = KeyPair::from_seed(ephemeral_r, err);
    auto sender_file = FileKey::from_seed(file_sender, err);
    auto recipient_file = FileKey::from_seed(file_recipient, err);
    if (err || !left.valid() || !right.valid() || !sender_file.valid() || !recipient_file.valid()) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    const auto right_public = right.public_key();
    const auto left_public = left.public_key();
    auto initiator = Handshake::initiator(
        std::move(left), right_public, context, std::move(left_ephemeral), session, err);
    auto responder = Handshake::responder(
        std::move(right), left_public, context, std::move(right_ephemeral), err);
    std::vector<std::uint8_t> message_1;
    std::vector<std::uint8_t> message_2;
    std::vector<std::uint8_t> message_3;
    if (err || initiator.write_message(message_1) || responder.read_message(message_1)
        || responder.write_message(message_2) || initiator.read_message(message_2)
        || initiator.write_message(message_3) || responder.read_message(message_3)
        || !initiator.complete() || !responder.complete()) {
        std::cout << error_json(err ? err : Error::make(ErrorCode::UnexpectedState,
                                                        "vector handshake did not complete"))
                         .dump()
                  << "\n";
        return 1;
    }
    const auto transcript = initiator.transcript();
    std::array<std::uint8_t, 32> salt{};
    if (transcript.empty()
        || crypto_generichash(salt.data(), salt.size(), transcript.data(), transcript.size(),
                              nullptr, 0) != 0) {
        std::cout << error_json(Error::make(ErrorCode::CryptoUnavailable, "transcript hash failed")).dump()
                  << "\n";
        return 1;
    }

    g_counter = 0;
    auto send = initiator.take_channel(err);
    auto recv = responder.take_channel(err);
    std::vector<std::uint8_t> frame;
    std::vector<std::uint8_t> opened;
    if (err || send.seal(plaintext, "text/plain", frame) || recv.open(frame, "text/plain", opened)
        || opened != plaintext) {
        std::cout << error_json(err ? err : Error::make(ErrorCode::AuthenticationFailed,
                                                        "vector frame did not open")).dump()
                  << "\n";
        return 1;
    }

    const PublicKey recipients[] = {recipient_file.public_key()};
    FileId transfer{};
    FileId room{};
    for (std::size_t i = 0; i < transfer.size(); ++i) {
        transfer[i] = static_cast<std::uint8_t>(0x30 + i);
        room[i] = static_cast<std::uint8_t>(0x80 + i);
    }
    FileOffer offer;
    err = create_file_offer(Identity::from_seed(identity_i, err), sender_file, transfer, room,
                            "kat.bin", "application/octet-stream", file_plain, 4, recipients, offer);
    std::vector<std::uint8_t> offer_blob;
    FileOffer decoded;
    if (!err)
        err = encode_file_offer(offer, offer_blob);
    if (!err)
        err = decode_file_offer(offer_blob, decoded);
    auto inbox = FileInbox::open(FileKey::from_seed(file_recipient, err), decoded.manifest, decoded.seals, err);
    for (std::uint32_t i = 0; !err && i < offer.chunks.size(); ++i)
        err = inbox.accept(i, offer.chunks[i]);
    std::vector<std::uint8_t> file_opened;
    if (!err)
        err = inbox.assemble(file_opened);
    if (err || file_opened != file_plain) {
        std::cout << error_json(err ? err : Error::make(ErrorCode::AuthenticationFailed,
                                                        "vector file did not open")).dump()
                  << "\n";
        return 1;
    }

    nlohmann::json chunks = nlohmann::json::array();
    for (const auto& chunk : offer.chunks)
        chunks.push_back(hex_of(chunk));
    std::cout << nlohmann::json{
                     {"ok", true},
                     {"schema", "pm.encryption.vectors.v1"},
                     {"rng", "counter-from-0-before-frame-then-file"},
                     {"context", context},
                     {"session", hex_of(session)},
                     {"identity_seed_initiator", hex_of(identity_i)},
                     {"identity_seed_responder", hex_of(identity_r)},
                     {"ephemeral_seed_initiator", hex_of(ephemeral_i)},
                     {"ephemeral_seed_responder", hex_of(ephemeral_r)},
                     {"file_seed_sender", hex_of(file_sender)},
                     {"file_seed_recipient", hex_of(file_recipient)},
                     {"domain", "pm.encryption.handshake.sigma-i.v1"},
                     {"hkdf_info_i2r", "pm.encryption.channel.i2r.v1"},
                     {"hkdf_info_r2i", "pm.encryption.channel.r2i.v1"},
                     {"message_1", hex_of(message_1)},
                     {"message_2", hex_of(message_2)},
                     {"message_3", hex_of(message_3)},
                     {"transcript", hex_of(transcript)},
                     {"transcript_hash", hex_of(salt)},
                     {"frame_content_type", "text/plain"},
                     {"frame_plaintext", hex_of(plaintext)},
                     {"frame", hex_of(frame)},
                     {"file_name", "kat.bin"},
                     {"file_plaintext", hex_of(file_plain)},
                     {"file_offer", hex_of(offer_blob)},
                     {"file_chunks", chunks},
                     {"ratchet", false},
                     {"removal_revokes_ciphertext", false},
                 }
                     .dump()
              << "\n";
    return 0;
#endif
}

} // namespace pm::encryption::cli
