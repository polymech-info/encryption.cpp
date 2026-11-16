#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"
#include "pm/room/broker.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#if PM_ENCRYPTION_LIVE_SESSION
#include "pm/encryption/handshake.hpp"

#include <sodium.h>

#include <cstring>
#endif

namespace pm::encryption::cli {
namespace {

constexpr const char* k_schema = "pm.room.harness.v1";

nlohmann::json room_failure(const char* code, std::string error) {
    return {{"ok", false}, {"schema", k_schema}, {"code", code}, {"error", std::move(error)}};
}

#if PM_ENCRYPTION_LIVE_SESSION

Identity keyed(std::uint8_t tag, Error& err) {
    Seed seed{};
    seed.fill(tag);
    return Identity::from_seed(seed, err);
}

bool contains_text(std::span<const std::uint8_t> hay, std::string_view needle) {
    if (needle.empty() || hay.size() < needle.size())
        return false;
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0)
            return true;
    }
    return false;
}

#endif

} // namespace

int run_room_harness(const std::string& text, LogSink& log) {
#if !PM_ENCRYPTION_LIVE_SESSION
    (void)text;
    log_warn(log, "room", "live session is not compiled");
    std::cout << room_failure("feature_disabled", "room harness needs the live session").dump() << "\n";
    return 1;
#else
    if (text.empty() || text.size() > pm::room::k_max_room_frame) {
        std::cout << room_failure("invalid_argument", "room chat text is empty or over 16384 bytes").dump()
                  << "\n";
        return text.empty() ? 2 : 1;
    }

    Error err;
    auto alice = keyed(0xA1, err);
    auto bob = keyed(0xB2, err);
    auto carol = keyed(0xC3, err);
    if (err || !alice.valid() || !bob.valid() || !carol.valid()) {
        std::cout << room_failure("crypto_unavailable", err.message).dump() << "\n";
        return 1;
    }

    auto pairing_id = random_session_id(err);
    auto room_id = random_session_id(err);
    pm::room::Broker broker;
    pm::room::PairOffer offer;
    err = pm::room::create_offer(alice, pairing_id, offer);
    if (!err)
        err = broker.put_offer(offer);
    pm::room::PairOffer relayed;
    if (!err)
        err = broker.get_offer(pairing_id, relayed);
    pm::room::PairAccept accept;
    if (!err)
        err = pm::room::accept_offer(bob, relayed, accept);
    if (!err)
        err = broker.put_accept(accept);
    pm::room::PairAccept relayed_accept;
    if (!err)
        err = broker.get_accept(pairing_id, relayed_accept);

    pm::room::Fingerprint shown{};
    pm::room::Fingerprint wrong{};
    wrong.fill(0x11);
    pm::room::PairedDevice rejected;
    const bool mismatch = !err
        && static_cast<bool>(pm::room::confirm_pairing(alice, relayed_accept, wrong, rejected));
    if (!err)
        shown = pm::room::fingerprint_of(relayed.initiator, bob.public_key(), pairing_id, err);
    pm::room::PairedDevice paired;
    if (!err)
        err = pm::room::confirm_pairing(alice, relayed_accept, shown, paired);

    pm::room::Id swapped_id = pairing_id;
    swapped_id[0] ^= 0x5a;
    pm::room::PairOffer swapped;
    pm::room::PairAccept swapped_accept;
    pm::room::PairedDevice not_alice;
    Error swap_err = pm::room::create_offer(carol, swapped_id, swapped);
    if (!swap_err)
        swap_err = broker.put_offer(swapped);
    if (!swap_err)
        swap_err = pm::room::accept_offer(bob, swapped, swapped_accept);
    if (!swap_err)
        swap_err = pm::room::confirm_pairing(alice, swapped_accept, shown, not_alice);
    const bool substituted_rejected = swap_err.code == ErrorCode::IdentityMismatch
        && not_alice.trust != pm::room::Trust::Paired;

    pm::room::Room room;
    if (!err)
        err = broker.create_room(alice, room_id, room);
    pm::room::Invite invite;
    if (!err)
        err = broker.invite(alice, room_id, bob.public_key(), pm::room::k_grant_chat, invite);
    pm::room::Invite media;
    const bool media_rejected = !err
        && static_cast<bool>(broker.invite(alice, room_id, bob.public_key(),
                                           pm::room::k_grant_audio | pm::room::k_grant_video
                                               | pm::room::k_grant_files,
                                           media));
    if (!err)
        err = broker.join(bob, invite, room);
    pm::room::Room second;
    const bool invite_reused = !err && broker.join(bob, invite, second).code == ErrorCode::Replay;

    constexpr std::string_view k_context = "tanit-room|loopback-v1";
    auto alice_channel_id = keyed(0xA1, err);
    auto bob_channel_id = keyed(0xB2, err);
    auto alice_hs = Handshake::initiator(std::move(alice_channel_id), bob.public_key(),
                                         std::string(k_context), err);
    auto bob_hs = Handshake::responder(std::move(bob_channel_id), alice.public_key(),
                                       std::string(k_context), err);

    auto post = [&](Identity& sender, std::span<const std::uint8_t> bytes, pm::room::Envelope& out) {
        return broker.post(sender, room_id, bytes, out);
    };
    auto take_peer = [&](const IdentityPublic& peer, std::uint64_t after, std::vector<std::uint8_t>& message) {
        std::vector<pm::room::Envelope> got;
        if (Error fetch_err = broker.fetch(room_id, after, got))
            return fetch_err;
        for (const pm::room::Envelope& envelope : got) {
            if (sodium_memcmp(envelope.sender.data(), peer.data(), peer.size()) != 0)
                continue;
            message = envelope.frame;
            return Error{};
        }
        return Error::make(ErrorCode::UnexpectedState, "peer frame was not relayed");
    };

    Identity alice_post = keyed(0xA1, err);
    Identity bob_post = keyed(0xB2, err);
    std::vector<std::uint8_t> message;
    std::vector<std::uint8_t> incoming;
    pm::room::Envelope envelope;
    bool relayed_chat = false;
    bool plaintext_hidden = true;
    bool tamper_rejected = false;
    bool manifest_hidden = false;
    if (!err)
        err = alice_hs.write_message(message);
    if (!err)
        err = post(alice_post, message, envelope);
    if (!err)
        err = take_peer(alice.public_key(), 0, incoming);
    if (!err)
        err = bob_hs.read_message(incoming);
    if (!err)
        err = bob_hs.write_message(message);
    if (!err)
        err = post(bob_post, message, envelope);
    if (!err)
        err = take_peer(bob.public_key(), 1, incoming);
    if (!err)
        err = alice_hs.read_message(incoming);
    if (!err)
        err = alice_hs.write_message(message);
    if (!err)
        err = post(alice_post, message, envelope);
    if (!err)
        err = take_peer(alice.public_key(), 2, incoming);
    if (!err)
        err = bob_hs.read_message(incoming);
    SecureChannel alice_session;
    SecureChannel bob_session;
    if (!err && alice_hs.complete() && bob_hs.complete()) {
        alice_session = alice_hs.take_channel(err);
        if (!err)
            bob_session = bob_hs.take_channel(err);
    }
    std::vector<std::uint8_t> frame;
    if (!err && alice_session.valid())
        err = alice_session.seal({reinterpret_cast<const std::uint8_t*>(text.data()), text.size()},
                                 "text/plain", frame, pm::room::k_max_room_frame);
    pm::room::Envelope chat;
    if (!err)
        err = post(alice_post, frame, chat);
    if (!err && contains_text(chat.frame, text))
        plaintext_hidden = false;
    std::vector<std::uint8_t> tampered = chat.frame;
    if (!tampered.empty())
        tampered.back() ^= 0x01;
    std::vector<std::uint8_t> opened;
    if (!err && bob_session.valid()) {
        err = take_peer(alice.public_key(), 3, incoming);
        if (!err) {
            Error tamper = bob_session.open(tampered, "text/plain", opened, pm::room::k_max_room_frame);
            tamper_rejected = tamper.code == ErrorCode::AuthenticationFailed;
            err = bob_session.open(incoming, "text/plain", opened, pm::room::k_max_room_frame);
        }
    }
    relayed_chat = !err && opened.size() == text.size()
        && std::memcmp(opened.data(), text.data(), text.size()) == 0;

    const std::string manifest = "manifest:room-file-1";
    std::vector<std::uint8_t> manifest_frame;
    if (relayed_chat)
        err = alice_session.seal({reinterpret_cast<const std::uint8_t*>(manifest.data()), manifest.size()},
                                 "text/plain", manifest_frame, pm::room::k_max_room_frame);
    pm::room::Envelope manifest_envelope;
    if (relayed_chat && !err)
        err = post(alice_post, manifest_frame, manifest_envelope);
    if (relayed_chat && !err)
        manifest_hidden = !contains_text(manifest_envelope.frame, manifest);

    pm::room::Envelope carol_envelope;
    Identity carol_post = keyed(0xC3, err);
    const bool outsider_rejected = broker.post(carol_post, room_id, frame, carol_envelope).code
        == ErrorCode::NotRecipient;

    const bool grants_chat_only = paired.trust == pm::room::Trust::Paired && paired.grants == pm::room::k_grant_chat
        && room.members.size() == 2;
    const bool ok = mismatch && substituted_rejected && media_rejected && invite_reused && relayed_chat
        && plaintext_hidden && tamper_rejected && manifest_hidden && outsider_rejected && grants_chat_only
        && !err;
    log_info(log, "room", ok ? "passed" : "failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", k_schema},
                     {"host", "in-process"},
                     {"underlay", "loopback"},
                     {"tailnet", false},
                     {"tailnet_authenticates_users", false},
                     {"broker", true},
                     {"broker_sees_plaintext", !plaintext_hidden},
                     {"pairing", paired.trust == pm::room::Trust::Paired ? "fingerprint-v1" : "failed"},
                     {"fingerprint_mismatch_rejected", mismatch},
                     {"substituted_offer_rejected", substituted_rejected},
                     {"members", room.members.size()},
                     {"grants", "chat"},
                     {"audio", false},
                     {"video", false},
                     {"files", false},
                     {"media_grants_rejected", media_rejected},
                     {"invite_reused_rejected", invite_reused},
                     {"outsider_rejected", outsider_rejected},
                     {"relayed_chat", relayed_chat},
                     {"tamper_rejected", tamper_rejected},
                     {"manifest_reference_hidden", manifest_hidden},
                     {"membership_rotates_keys", false},
                     {"channel_key", "one-for-process"},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
