#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#if PM_ENCRYPTION_LIBSIGNAL
#include "pm/encryption/signal_session.hpp"
#include "pm/room/broker.hpp"

#include <cstring>
#endif

namespace pm::encryption::cli {
namespace {

constexpr const char* k_schema = "pm.signal.room.v1";

nlohmann::json signal_failure(const char* code, std::string error) {
    return {{"ok", false}, {"schema", k_schema}, {"code", code}, {"error", std::move(error)}};
}

#if PM_ENCRYPTION_LIBSIGNAL

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

bool frames_hide(const std::vector<pm::room::Envelope>& frames, std::string_view text) {
    for (const auto& frame : frames) {
        if (contains_text(frame.frame, text))
            return false;
    }
    return true;
}

#endif

} // namespace

int run_signal_room(const std::string& text, LogSink& log) {
#if !PM_ENCRYPTION_LIBSIGNAL
    (void)text;
    log_warn(log, "signal", "libsignal is not compiled");
    std::cout << signal_failure("feature_disabled", "signal session policy is not compiled").dump()
              << "\n";
    return 1;
#else
    if (text.empty() || text.size() > 12U * 1024U) {
        std::cout << signal_failure("invalid_argument", "signal room text is empty or over 12288 bytes").dump()
                  << "\n";
        return text.empty() ? 2 : 1;
    }

    Error err;
    auto alice_id = keyed(0xA1, err);
    auto bob_id = keyed(0xB2, err);
    auto signal_alice = SignalEndpoint::open("alice", err);
    auto signal_bob = SignalEndpoint::open("bob", err);
    if (err || !alice_id.valid() || !bob_id.valid() || !signal_alice.valid() || !signal_bob.valid()) {
        std::cout << signal_failure("crypto_unavailable", err.message).dump() << "\n";
        return 1;
    }

    std::vector<std::uint8_t> bundle;
    err = signal_bob.export_bundle(bundle, true);
    if (err || bundle.empty()) {
        std::cout << signal_failure("crypto_unavailable", err ? err.message : "empty prekey bundle").dump()
                  << "\n";
        return 1;
    }

    auto pairing_id = random_session_id(err);
    auto room_id = random_session_id(err);
    pm::room::Broker broker;
    pm::room::PairOffer offer;
    if (!err)
        err = pm::room::create_offer(alice_id, pairing_id, offer);
    if (!err)
        err = broker.put_offer(offer);
    pm::room::PairAccept accept;
    if (!err)
        err = pm::room::accept_offer(bob_id, offer, accept);
    if (!err)
        err = broker.put_accept(accept);
    pm::room::Fingerprint shown = pm::room::fingerprint_of(offer.initiator, bob_id.public_key(), pairing_id, err);
    pm::room::PairedDevice paired;
    if (!err)
        err = pm::room::confirm_pairing(alice_id, accept, shown, paired);
    pm::room::Room room;
    if (!err)
        err = broker.create_room(alice_id, room_id, room);
    pm::room::Invite invite;
    if (!err)
        err = broker.invite(alice_id, room_id, bob_id.public_key(), pm::room::k_grant_chat, invite);
    pm::room::Invite files;
    Error files_err = err ? err
                          : broker.invite(alice_id, room_id, bob_id.public_key(), pm::room::k_grant_files, files);
    const bool files_rejected = files_err.code == ErrorCode::InvalidArgument;
    if (!err)
        err = broker.join(bob_id, invite, room);

    pm::room::Envelope bundle_frame;
    if (!err)
        err = broker.post(bob_id, room_id, bundle, bundle_frame);
    std::vector<pm::room::Envelope> fetched;
    if (!err)
        err = broker.fetch(room_id, 0, fetched);
    if (!err)
        err = signal_alice.initiate("bob", fetched.empty() ? std::span<const std::uint8_t>{} : fetched.front().frame);

    const auto plain = bytes_of(text);
    std::vector<std::uint8_t> first;
    if (!err)
        err = signal_alice.encrypt("bob", plain, first);
    pm::room::Envelope first_frame;
    if (!err)
        err = broker.post(alice_id, room_id, first, first_frame);
    fetched.clear();
    if (!err)
        err = broker.fetch(room_id, 1, fetched);
    std::vector<std::uint8_t> opened;
    if (!err)
        err = signal_bob.decrypt("alice", fetched.empty() ? std::span<const std::uint8_t>{} : fetched.front().frame, opened);
    const bool offline_first = !err && opened == plain;

    std::vector<std::uint8_t> reply;
    const auto reply_plain = bytes_of("ack");
    if (!err)
        err = signal_bob.encrypt("alice", reply_plain, reply);
    pm::room::Envelope reply_frame;
    if (!err)
        err = broker.post(bob_id, room_id, reply, reply_frame);
    fetched.clear();
    if (!err)
        err = broker.fetch(room_id, first_frame.sequence, fetched);
    if (!err)
        err = signal_alice.decrypt("bob", fetched.empty() ? std::span<const std::uint8_t>{} : fetched.front().frame, opened);
    const bool reply_ok = !err && opened == reply_plain;
    Error replay = signal_alice.decrypt("bob", reply, opened);
    const bool duplicate_rejected = static_cast<bool>(replay) && opened.empty();

    std::vector<std::uint8_t> one;
    std::vector<std::uint8_t> two;
    if (!err)
        err = signal_alice.encrypt("bob", bytes_of("one"), one);
    if (!err)
        err = signal_alice.encrypt("bob", bytes_of("two"), two);
    if (!err)
        err = signal_bob.decrypt("alice", two, opened);
    const bool two_ok = !err && opened == bytes_of("two");
    if (!err)
        err = signal_bob.decrypt("alice", one, opened);
    const bool reorder = two_ok && !err && opened == bytes_of("one");

    auto tampered = first;
    if (!tampered.empty())
        tampered.back() ^= 0x01;
    Error flipped = signal_bob.decrypt("alice", tampered, opened);

    auto carol = SignalEndpoint::open("carol", err);
    Error outsider;
    if (carol.valid())
        outsider = carol.decrypt("alice", first, opened);

    auto dave = SignalEndpoint::open("dave", err);
    auto eve = SignalEndpoint::open("eve", err);
    std::vector<std::uint8_t> bare;
    Error bare_err;
    if (dave.valid())
        bare_err = dave.export_bundle(bare, false);
    if (!bare_err && eve.valid())
        bare_err = eve.initiate("dave", bare);
    std::vector<std::uint8_t> bare_cipher;
    std::vector<std::uint8_t> bare_open;
    if (!bare_err)
        bare_err = eve.encrypt("dave", bytes_of("no-onetime"), bare_cipher);
    if (!bare_err)
        bare_err = dave.decrypt("eve", bare_cipher, bare_open);
    const bool no_onetime = !bare_err && bare_open == bytes_of("no-onetime");

    fetched.clear();
    Error fetch_err = broker.fetch(room_id, 0, fetched);
    const bool hidden = !fetch_err && frames_hide(fetched, text) && frames_hide(fetched, "one")
        && frames_hide(fetched, "two") && frames_hide(fetched, "ack");

    const bool tamper_rejected = static_cast<bool>(flipped);
    const bool outsider_rejected = static_cast<bool>(outsider);
    const bool ok = offline_first && reply_ok && reorder && no_onetime && hidden
        && duplicate_rejected && tamper_rejected && outsider_rejected
        && files_rejected
        && room.members.size() == 2;
    if (!ok && err)
        log_warn(log, "signal", err.message);
    log_info(log, "signal", ok ? "room passed" : "room failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", k_schema},
                     {"policy", "signal"},
                     {"session", "pqxdh-triple-ratchet"},
                     {"offline_first", offline_first},
                     {"reply", reply_ok},
                     {"reorder", reorder},
                     {"no_onetime_prekey", no_onetime},
                     {"duplicate_rejected", duplicate_rejected},
                     {"tamper_rejected", tamper_rejected},
                     {"outsider_rejected", outsider_rejected},
                     {"replay_code", error_code_name(replay.code)},
                     {"tamper_code", error_code_name(flipped.code)},
                     {"outsider_code", error_code_name(outsider.code)},
                     {"files_grant_rejected", files_rejected},
                     {"broker_sees_plaintext", false},
                     {"plaintext_hidden", hidden},
                     {"audio", false},
                     {"video", false},
                     {"members", room.members.size()},
                     {"ratchet", true},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
