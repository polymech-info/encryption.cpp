#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"
#include "pm/host/device.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#if PM_ENCRYPTION_LIBSIGNAL
#include "pm/encryption/signal_session.hpp"
#include "pm/room/broker.hpp"

#include <sodium.h>

#include <cstring>
#endif

namespace pm::encryption::cli {
namespace {

constexpr const char* k_schema = "pm.host.media.v1";

nlohmann::json host_failure(const char* code, std::string error) {
    return {{"ok", false}, {"schema", k_schema}, {"code", code}, {"error", std::move(error)}};
}

#if PM_ENCRYPTION_LIBSIGNAL

Identity keyed(std::uint8_t tag, Error& err) {
    Seed seed{};
    seed.fill(tag);
    return Identity::from_seed(seed, err);
}

void wipe(std::vector<std::uint8_t>& bytes) {
    if (!bytes.empty())
        sodium_memzero(bytes.data(), bytes.size());
    bytes.clear();
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

bool same_bytes(const std::vector<std::uint8_t>& left, const std::vector<std::uint8_t>& right) {
    return left == right;
}

Error exchange_key(SignalEndpoint& sender, SignalEndpoint& receiver, pm::room::Broker& broker,
                   const Identity& sender_id, const pm::room::Id& room_id, std::string_view peer,
                   FlowKey& local, FlowKey& remote) {
    std::vector<std::uint8_t> wrap;
    if (Error err = local.write_wrap(wrap))
        return err;
    std::vector<std::uint8_t> sealed;
    Error err = sender.encrypt(peer, wrap, sealed);
    wipe(wrap);
    if (err)
        return err;
    pm::room::Envelope posted;
    if (Error post_err = broker.post(sender_id, room_id, sealed, posted))
        return post_err;
    std::vector<pm::room::Envelope> got;
    if (Error fetch_err = broker.fetch(room_id, posted.sequence - 1, got))
        return fetch_err;
    if (got.empty())
        return Error::make(ErrorCode::UnexpectedState, "media key wrap was not relayed");
    std::vector<std::uint8_t> opened;
    err = receiver.decrypt(sender.name(), got.front().frame, opened);
    if (err) {
        wipe(opened);
        return err;
    }
    remote = FlowKey::from_wrap(opened, err);
    wipe(opened);
    return err;
}

#endif

} // namespace

int run_media_host(LogSink& log) {
#if !PM_ENCRYPTION_LIBSIGNAL
    log_warn(log, "media-host", "libsignal is not compiled");
    std::cout << host_failure("feature_disabled", "media host needs the signal text session").dump() << "\n";
    return 1;
#else
    Error err;
    auto alice_id = keyed(0xA1, err);
    auto bob_id = keyed(0xB2, err);
    auto signal_alice = SignalEndpoint::open("alice", err);
    auto signal_bob = SignalEndpoint::open("bob", err);
    const std::uint32_t media_grants = pm::room::k_grant_chat | pm::room::k_grant_audio | pm::room::k_grant_video;
    pm::host::Device alice;
    pm::host::Device bob;
    pm::host::Device chat_only;
    if (!err)
        err = alice.open("alice", media_grants);
    if (!err)
        err = bob.open("bob", media_grants);
    if (!err)
        err = chat_only.open("chat-only", pm::room::k_grant_chat);

    std::vector<std::uint8_t> bundle;
    if (!err)
        err = signal_bob.export_bundle(bundle, true);
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
        err = broker.invite(alice_id, room_id, bob_id.public_key(), media_grants, invite);
    pm::room::Invite files;
    Error files_err = err ? err : broker.invite(alice_id, room_id, bob_id.public_key(), pm::room::k_grant_files, files);
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

    const auto mic = bytes_of(pm::host::k_microphone_flow);
    const auto cam = bytes_of(pm::host::k_camera_flow);
    const auto scope = bytes_of("pair");
    FlowKey audio_key = FlowKey::generate(mic, scope, 1, err);
    FlowKey video_key = FlowKey::generate(cam, scope, 1, err);
    FlowKey bob_audio;
    FlowKey bob_video;
    if (!err)
        err = exchange_key(signal_alice, signal_bob, broker, alice_id, room_id, "bob", audio_key, bob_audio);
    if (!err)
        err = exchange_key(signal_alice, signal_bob, broker, alice_id, room_id, "bob", video_key, bob_video);
    if (!err)
        err = alice.install_send(std::move(audio_key));
    if (!err)
        err = alice.install_send(std::move(video_key));
    if (!err)
        err = bob.install_recv(std::move(bob_audio));
    if (!err)
        err = bob.install_recv(std::move(bob_video));

    const auto mic_one = bytes_of("mic-one");
    const auto mic_gap = bytes_of("mic-gap");
    const auto mic_two = bytes_of("mic-two");
    const auto cam_one = bytes_of("cam-one");
    const auto mic_muted = bytes_of("mic-muted");
    const auto mic_new = bytes_of("mic-new");
    if (!err)
        err = alice.capture(pm::host::Source::Microphone, 0, mic_one);
    if (!err)
        err = alice.capture(pm::host::Source::Microphone, 20, mic_gap);
    if (!err)
        err = alice.capture(pm::host::Source::Microphone, 40, mic_two);
    if (!err)
        err = alice.capture(pm::host::Source::Camera, 40, cam_one);

    std::vector<std::vector<std::uint8_t>> plane;
    if (!err)
        err = alice.publish(plane);
    const bool published = !err && plane.size() == 4 && alice.published() == 4;

    bool rendered = false;
    if (published) {
        rendered = !bob.render(plane[2]) && !bob.render(plane[0]) && !bob.render(plane[3])
            && bob.rendered().size() == 3
            && same_bytes(bob.rendered()[0].payload, mic_two) && bob.rendered()[0].sequence == 2
            && same_bytes(bob.rendered()[1].payload, mic_one) && bob.rendered()[1].sequence == 0
            && bob.rendered()[2].source == pm::host::Source::Camera
            && same_bytes(bob.rendered()[2].payload, cam_one);
        for (const auto& frame : bob.rendered()) {
            if (same_bytes(frame.payload, mic_gap))
                rendered = false;
        }
    }

    const std::size_t before_mute = plane.size();
    alice.set_muted(pm::host::Source::Microphone, true);
    if (!err)
        err = alice.capture(pm::host::Source::Microphone, 60, mic_muted);
    if (!err)
        err = alice.publish(plane);
    const bool muted = !err && plane.size() == before_mute && alice.muted_dropped() >= 1;
    alice.set_muted(pm::host::Source::Microphone, false);

    if (!err)
        err = chat_only.capture(pm::host::Source::Microphone, 0, mic_one);
    Error grant_err = chat_only.publish(plane);
    const bool grant_required = grant_err.code == ErrorCode::InvalidArgument && plane.size() == before_mute;
    const std::string early_error = err.message;

    FlowKey audio_next = FlowKey::generate(mic, scope, 2, err);
    FlowKey bob_next;
    if (!err)
        err = exchange_key(signal_alice, signal_bob, broker, alice_id, room_id, "bob", audio_next, bob_next);
    if (!err)
        err = alice.install_send(std::move(audio_next));
    if (!err)
        err = bob.install_recv(std::move(bob_next));
    if (!err)
        err = alice.capture(pm::host::Source::Microphone, 80, mic_new);
    const std::size_t before_rekey = plane.size();
    if (!err)
        err = alice.publish(plane);
    const bool rekeyed = !err && plane.size() == before_rekey + 1 && !bob.render(plane.back())
        && same_bytes(bob.rendered().back().payload, mic_new) && bob.rendered().back().generation == 2;
    const std::size_t rendered_before_stale = bob.rendered().size();
    Error stale = bob.render(plane[0]);
    const bool stale_discarded = stale.code == ErrorCode::WrongSession && bob.rendered().size() == rendered_before_stale;

    fetched.clear();
    Error fetch_err = broker.fetch(room_id, 0, fetched);
    const bool hidden = !fetch_err && frames_hide(fetched, "mic-one") && frames_hide(fetched, "mic-gap")
        && frames_hide(fetched, "mic-two") && frames_hide(fetched, "cam-one") && frames_hide(fetched, "mic-muted")
        && frames_hide(fetched, "mic-new");
    const bool ok = published && rendered && muted && grant_required && rekeyed && stale_discarded && hidden
        && files_rejected && paired.trust == pm::room::Trust::Paired && room.members.size() == 2 && !err;
    if (!ok && err)
        log_warn(log, "media-host", err.message);
    log_info(log, "media-host", ok ? "passed" : "failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", k_schema},
                     {"host", "in-process"},
                     {"capture", published},
                     {"render", rendered},
                     {"muted", muted},
                     {"grant_required", grant_required},
                     {"rekey", rekeyed},
                     {"stale_discarded", stale_discarded},
                     {"media_hidden", hidden},
                     {"files_grant_rejected", files_rejected},
                     {"broker_sees_media", false},
                     {"codec", false},
                     {"webrtc", false},
                     {"transport", false},
                     {"frames", fetched.size()},
                     {"rendered", bob.rendered().size()},
                     {"setup_error", early_error.empty() ? err.message : early_error},
                     {"stale_code", error_code_name(stale.code)},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
