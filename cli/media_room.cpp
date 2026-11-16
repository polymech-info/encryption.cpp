#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/audio.hpp"
#include "pm/encryption/features.hpp"
#include "pm/encryption/video.hpp"

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

constexpr const char* k_schema = "pm.media.room.v1";

nlohmann::json media_failure(const char* code, std::string error) {
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

Error exchange_key(SignalEndpoint& sender, SignalEndpoint& receiver, pm::room::Broker& broker,
                   const Identity& sender_id, const pm::room::Id& room_id, std::string_view peer,
                   TrackKey& local, TrackKey& remote) {
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
    remote = TrackKey::from_wrap(opened, err);
    wipe(opened);
    return err;
}

#endif

} // namespace

int run_media_room(LogSink& log) {
#if !PM_ENCRYPTION_LIBSIGNAL
    log_warn(log, "media", "libsignal is not compiled");
    std::cout << media_failure("feature_disabled", "media room needs the signal text session").dump() << "\n";
    return 1;
#else
    Error err;
    auto alice_id = keyed(0xA1, err);
    auto bob_id = keyed(0xB2, err);
    auto signal_alice = SignalEndpoint::open("alice", err);
    auto signal_bob = SignalEndpoint::open("bob", err);
    if (err || !alice_id.valid() || !bob_id.valid() || !signal_alice.valid() || !signal_bob.valid()) {
        std::cout << media_failure("crypto_unavailable", err.message).dump() << "\n";
        return 1;
    }

    std::vector<std::uint8_t> bundle;
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
    const std::uint32_t media_grants = pm::room::k_grant_chat | pm::room::k_grant_audio | pm::room::k_grant_video;
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

    TrackKey audio_key = TrackKey::generate(MediaKind::Audio, 1, err);
    TrackKey video_key = TrackKey::generate(MediaKind::Video, 1, err);
    TrackKey bob_audio;
    TrackKey bob_video;
    if (!err)
        err = exchange_key(signal_alice, signal_bob, broker, alice_id, room_id, "bob", audio_key, bob_audio);
    if (!err)
        err = exchange_key(signal_alice, signal_bob, broker, alice_id, room_id, "bob", video_key, bob_video);

    AudioSender audio_tx = AudioSender::adopt(std::move(audio_key), err);
    AudioReceiver audio_rx = AudioReceiver::adopt(std::move(bob_audio), err);
    VideoSender video_tx = VideoSender::adopt(std::move(video_key), err);
    VideoReceiver video_rx = VideoReceiver::adopt(std::move(bob_video), err);

    const auto audio_one = bytes_of("audio-frame-one");
    const auto audio_gap = bytes_of("audio-frame-gap");
    const auto audio_two = bytes_of("audio-frame-two");
    const auto video_one = bytes_of("video-frame-one");
    std::vector<std::uint8_t> packet_one;
    std::vector<std::uint8_t> packet_gap;
    std::vector<std::uint8_t> packet_two;
    std::vector<std::uint8_t> video_packet;
    if (!err)
        err = audio_tx.seal(audio_one, 0, packet_one);
    if (!err)
        err = audio_tx.seal(audio_gap, 20, packet_gap);
    if (!err)
        err = audio_tx.seal(audio_two, 40, packet_two);
    if (!err)
        err = video_tx.seal(video_one, 40, video_packet);

    std::vector<std::uint8_t> opened;
    std::uint32_t stamp = 0;
    std::uint64_t sequence = 0;
    bool gap = false;
    if (!err)
        err = audio_rx.open(packet_two, opened, stamp, sequence);
    gap = !err && sequence == 2 && opened == audio_two && stamp == 40;
    if (!err)
        err = audio_rx.open(packet_one, opened, stamp, sequence);
    gap = gap && !err && sequence == 0 && opened == audio_one;
    Error replay = audio_rx.open(packet_one, opened, stamp, sequence);

    auto flipped = packet_two;
    if (!flipped.empty())
        flipped.back() ^= 0x01;
    Error tamper = audio_rx.open(flipped, opened, stamp, sequence);
    Error crossed = video_rx.open(packet_two, opened, stamp, sequence);
    Error crossed_back = audio_rx.open(video_packet, opened, stamp, sequence);

    bool video_ok = false;
    if (!err)
        err = video_rx.open(video_packet, opened, stamp, sequence);
    video_ok = !err && sequence == 0 && opened == video_one;
    const bool setup = !err;
    const std::string setup_error = err.message;

    TrackKey next_gen = TrackKey::generate(MediaKind::Audio, 2, err);
    AudioReceiver rotated = AudioReceiver::adopt(std::move(next_gen), err);
    Error old_gen = rotated.open(packet_one, opened, stamp, sequence);

    TrackKey outsider_key = TrackKey::generate(MediaKind::Audio, 1, err);
    AudioReceiver outsider = AudioReceiver::adopt(std::move(outsider_key), err);
    Error outsider_err = outsider.open(packet_one, opened, stamp, sequence);

    fetched.clear();
    Error fetch_err = broker.fetch(room_id, 0, fetched);
    const bool hidden = !fetch_err && frames_hide(fetched, "audio-frame-one") && frames_hide(fetched, "audio-frame-gap")
        && frames_hide(fetched, "audio-frame-two") && frames_hide(fetched, "video-frame-one");
    const bool granted = (room.grants & pm::room::k_grant_audio) != 0 && (room.grants & pm::room::k_grant_video) != 0;
    const bool paired_ok = paired.trust == pm::room::Trust::Paired;
    const bool ok = setup && gap && video_ok && hidden && granted && files_rejected && paired_ok
        && fetched.size() == 3 && replay.code == ErrorCode::Replay
        && tamper.code == ErrorCode::AuthenticationFailed
        && crossed.code == ErrorCode::InvalidFrame && crossed_back.code == ErrorCode::InvalidFrame
        && old_gen.code == ErrorCode::WrongSession && outsider_err.code == ErrorCode::AuthenticationFailed
        && room.members.size() == 2;
    if (!ok && err)
        log_warn(log, "media", err.message);
    log_info(log, "media", ok ? "room passed" : "room failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", k_schema},
                     {"audio", true},
                     {"video", true},
                     {"transport", false},
                     {"gap", gap},
                     {"video_opened", video_ok},
                     {"replay_rejected", replay.code == ErrorCode::Replay},
                     {"replay_code", error_code_name(replay.code)},
                     {"tamper_code", error_code_name(tamper.code)},
                     {"crossed_code", error_code_name(crossed.code)},
                     {"generation_code", error_code_name(old_gen.code)},
                     {"outsider_code", error_code_name(outsider_err.code)},
                     {"setup_error", setup_error},
                     {"tamper_rejected", tamper.code == ErrorCode::AuthenticationFailed},
                     {"kind_separated", crossed.code == ErrorCode::InvalidFrame
                          && crossed_back.code == ErrorCode::InvalidFrame},
                     {"generation_separated", old_gen.code == ErrorCode::WrongSession},
                     {"outsider_rejected", outsider_err.code == ErrorCode::AuthenticationFailed},
                     {"files_grant_rejected", files_rejected},
                     {"broker_sees_media", false},
                     {"media_hidden", hidden},
                     {"frames", fetched.size()},
                     {"members", room.members.size()},
                     {"grants", granted ? "chat+audio+video" : "missing"},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
