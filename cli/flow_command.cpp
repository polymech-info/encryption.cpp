#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/flow.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#include <sodium.h>

namespace pm::encryption::cli {
namespace {

constexpr const char* k_schema = "pm.encryption.flow.v1";

void wipe(std::vector<std::uint8_t>& bytes) {
    if (!bytes.empty())
        sodium_memzero(bytes.data(), bytes.size());
    bytes.clear();
}

bool same(const std::vector<std::uint8_t>& left, const std::vector<std::uint8_t>& right) {
    return left.size() == right.size()
        && (left.empty() || sodium_memcmp(left.data(), right.data(), left.size()) == 0);
}

} // namespace

int run_flow(LogSink& log) {
    Error err;
    SecureEndpoint endpoint = SecureEndpoint::open(err);

    FlowOptions reliable;
    reliable.delivery = Delivery::Reliable;
    reliable.id = bytes_of("chat");
    reliable.scope = bytes_of("pair");
    SecureFlow denied_reliable = endpoint.open_flow(reliable, err);
    const bool reliable_rejected = err.code == ErrorCode::InvalidArgument && !denied_reliable.valid();

    FlowOptions durable;
    durable.delivery = Delivery::Durable;
    durable.id = bytes_of("object");
    durable.scope = bytes_of("pair");
    SecureFlow denied_durable = endpoint.open_flow(durable, err);
    const bool durable_rejected = err.code == ErrorCode::InvalidArgument && !denied_durable.valid();

    FlowOptions options;
    options.delivery = Delivery::Datagram;
    options.id = bytes_of("chat");
    options.scope = bytes_of("pair");
    options.epoch = 1;
    SecureFlow alice = endpoint.open_flow(options, err);
    std::vector<std::uint8_t> wrap;
    if (!err)
        err = alice.export_key(wrap);
    std::vector<std::uint8_t> first_wrap = wrap;
    SecureFlow bob = SecureFlow::accept(wrap, err);
    SecureFlow kept = SecureFlow::accept(wrap, err);
    wipe(wrap);
    std::vector<std::uint8_t> peer_packet;
    Error peer_send = bob.seal(bytes_of("flow-peer-send"), peer_packet);
    const bool receiver_cannot_send = peer_send.code == ErrorCode::UnexpectedState && peer_packet.empty() && !bob.can_send();
    std::vector<std::uint8_t> peer_wrap;
    Error peer_rekey = bob.rekey(peer_wrap);
    const bool receiver_cannot_rekey = peer_rekey.code == ErrorCode::UnexpectedState && peer_wrap.empty();
    wipe(peer_wrap);

    const auto text = bytes_of("flow-chat-bytes");
    const std::vector<std::uint8_t> binary{0x00, 0xff, 0x10, 0x7f};
    const auto framed = bytes_of("PMD1-looking-frame");
    std::vector<std::uint8_t> sealed_text;
    std::vector<std::uint8_t> sealed_binary;
    std::vector<std::uint8_t> sealed_frame;
    if (!err)
        err = alice.seal(text, sealed_text);
    if (!err)
        err = alice.seal(binary, sealed_binary);
    if (!err)
        err = alice.seal(framed, sealed_frame);

    std::vector<std::uint8_t> opened;
    bool chat_ok = false;
    bool binary_ok = false;
    bool frame_ok = false;
    if (!err)
        err = bob.open(sealed_text, opened);
    chat_ok = !err && same(opened, text);
    if (!err)
        err = bob.open(sealed_binary, opened);
    binary_ok = !err && same(opened, binary);
    if (!err)
        err = bob.open(sealed_frame, opened);
    frame_ok = !err && same(opened, framed);
    Error replay = bob.open(sealed_text, opened);

    FlowOptions other = options;
    other.id = bytes_of("bin");
    SecureFlow side = endpoint.open_flow(other, err);
    std::vector<std::uint8_t> side_packet;
    if (!err)
        err = side.seal(text, side_packet);
    Error crossed = bob.open(side_packet, opened);
    Error crossed_back = side.open(sealed_text, opened);

    FlowOptions scoped = options;
    scoped.scope = bytes_of("other");
    SecureFlow wrong_scope = endpoint.open_flow(scoped, err);
    Error scope_err = wrong_scope.open(sealed_text, opened);

    const auto gap_one = bytes_of("flow-gap-one");
    const auto gap_two = bytes_of("flow-gap-two");
    const auto gap_three = bytes_of("flow-gap-three");
    std::vector<std::uint8_t> packet_one;
    std::vector<std::uint8_t> packet_two;
    std::vector<std::uint8_t> packet_three;
    if (!err)
        err = alice.seal(gap_one, packet_one);
    if (!err)
        err = alice.seal(gap_two, packet_two);
    if (!err)
        err = alice.seal(gap_three, packet_three);
    bool gap = false;
    if (!err)
        err = bob.open(packet_three, opened);
    gap = !err && same(opened, gap_three);
    if (!err)
        err = bob.open(packet_one, opened);
    gap = gap && !err && same(opened, gap_one);

    const auto old_bytes = bytes_of("flow-old-epoch");
    const auto new_bytes = bytes_of("flow-new-epoch");
    std::vector<std::uint8_t> old_packet;
    std::vector<std::uint8_t> next_wrap;
    std::vector<std::uint8_t> new_packet;
    if (!err)
        err = alice.seal(old_bytes, old_packet);
    if (!err)
        err = alice.rekey(next_wrap);
    SecureFlow current = SecureFlow::accept(next_wrap, err);
    wipe(next_wrap);
    if (!err)
        err = alice.seal(new_bytes, new_packet);
    Error stale_wrap = kept.accept_next(first_wrap);
    const bool stale_wrap_rejected = stale_wrap.code == ErrorCode::Stale && kept.epoch() == 1;
    wipe(first_wrap);

    alice.close();
    std::vector<std::uint8_t> ignored;
    Error closed = alice.seal(bytes_of("flow-after-close"), ignored);
    const bool closed_dead = !alice.valid();
    wipe(ignored);

    Error kept_old = kept.open(old_packet, opened);
    const bool old_kept = !kept_old && same(opened, old_bytes);
    Error current_old = current.open(old_packet, opened);
    Error current_new = current.open(new_packet, opened);
    const bool new_opened = !current_new && same(opened, new_bytes);
    Error kept_new = kept.open(new_packet, opened);

    const std::string setup_error = err.message;
    std::vector<std::uint8_t> too_big(k_datagram_max_plaintext + 1, 0x11);
    SecureFlow fresh = endpoint.open_flow(options, err);
    Error too_big_err = fresh.seal(too_big, ignored);
    wipe(too_big);
    wipe(ignored);

    const bool flow_separated = crossed.code == ErrorCode::WrongSession && crossed_back.code == ErrorCode::WrongSession;
    const bool scope_separated = scope_err.code == ErrorCode::WrongSession;
    const bool epoch_separated = current_old.code == ErrorCode::WrongSession && kept_new.code == ErrorCode::WrongSession
        && new_opened;
    const bool close_local = closed.code == ErrorCode::InvalidArgument && old_kept && closed_dead;
    const bool size_rejected = too_big_err.code == ErrorCode::PlaintextTooLarge;
    const bool ok = reliable_rejected && durable_rejected && chat_ok && binary_ok && frame_ok && gap && flow_separated
        && scope_separated && epoch_separated && close_local && size_rejected && replay.code == ErrorCode::Replay
        && receiver_cannot_send && receiver_cannot_rekey && stale_wrap_rejected;
    if (!ok && err)
        log_warn(log, "flow", err.message);
    log_info(log, "flow", ok ? "passed" : "failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", k_schema},
                     {"delivery", "datagram"},
                     {"chat_bytes", chat_ok},
                     {"binary", binary_ok},
                     {"encoded_frame", frame_ok},
                     {"flow_separated", flow_separated},
                     {"scope_separated", scope_separated},
                     {"epoch_separated", epoch_separated},
                     {"old_key_kept", old_kept},
                     {"close_local_only", close_local},
                     {"gap", gap},
                     {"replay_rejected", replay.code == ErrorCode::Replay},
                     {"reliable_rejected", reliable_rejected},
                     {"durable_rejected", durable_rejected},
                     {"size_rejected", size_rejected},
                     {"receiver_cannot_send", receiver_cannot_send},
                     {"receiver_cannot_rekey", receiver_cannot_rekey},
                     {"stale_wrap_rejected", stale_wrap_rejected},
                     {"webrtc", false},
                     {"transport", false},
                     {"setup_error", setup_error},
                     {"replay_code", error_code_name(replay.code)},
                     {"crossed_code", error_code_name(crossed.code)},
                     {"scope_code", error_code_name(scope_err.code)},
                     {"closed_code", error_code_name(closed.code)},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
}

} // namespace pm::encryption::cli
