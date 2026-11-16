#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"

#include <iostream>
#include <utility>

namespace pm::encryption::cli {
namespace {

#if PM_ENCRYPTION_UNAUTHENTICATED_KX
struct Pair {
    SecureChannel initiator;
    SecureChannel responder;
};

Pair deterministic_pair(std::string context, SessionId session_id, Error& err) {
    Seed client_seed{};
    Seed server_seed{};
    for (std::size_t i = 0; i < client_seed.size(); ++i) {
        client_seed[i] = static_cast<std::uint8_t>(i + 1);
        server_seed[i] = static_cast<std::uint8_t>(0xf0U - i);
    }
    auto client_keys = KeyPair::from_seed(client_seed, err);
    if (err)
        return {};
    auto server_keys = KeyPair::from_seed(server_seed, err);
    if (err)
        return {};
    const auto client_public = client_keys.public_key();
    const auto server_public = server_keys.public_key();
    Pair out;
    out.initiator = SecureChannel::initiator(
        std::move(client_keys), server_public, session_id, context, err);
    if (err)
        return {};
    out.responder = SecureChannel::responder(
        std::move(server_keys), client_public, session_id, std::move(context), err);
    return out;
}
#endif

} // namespace

int run_channel_checks(Check& check) {
#if !PM_ENCRYPTION_UNAUTHENTICATED_KX
    (void)check;
    return 0;
#else
    Error err;
    auto pair = deterministic_pair("/v1/chat/completions|turn-1", test_session(), err);
    check(!err && pair.initiator.valid() && pair.responder.valid(),
          "derive complementary channel keys", err.message);
    if (err) {
        std::cout << nlohmann::json{{"ok", false}, {"passed", check.passed},
                                    {"failed", check.failed}, {"failures", check.failures}}
                         .dump()
                  << "\n";
        return 1;
    }

    std::vector<std::uint8_t> request_frame;
    const auto request = bytes_of(
        R"({"model":"text-fast","messages":[{"role":"user","content":"hello"}]})");
    err = pair.initiator.seal(request, "application/json", request_frame);
    check(!err && !request_frame.empty(), "seal request", err.message);
    std::vector<std::uint8_t> opened;
    err = pair.responder.open(request_frame, "application/json", opened);
    check(!err && opened == request, "open request", err.message);

    std::vector<std::uint8_t> response_frame;
    const auto response = bytes_of("data: encrypted assistant delta\n\n");
    err = pair.responder.seal(response, "text/event-stream", response_frame);
    check(!err, "seal response event", err.message);
    err = pair.initiator.open(response_frame, "text/event-stream", opened);
    check(!err && opened == response, "open response event", err.message);

    err = pair.responder.open(request_frame, "application/json", opened);
    check(err.code == ErrorCode::Replay, "reject duplicate request frame",
          error_code_name(err.code));

    {
        auto p = deterministic_pair("/v1/chat/completions|tamper", test_session(1), err);
        std::vector<std::uint8_t> frame;
        p.initiator.seal(bytes_of("secret"), "application/json", frame);
        frame.back() ^= 0x80;
        err = p.responder.open(frame, "application/json", opened);
        check(err.code == ErrorCode::AuthenticationFailed && opened.empty(),
              "reject modified ciphertext", error_code_name(err.code));
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|type", test_session(2), err);
        std::vector<std::uint8_t> frame;
        p.initiator.seal(bytes_of("body"), "application/json", frame);
        err = p.responder.open(frame, "text/event-stream", opened);
        check(err.code == ErrorCode::WrongContentType, "bind content type",
              error_code_name(err.code));
    }
    {
        auto sender = deterministic_pair("/v1/chat/completions|a", test_session(3), err);
        auto receiver = deterministic_pair("/v1/chat/completions|b", test_session(3), err);
        std::vector<std::uint8_t> frame;
        sender.initiator.seal(bytes_of("body"), "application/json", frame);
        err = receiver.responder.open(frame, "application/json", opened);
        check(err.code == ErrorCode::AuthenticationFailed, "bind route/request context",
              error_code_name(err.code));
    }
    {
        auto sender = deterministic_pair("/v1/chat/completions|session", test_session(4), err);
        auto receiver = deterministic_pair("/v1/chat/completions|session", test_session(5), err);
        std::vector<std::uint8_t> frame;
        sender.initiator.seal(bytes_of("body"), "application/json", frame);
        err = receiver.responder.open(frame, "application/json", opened);
        check(err.code == ErrorCode::WrongSession, "bind session id", error_code_name(err.code));
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|direction", test_session(6), err);
        std::vector<std::uint8_t> frame;
        p.initiator.seal(bytes_of("body"), "application/json", frame);
        err = p.initiator.open(frame, "application/json", opened);
        check(err.code == ErrorCode::WrongDirection, "separate traffic directions",
              error_code_name(err.code));
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|order", test_session(7), err);
        std::vector<std::uint8_t> first;
        std::vector<std::uint8_t> second;
        p.initiator.seal(bytes_of("zero"), "application/json", first);
        p.initiator.seal(bytes_of("one"), "application/json", second);
        auto early = p.responder.open(second, "application/json", opened);
        const bool held = early.code == ErrorCode::Stale && opened.empty();
        auto e0 = p.responder.open(first, "application/json", opened);
        const bool zero_ok = !e0 && text_of(opened) == "zero";
        auto e1 = p.responder.open(second, "application/json", opened);
        check(held && zero_ok && !e1 && text_of(opened) == "one",
              "sequence 0 is required before the replay window moves",
              held ? e0.message : error_code_name(early.code));
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|reorder", test_session(12), err);
        std::vector<std::uint8_t> zero;
        std::vector<std::uint8_t> one;
        std::vector<std::uint8_t> two;
        p.initiator.seal(bytes_of("zero"), "application/json", zero);
        p.initiator.seal(bytes_of("one"), "application/json", one);
        p.initiator.seal(bytes_of("two"), "application/json", two);
        auto e0 = p.responder.open(zero, "application/json", opened);
        auto e2 = p.responder.open(two, "application/json", opened);
        const bool two_ok = !e2 && text_of(opened) == "two";
        auto e1 = p.responder.open(one, "application/json", opened);
        check(!e0 && two_ok && !e1 && text_of(opened) == "one",
              "accept bounded reordering after sequence 0", e1.message);
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|stale", test_session(8), err);
        std::vector<std::vector<std::uint8_t>> frames(66);
        for (auto& frame : frames)
            p.initiator.seal(bytes_of("x"), "application/json", frame);
        auto newest = p.responder.open(frames.back(), "application/json", opened);
        const bool held = newest.code == ErrorCode::Stale && opened.empty();
        auto first = p.responder.open(frames.front(), "application/json", opened);
        check(held && !first && text_of(opened) == "x",
              "a high sequence before 0 does not pin the window",
              held ? first.message : error_code_name(newest.code));
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|gap", test_session(13), err);
        std::vector<std::vector<std::uint8_t>> frames(66);
        for (auto& frame : frames)
            p.initiator.seal(bytes_of("x"), "application/json", frame);
        auto first = p.responder.open(frames.front(), "application/json", opened);
        auto jumped = p.responder.open(frames.back(), "application/json", opened);
        err = p.responder.open(frames[1], "application/json", opened);
        check(!first && !jumped && err.code == ErrorCode::Stale,
              "reject frame outside replay window", error_code_name(err.code));
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|empty", test_session(9), err);
        std::vector<std::uint8_t> frame;
        std::vector<std::uint8_t> empty;
        auto sealed = p.initiator.seal(empty, "application/json", frame);
        auto unsealed = p.responder.open(frame, "application/json", opened);
        check(!sealed && !unsealed && opened.empty(), "round trip empty payload", unsealed.message);
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|utf8", test_session(11), err);
        const std::vector<std::uint8_t> utf8{
            0x47, 0x72, 0xc3, 0xbc, 0xc3, 0x9f, 0x20, 0xf0, 0x9f, 0x94, 0x90,
        };
        std::vector<std::uint8_t> frame;
        auto sealed = p.initiator.seal(utf8, "application/json", frame);
        auto unsealed = p.responder.open(frame, "application/json", opened);
        check(!sealed && !unsealed && opened == utf8,
              "round trip UTF-8 and arbitrary bytes", unsealed.message);
    }
    {
        auto p = deterministic_pair("/v1/chat/completions|limit", test_session(10), err);
        std::vector<std::uint8_t> frame;
        auto too_large = p.initiator.seal(bytes_of("12345"), "application/json", frame, 4);
        check(too_large.code == ErrorCode::PlaintextTooLarge, "enforce sender plaintext limit",
              error_code_name(too_large.code));
    }
    {
        Seed seed{};
        seed[0] = 7;
        auto key = KeyPair::from_seed(seed, err);
        const std::string encoded = encode_base64(key.public_key());
        PublicKey decoded{};
        const bool ok = decode_base64(encoded, decoded, err);
        check(ok && decoded == key.public_key(), "strict public-key base64 round trip", err.message);
    }
    check(!k_channel_ratchet && k_first_sequence == 0 && k_replay_window == 64,
          "one channel key, sequence 0, then a 64-frame window");
    return 0;
#endif
}

int run_roundtrip(const std::string& input) {
#if !PM_ENCRYPTION_UNAUTHENTICATED_KX
    (void)input;
    std::cout << nlohmann::json{{"ok", false}, {"code", "unauthenticated_kx_disabled"},
                                {"error", "this build has no unauthenticated channel"}}
                     .dump()
              << "\n";
    return 1;
#else
    Error err;
    auto pair = deterministic_pair("/v1/chat/completions|cli-roundtrip", test_session(), err);
    if (err) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    std::vector<std::uint8_t> frame;
    err = pair.initiator.seal(bytes_of(input), "application/json", frame);
    if (err) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    std::vector<std::uint8_t> opened;
    err = pair.responder.open(frame, "application/json", opened);
    if (err) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    std::cout << nlohmann::json{{"ok", true},
                                {"schema", "pm.encryption.roundtrip.v1"},
                                {"plaintext_bytes", input.size()},
                                {"frame_bytes", frame.size()},
                                {"match", text_of(opened) == input}}
                     .dump()
              << "\n";
    return text_of(opened) == input ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
