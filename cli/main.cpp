#include "pm/encryption/channel.hpp"
#include "http_harness.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {

using pm::encryption::SecureChannel;
using pm::encryption::Error;
using pm::encryption::ErrorCode;
using pm::encryption::KeyPair;
using pm::encryption::Seed;
using pm::encryption::SessionId;
using json = nlohmann::json;

std::vector<std::uint8_t> bytes(std::string_view text) {
    return {text.begin(), text.end()};
}

std::string text(const std::vector<std::uint8_t>& value) {
    return {value.begin(), value.end()};
}

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

SessionId test_session(std::uint8_t suffix = 0) {
    SessionId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(0xa0U + i);
    id.back() ^= suffix;
    return id;
}

json error_json(const Error& err) {
    return {
        {"ok", false},
        {"code", pm::encryption::error_code_name(err.code)},
        {"error", err.message},
    };
}

int run_selftest() {
    int passed = 0;
    int failed = 0;
    json failures = json::array();
    auto check = [&](bool condition, std::string name, std::string detail = {}) {
        if (condition) {
            ++passed;
        } else {
            ++failed;
            failures.push_back({{"name", std::move(name)}, {"detail", std::move(detail)}});
        }
    };

    Error err;
    auto pair = deterministic_pair("/v1/chat/completions|turn-1", test_session(), err);
    check(!err && pair.initiator.valid() && pair.responder.valid(), "derive complementary channel keys",
          err.message);
    if (err) {
        std::cout << json{{"ok", false}, {"passed", passed}, {"failed", failed},
                         {"failures", failures}}
                         .dump()
                  << "\n";
        return 1;
    }

    std::vector<std::uint8_t> request_frame;
    const auto request = bytes(R"({"model":"text-fast","messages":[{"role":"user","content":"hello"}]})");
    err = pair.initiator.seal(request, "application/json", request_frame);
    check(!err && !request_frame.empty(), "seal request", err.message);
    std::vector<std::uint8_t> opened;
    err = pair.responder.open(request_frame, "application/json", opened);
    check(!err && opened == request, "open request", err.message);

    std::vector<std::uint8_t> response_frame;
    const auto response = bytes("data: encrypted assistant delta\n\n");
    err = pair.responder.seal(response, "text/event-stream", response_frame);
    check(!err, "seal response event", err.message);
    err = pair.initiator.open(response_frame, "text/event-stream", opened);
    check(!err && opened == response, "open response event", err.message);

    err = pair.responder.open(request_frame, "application/json", opened);
    check(err.code == ErrorCode::Replay, "reject duplicate request frame",
          pm::encryption::error_code_name(err.code));

    {
        auto p = deterministic_pair("/v1/chat/completions|tamper", test_session(1), err);
        std::vector<std::uint8_t> frame;
        p.initiator.seal(bytes("secret"), "application/json", frame);
        frame.back() ^= 0x80;
        err = p.responder.open(frame, "application/json", opened);
        check(err.code == ErrorCode::AuthenticationFailed && opened.empty(),
              "reject modified ciphertext", pm::encryption::error_code_name(err.code));
    }

    {
        auto p = deterministic_pair("/v1/chat/completions|type", test_session(2), err);
        std::vector<std::uint8_t> frame;
        p.initiator.seal(bytes("body"), "application/json", frame);
        err = p.responder.open(frame, "text/event-stream", opened);
        check(err.code == ErrorCode::WrongContentType, "bind content type",
              pm::encryption::error_code_name(err.code));
    }

    {
        auto sender = deterministic_pair("/v1/chat/completions|a", test_session(3), err);
        auto receiver = deterministic_pair("/v1/chat/completions|b", test_session(3), err);
        std::vector<std::uint8_t> frame;
        sender.initiator.seal(bytes("body"), "application/json", frame);
        err = receiver.responder.open(frame, "application/json", opened);
        check(err.code == ErrorCode::AuthenticationFailed, "bind route/request context",
              pm::encryption::error_code_name(err.code));
    }

    {
        auto sender = deterministic_pair("/v1/chat/completions|session", test_session(4), err);
        auto receiver = deterministic_pair("/v1/chat/completions|session", test_session(5), err);
        std::vector<std::uint8_t> frame;
        sender.initiator.seal(bytes("body"), "application/json", frame);
        err = receiver.responder.open(frame, "application/json", opened);
        check(err.code == ErrorCode::WrongSession, "bind session id",
              pm::encryption::error_code_name(err.code));
    }

    {
        auto p = deterministic_pair("/v1/chat/completions|direction", test_session(6), err);
        std::vector<std::uint8_t> frame;
        p.initiator.seal(bytes("body"), "application/json", frame);
        err = p.initiator.open(frame, "application/json", opened);
        check(err.code == ErrorCode::WrongDirection, "separate traffic directions",
              pm::encryption::error_code_name(err.code));
    }

    {
        auto p = deterministic_pair("/v1/chat/completions|order", test_session(7), err);
        std::vector<std::uint8_t> first;
        std::vector<std::uint8_t> second;
        p.initiator.seal(bytes("zero"), "application/json", first);
        p.initiator.seal(bytes("one"), "application/json", second);
        auto e1 = p.responder.open(second, "application/json", opened);
        const bool second_ok = !e1 && text(opened) == "one";
        auto e0 = p.responder.open(first, "application/json", opened);
        check(second_ok && !e0 && text(opened) == "zero",
              "accept bounded out-of-order delivery", e0.message);
    }

    {
        auto p = deterministic_pair("/v1/chat/completions|stale", test_session(8), err);
        std::vector<std::vector<std::uint8_t>> frames(66);
        for (auto& frame : frames)
            p.initiator.seal(bytes("x"), "application/json", frame);
        auto newest = p.responder.open(frames.back(), "application/json", opened);
        err = p.responder.open(frames.front(), "application/json", opened);
        check(!newest && err.code == ErrorCode::Stale, "reject frame outside replay window",
              pm::encryption::error_code_name(err.code));
    }

    {
        auto p = deterministic_pair("/v1/chat/completions|empty", test_session(9), err);
        std::vector<std::uint8_t> frame;
        std::vector<std::uint8_t> empty;
        auto sealed = p.initiator.seal(empty, "application/json", frame);
        auto unsealed = p.responder.open(frame, "application/json", opened);
        check(!sealed && !unsealed && opened.empty(), "round trip empty payload",
              unsealed.message);
    }

    {
        auto p = deterministic_pair("/v1/chat/completions|utf8", test_session(11), err);
        const std::vector<std::uint8_t> utf8{
            0x47, 0x72, 0xc3, 0xbc, 0xc3, 0x9f, 0x20,
            0xf0, 0x9f, 0x94, 0x90,
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
        auto too_large = p.initiator.seal(bytes("12345"), "application/json", frame, 4);
        check(too_large.code == ErrorCode::PlaintextTooLarge,
              "enforce sender plaintext limit",
              pm::encryption::error_code_name(too_large.code));
    }

    {
        Seed seed{};
        seed[0] = 7;
        auto key = KeyPair::from_seed(seed, err);
        const std::string encoded = pm::encryption::encode_base64(key.public_key());
        pm::encryption::PublicKey decoded{};
        const bool ok = pm::encryption::decode_base64(encoded, decoded, err);
        check(ok && decoded == key.public_key(), "strict public-key base64 round trip",
              err.message);
    }

    const bool ok = failed == 0;
    std::cout << json{
                     {"ok", ok},
                     {"schema", "pm.encryption.selftest.v1"},
                     {"passed", passed},
                     {"failed", failed},
                     {"failures", failures},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
}

int run_roundtrip(const std::string& input) {
    Error err;
    auto pair = deterministic_pair("/v1/chat/completions|cli-roundtrip", test_session(), err);
    if (err) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    std::vector<std::uint8_t> frame;
    err = pair.initiator.seal(bytes(input), "application/json", frame);
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
    std::cout << json{
                     {"ok", true},
                     {"schema", "pm.encryption.roundtrip.v1"},
                     {"plaintext_bytes", input.size()},
                     {"frame_bytes", frame.size()},
                     {"match", text(opened) == input},
                 }
                     .dump()
              << "\n";
    return text(opened) == input ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"PolyMech encryption protocol test CLI"};
    app.require_subcommand(1);
    auto* capabilities = app.add_subcommand("capabilities", "Print compiled protocol support");
    auto* selftest = app.add_subcommand("selftest", "Run deterministic E2EE protocol checks");
    auto* scenario = app.add_subcommand("scenario", "Run a named deterministic scenario");
    std::string scenario_name;
    scenario->add_option("name", scenario_name)->required();
    auto* roundtrip = app.add_subcommand("roundtrip", "Round-trip one in-memory chat payload");
    std::string roundtrip_text;
    roundtrip->add_option("--text", roundtrip_text)->required();
    auto* server = app.add_subcommand("server", "Run the standalone encrypted HTTP/SSE harness");
    std::string server_host = "127.0.0.1";
    int server_port = 0;
    bool server_once = false;
    server->add_option("--host", server_host);
    server->add_option("--port", server_port);
    server->add_flag("--once", server_once, "Stop after one completed encrypted chat");
    auto* client = app.add_subcommand("client", "Call the standalone encrypted HTTP/SSE harness");
    std::string client_url;
    std::string client_prompt;
    bool client_tamper = false;
    client->add_option("--url", client_url)->required();
    client->add_option("--text", client_prompt)->required();
    client->add_flag("--tamper", client_tamper, "Modify ciphertext; success means rejection");

    CLI11_PARSE(app, argc, argv);

    if (*capabilities) {
        std::cout << json{
                         {"ok", true},
                         {"schema", "pm.encryption.capabilities.v1"},
                         {"secure_channel_e2ee", true},
                         {"chat_http_sse_harness", true},
                         {"cipher", "XChaCha20-Poly1305"},
                         {"key_agreement", "libsodium-crypto_kx-X25519"},
                         {"frame", "PME2/v1"},
                         {"replay_window", 64},
                         {"libsignal", false},
                         {"openmls", false},
                     }
                         .dump()
                  << "\n";
        return 0;
    }
    if (*selftest)
        return run_selftest();
    if (*scenario) {
        if (scenario_name != "tanit-chat-wifi") {
            std::cout << json{{"ok", false}, {"code", "unknown_scenario"},
                              {"error", "known scenario: tanit-chat-wifi"}}
                             .dump()
                      << "\n";
            return 1;
        }
        return run_selftest();
    }
    if (*roundtrip)
        return run_roundtrip(roundtrip_text);
    if (*server)
        return pm::encryption::cli::run_http_server(server_host, server_port, server_once);
    if (*client)
        return pm::encryption::cli::run_http_client(client_url, client_prompt, client_tamper);
    return 2;
}
