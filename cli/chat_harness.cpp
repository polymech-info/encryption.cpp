#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#if PM_ENCRYPTION_HTTP_HARNESS && PM_ENCRYPTION_LIVE_SESSION
#include "pm/encryption/handshake.hpp"

#include <httplib.h>

#include <future>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>
#endif

namespace pm::encryption::cli {
namespace {

constexpr const char* k_schema = "pm.encryption.chat-harness.v1";

nlohmann::json harness_failure(const char* code, std::string error) {
    return {{"ok", false}, {"schema", k_schema}, {"code", code}, {"error", std::move(error)}};
}

#if PM_ENCRYPTION_HTTP_HARNESS && PM_ENCRYPTION_LIVE_SESSION

constexpr std::size_t k_frame_cap = 16U * 1024U;
constexpr std::string_view k_context = "tanit-chat-desktop|loopback-v1";

bool loopback_host(std::string_view host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

std::string bind_host_of(std::string_view host) {
    if (host == "localhost")
        return "127.0.0.1";
    return std::string(host);
}

Identity keyed(std::uint8_t tag, Error& err) {
    Seed seed{};
    seed.fill(tag);
    return Identity::from_seed(seed, err);
}

#endif

} // namespace

int run_chat_harness(const std::string& host, const std::string& text, LogSink& log) {
#if !PM_ENCRYPTION_HTTP_HARNESS || !PM_ENCRYPTION_LIVE_SESSION
    (void)host;
    (void)text;
    log_warn(log, "chat-harness", "desktop chat harness is not compiled");
    std::cout << harness_failure("feature_disabled",
                                 "chat-harness needs the live session and the HTTP harness")
                     .dump()
              << "\n";
    return 1;
#else
    if (!loopback_host(host)) {
        log_warn(log, "chat-harness", "refusing a non-loopback host");
        std::cout << harness_failure("not_loopback",
                                     "chat-harness binds 127.0.0.1, localhost, or ::1")
                         .dump()
                  << "\n";
        return 2;
    }
    if (text.empty()) {
        std::cout << harness_failure("invalid_argument", "chat text is empty").dump() << "\n";
        return 2;
    }
    if (text.size() > k_frame_cap) {
        log_warn(log, "chat-harness", "chat text exceeds the frame cap");
        std::cout << harness_failure("plaintext_too_large", "chat frame cap is 16384 bytes").dump()
                  << "\n";
        return 1;
    }

    Error err;
    auto alice = keyed(0xA1, err);
    auto bob = keyed(0xB2, err);
    if (err || !alice.valid() || !bob.valid()) {
        std::cout << harness_failure("crypto_unavailable", err.message).dump() << "\n";
        return 1;
    }
    const auto alice_public = alice.public_key();
    const auto bob_public = bob.public_key();
    auto responder = Handshake::responder(std::move(bob), alice_public, std::string(k_context), err);
    if (err) {
        std::cout << harness_failure(error_code_name(err.code), err.message).dump() << "\n";
        return 1;
    }

    struct State {
        std::mutex mu;
        Handshake handshake;
        std::optional<SecureChannel> channel;
        bool failed = false;
    };
    auto state = std::make_shared<State>();
    state->handshake = std::move(responder);

    httplib::Server server;
    server.Post("/v1/e2ee/session", [](const httplib::Request&, httplib::Response& res) {
        res.status = 400;
        res.set_content(harness_failure("authenticated_mode",
                                        "the desktop harness has no unauthenticated exchange")
                            .dump(),
                        "application/json");
    });
    server.Post("/v1/e2ee/handshake", [state, &log](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json wrapper;
        try {
            wrapper = nlohmann::json::parse(req.body);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(harness_failure("invalid_json", "handshake body is not json").dump(),
                            "application/json");
            return;
        }
        Error handshake_err;
        std::vector<std::uint8_t> incoming;
        if (!decode_base64(wrapper.value("message", std::string{}), incoming, 4096, handshake_err)) {
            res.status = 400;
            res.set_content(harness_failure(error_code_name(handshake_err.code), handshake_err.message).dump(),
                            "application/json");
            return;
        }
        std::vector<std::uint8_t> reply;
        bool complete = false;
        {
            std::lock_guard lock(state->mu);
            if (state->failed || state->channel) {
                res.status = 409;
                res.set_content(harness_failure("unexpected_state", "handshake is already finished").dump(),
                                "application/json");
                return;
            }
            handshake_err = state->handshake.read_message(incoming);
            if (!handshake_err && !state->handshake.complete())
                handshake_err = state->handshake.write_message(reply);
            if (!handshake_err && state->handshake.complete()) {
                auto channel = state->handshake.take_channel(handshake_err);
                if (!handshake_err)
                    state->channel = std::move(channel);
            }
            if (handshake_err) {
                state->failed = true;
                log_warn(log, "chat-harness", error_code_name(handshake_err.code));
                res.status = 400;
                res.set_content(
                    harness_failure(error_code_name(handshake_err.code), handshake_err.message).dump(),
                    "application/json");
                return;
            }
            complete = state->channel.has_value();
        }
        res.set_content(nlohmann::json{{"ok", true},
                                       {"schema", "pm.e2ee.handshake.reply.v1"},
                                       {"complete", complete},
                                       {"message", reply.empty() ? std::string{} : encode_base64(reply)}}
                            .dump(),
                        "application/json");
    });
    server.Post("/v1/chat/completions", [state](const httplib::Request& req, httplib::Response& res) {
        std::shared_ptr<SecureChannel> session;
        {
            std::lock_guard lock(state->mu);
            if (!state->channel) {
                res.status = 409;
                res.set_content(harness_failure("handshake_required",
                                                "chat requires both sides to have finished message 3")
                                    .dump(),
                                "application/json");
                return;
            }
            session = std::make_shared<SecureChannel>(std::move(*state->channel));
            state->channel.reset();
        }
        nlohmann::json wrapper;
        try {
            wrapper = nlohmann::json::parse(req.body);
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(harness_failure("invalid_json", "chat body is not json").dump(),
                            "application/json");
            return;
        }
        Error open_err;
        std::vector<std::uint8_t> frame;
        if (!decode_base64(wrapper.value("frame", std::string{}), frame, k_frame_cap + 4096, open_err)) {
            res.status = 400;
            res.set_content(harness_failure(error_code_name(open_err.code), open_err.message).dump(),
                            "application/json");
            return;
        }
        std::vector<std::uint8_t> plain;
        open_err = session->open(frame, "text/plain", plain, k_frame_cap);
        if (open_err) {
            res.status = 400;
            res.set_content(harness_failure(error_code_name(open_err.code), open_err.message).dump(),
                            "application/json");
            return;
        }
        const auto ack = std::to_string(plain.size());
        std::vector<std::uint8_t> reply;
        open_err = session->seal({reinterpret_cast<const std::uint8_t*>(ack.data()), ack.size()},
                                 "text/plain", reply, k_frame_cap);
        if (open_err) {
            res.status = 400;
            res.set_content(harness_failure(error_code_name(open_err.code), open_err.message).dump(),
                            "application/json");
            return;
        }
        res.set_content(nlohmann::json{{"ok", true},
                                       {"schema", "pm.e2ee.chat.reply.v1"},
                                       {"frame", encode_base64(reply)}}
                            .dump(),
                        "application/json");
    });

    const std::string bound_host = bind_host_of(host);
    std::promise<int> bound_port;
    std::thread serve([&server, &bound_port, bound_host] {
        const int port = server.bind_to_any_port(bound_host);
        if (port < 0) {
            bound_port.set_value(-1);
            return;
        }
        std::thread listener([&server] { (void)server.listen_after_bind(); });
        server.wait_until_ready();
        bound_port.set_value(port);
        listener.join();
    });
    const int port = bound_port.get_future().get();
    if (port < 0) {
        serve.join();
        std::cout << harness_failure("bind_failed", "could not bind the loopback chat harness").dump()
                  << "\n";
        return 1;
    }

    httplib::Client client(bound_host, port);
    client.set_connection_timeout(2, 0);
    client.set_read_timeout(5, 0);
    client.set_write_timeout(5, 0);

    bool unauthenticated_rejected = false;
    if (const auto rejected = client.Post("/v1/e2ee/session", "{}", "application/json"))
        unauthenticated_rejected = rejected->status == 400;

    bool chat_before_handshake_rejected = false;
    if (const auto early = client.Post("/v1/chat/completions",
                                       nlohmann::json{{"frame", ""}}.dump(), "application/json"))
        chat_before_handshake_rejected = early->status == 409;

    auto initiator = Handshake::initiator(std::move(alice), bob_public, std::string(k_context), err);
    auto exchange = [&](const std::vector<std::uint8_t>& message, std::vector<std::uint8_t>& reply,
                        bool& complete) {
        reply.clear();
        complete = false;
        const auto response = client.Post(
            "/v1/e2ee/handshake",
            nlohmann::json{{"schema", "pm.e2ee.handshake.v1"}, {"message", encode_base64(message)}}.dump(),
            "application/json");
        if (!response || response->status != 200)
            return false;
        const auto body = nlohmann::json::parse(response->body);
        complete = body.value("complete", false);
        const std::string encoded = body.value("message", std::string{});
        if (!encoded.empty() && !decode_base64(encoded, reply, 4096, err))
            return false;
        return true;
    };

    std::vector<std::uint8_t> message;
    std::vector<std::uint8_t> reply;
    bool responder_complete = false;
    bool both_complete = false;
    bool reply_matches = false;
    try {
        const bool exchanged = !err && !initiator.write_message(message)
            && exchange(message, reply, responder_complete) && !responder_complete
            && !initiator.read_message(reply) && !initiator.write_message(message)
            && exchange(message, reply, responder_complete) && responder_complete;
        SecureChannel session;
        if (exchanged)
            session = initiator.take_channel(err);
        both_complete = exchanged && !err && session.valid();
        std::vector<std::uint8_t> frame;
        if (both_complete)
            err = session.seal({reinterpret_cast<const std::uint8_t*>(text.data()), text.size()},
                               "text/plain", frame, k_frame_cap);
        if (both_complete && !err) {
            const auto response = client.Post(
                "/v1/chat/completions",
                nlohmann::json{{"schema", "pm.e2ee.chat.request.v1"}, {"frame", encode_base64(frame)}}
                    .dump(),
                "application/json");
            if (response && response->status == 200) {
                const auto body = nlohmann::json::parse(response->body);
                std::vector<std::uint8_t> reply_frame;
                std::vector<std::uint8_t> ack;
                if (decode_base64(body.value("frame", std::string{}), reply_frame, k_frame_cap + 4096, err)
                    && !session.open(reply_frame, "text/plain", ack, k_frame_cap)) {
                    const std::string ack_text(ack.begin(), ack.end());
                    reply_matches = ack_text == std::to_string(text.size());
                }
            }
        }
    } catch (const std::exception&) {
        both_complete = false;
        reply_matches = false;
    }

    server.stop();
    serve.join();

    const bool ok = unauthenticated_rejected && chat_before_handshake_rejected && both_complete
        && reply_matches;
    log_info(log, "chat-harness", ok ? "passed" : "failed");
    std::cout << nlohmann::json{
                     {"ok", ok},
                     {"schema", k_schema},
                     {"host", bound_host},
                     {"port", port},
                     {"loopback", true},
                     {"broker", false},
                     {"pinned", true},
                     {"identity_hiding", false},
                     {"handshake", "pinned-online"},
                     {"wire_label", "sigma-i-v1"},
                     {"channel_key", "one-for-process"},
                     {"files", false},
                     {"frame_context", "transcript-hash"},
                     {"frame_cap_bytes", k_frame_cap},
                     {"unauthenticated_rejected", unauthenticated_rejected},
                     {"chat_before_handshake_rejected", chat_before_handshake_rejected},
                     {"both_complete_before_chat", both_complete},
                     {"reply_matches", reply_matches},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
#endif
}

} // namespace pm::encryption::cli
