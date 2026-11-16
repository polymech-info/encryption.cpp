#include "http_harness.hpp"

#include "pm/encryption/channel.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pm::encryption::cli {
namespace {

using json = nlohmann::json;
constexpr std::string_view k_context = "/v1/chat/completions|standalone-wifi-v1";
constexpr std::size_t k_max_wire = 64U * 1024U * 1024U;

json failure(std::string code, std::string message) {
    return {{"ok", false}, {"code", std::move(code)}, {"error", std::move(message)}};
}

struct Pending {
    KeyPair server_key;
    SessionId session_id{};
    std::chrono::steady_clock::time_point expires;
};

class ChallengeStore {
public:
    bool create(json& out, Error& err) {
        auto key = KeyPair::generate(err);
        if (err)
            return false;
        auto session_id = random_session_id(err);
        if (err)
            return false;
        const std::string id = encode_base64(session_id);
        const std::string public_key = encode_base64(key.public_key());
        {
            std::lock_guard lock(mu_);
            expire_locked();
            if (pending_.size() >= 128)
                pending_.erase(pending_.begin());
            pending_.emplace(id, Pending{
                std::move(key),
                session_id,
                std::chrono::steady_clock::now() + std::chrono::seconds(30),
            });
        }
        out = {
            {"ok", true},
            {"schema", "pm.e2ee.challenge.v1"},
            {"session_id", id},
            {"server_key", public_key},
            {"expires_in", 30},
            {"context", k_context},
        };
        return true;
    }

    std::optional<SecureChannel> consume(std::string_view encoded_session,
                                       std::string_view encoded_client_key,
                                       Error& err) {
        SessionId session_id{};
        PublicKey client_key{};
        if (!decode_base64(encoded_session, session_id, err)
            || !decode_base64(encoded_client_key, client_key, err))
            return std::nullopt;

        KeyPair server_key;
        {
            std::lock_guard lock(mu_);
            expire_locked();
            const auto it = pending_.find(std::string(encoded_session));
            if (it == pending_.end()) {
                err = Error::make(ErrorCode::Replay,
                                  "challenge is unknown, expired, or already consumed");
                return std::nullopt;
            }
            server_key = std::move(it->second.server_key);
            pending_.erase(it);
        }
        auto session = SecureChannel::responder(
            std::move(server_key), client_key, session_id, std::string(k_context), err);
        if (err)
            return std::nullopt;
        return session;
    }

private:
    void expire_locked() {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (now >= it->second.expires)
                it = pending_.erase(it);
            else
                ++it;
        }
    }

    std::mutex mu_;
    std::unordered_map<std::string, Pending> pending_;
};

struct HttpEndpoint {
    std::string host;
    int port = 0;
};

bool parse_http_url(std::string_view url, HttpEndpoint& out) {
    constexpr std::string_view prefix = "http://";
    if (!url.starts_with(prefix))
        return false;
    url.remove_prefix(prefix.size());
    const auto slash = url.find('/');
    if (slash != std::string_view::npos)
        url = url.substr(0, slash);
    const auto colon = url.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= url.size())
        return false;
    out.host = std::string(url.substr(0, colon));
    try {
        out.port = std::stoi(std::string(url.substr(colon + 1)));
    } catch (...) {
        return false;
    }
    return out.port > 0 && out.port <= 65535;
}

std::string outer_sse_frame(SecureChannel& session, std::string_view inner, Error& err) {
    std::vector<std::uint8_t> frame;
    err = session.seal(
        {reinterpret_cast<const std::uint8_t*>(inner.data()), inner.size()},
        "text/event-stream", frame, 1024U * 1024U);
    if (err)
        return {};
    return "event: e2ee.frame\ndata: "
        + json{{"frame", encode_base64(frame)}}.dump() + "\n\n";
}

std::string data_line(const json& body) {
    return "data: " + body.dump() + "\n\n";
}

class StreamDecoder {
public:
    explicit StreamDecoder(SecureChannel& session) : session_(session) {}

    bool feed(const char* bytes, std::size_t size, Error& err) {
        buffer_.append(bytes, size);
        if (buffer_.size() > 4U * 1024U * 1024U) {
            err = Error::make(ErrorCode::FrameTooLarge, "outer SSE buffer exceeded its limit");
            return false;
        }
        for (;;) {
            const auto end = buffer_.find("\n\n");
            if (end == std::string::npos)
                return true;
            const std::string event = buffer_.substr(0, end);
            buffer_.erase(0, end + 2);
            if (!consume_event(event, err))
                return false;
        }
    }

    bool done() const noexcept { return done_; }
    const std::string& assistant_text() const noexcept { return assistant_text_; }
    std::size_t encrypted_frames() const noexcept { return encrypted_frames_; }

private:
    bool consume_event(const std::string& event, Error& err) {
        const auto marker = event.find("\ndata: ");
        if (!event.starts_with("event: e2ee.frame") || marker == std::string::npos) {
            err = Error::make(ErrorCode::InvalidFrame, "unexpected outer SSE event");
            return false;
        }
        json wrapper;
        try {
            wrapper = json::parse(event.substr(marker + 7));
        } catch (const std::exception& e) {
            err = Error::make(ErrorCode::InvalidFrame,
                              std::string("outer SSE JSON is invalid: ") + e.what());
            return false;
        }
        std::vector<std::uint8_t> frame;
        if (!decode_base64(wrapper.value("frame", std::string{}), frame,
                           1024U * 1024U, err))
            return false;
        std::vector<std::uint8_t> plain;
        err = session_.open(frame, "text/event-stream", plain, 1024U * 1024U);
        if (err)
            return false;
        ++encrypted_frames_;
        const std::string inner(plain.begin(), plain.end());
        if (!inner.starts_with("data: ") || !inner.ends_with("\n\n")) {
            err = Error::make(ErrorCode::InvalidFrame, "inner SSE frame is malformed");
            return false;
        }
        const std::string payload = inner.substr(6, inner.size() - 8);
        if (payload == "[DONE]") {
            done_ = true;
            return true;
        }
        json chunk;
        try {
            chunk = json::parse(payload);
        } catch (const std::exception& e) {
            err = Error::make(ErrorCode::InvalidFrame,
                              std::string("inner SSE JSON is invalid: ") + e.what());
            return false;
        }
        if (chunk.contains("choices") && chunk["choices"].is_array()
            && !chunk["choices"].empty()) {
            assistant_text_ +=
                chunk["choices"][0].value("delta", json::object()).value("content", std::string{});
        }
        return true;
    }

    SecureChannel& session_;
    std::string buffer_;
    std::string assistant_text_;
    std::size_t encrypted_frames_ = 0;
    bool done_ = false;
};

} // namespace

int run_http_server(const std::string& host, int port, bool once) {
    httplib::Server server;
    ChallengeStore challenges;

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(json{{"ok", true}, {"ready", true},
                             {"schema", "pm.encryption.http-harness.v1"}}
                            .dump(),
                        "application/json");
    });

    server.Post("/v1/e2ee/session",
                [&challenges](const httplib::Request&, httplib::Response& res) {
        Error err;
        json body;
        if (!challenges.create(body, err)) {
            res.status = 500;
            res.set_content(failure(error_code_name(err.code), err.message).dump(),
                            "application/json");
            return;
        }
        res.set_content(body.dump(), "application/json");
    });

    server.Post("/v1/chat/completions",
                [&server, &challenges, once](const httplib::Request& req,
                                             httplib::Response& res) {
        json wrapper;
        try {
            wrapper = json::parse(req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(failure("invalid_json", e.what()).dump(), "application/json");
            return;
        }
        if (wrapper.value("schema", std::string{}) != "pm.e2ee.chat.request.v1") {
            res.status = 400;
            res.set_content(failure("invalid_schema", "encrypted request schema is required").dump(),
                            "application/json");
            return;
        }

        Error err;
        auto session = challenges.consume(
            wrapper.value("session_id", std::string{}),
            wrapper.value("client_key", std::string{}), err);
        if (!session) {
            res.status = err.code == ErrorCode::Replay ? 409 : 400;
            res.set_content(failure(error_code_name(err.code), err.message).dump(),
                            "application/json");
            return;
        }
        std::vector<std::uint8_t> frame;
        if (!decode_base64(wrapper.value("frame", std::string{}), frame, k_max_wire, err)) {
            res.status = 400;
            res.set_content(failure(error_code_name(err.code), err.message).dump(),
                            "application/json");
            return;
        }
        std::vector<std::uint8_t> plain;
        err = session->open(frame, "application/json", plain, k_max_wire);
        if (err) {
            res.status = 400;
            res.set_content(failure(error_code_name(err.code), err.message).dump(),
                            "application/json");
            return;
        }

        json request;
        try {
            request = json::parse(plain);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(failure("invalid_inner_json", e.what()).dump(), "application/json");
            return;
        }
        const std::size_t prompt_bytes =
            request.value("prompt", std::string{}).size();
        auto shared = std::make_shared<SecureChannel>(std::move(*session));
        res.set_header("Cache-Control", "no-cache");
        res.set_chunked_content_provider(
            "text/event-stream; charset=utf-8",
            [&server, shared, prompt_bytes, once](std::size_t, httplib::DataSink& sink) mutable {
                Error seal_err;
                const std::vector<std::string> inner{
                    data_line({{"choices", json::array(
                        {{{"delta", {{"content", "ack"}}}}})}}),
                    data_line({{"choices", json::array(
                        {{{"delta", {{"content", ":" + std::to_string(prompt_bytes)}}}}})}}),
                    "data: [DONE]\n\n",
                };
                for (const auto& event : inner) {
                    const std::string outer = outer_sse_frame(*shared, event, seal_err);
                    if (seal_err || !sink.write(outer.data(), outer.size())) {
                        sink.done();
                        if (once)
                            server.stop();
                        return false;
                    }
                }
                sink.done();
                if (once)
                    server.stop();
                return false;
            });
    });

    const int bound = port == 0
        ? server.bind_to_any_port(host)
        : (server.bind_to_port(host, port) ? port : -1);
    if (bound < 0) {
        std::cout << failure("bind_failed", "could not bind HTTP harness").dump() << std::endl;
        return 1;
    }
    std::thread listener([&server] { (void)server.listen_after_bind(); });
    server.wait_until_ready();
    std::cout << json{{"ok", true}, {"schema", "pm.encryption.server.v1"},
                      {"host", host}, {"port", bound}, {"e2ee", true},
                      {"authenticated_peer", false}}
                     .dump()
              << std::endl;
    listener.join();
    return 0;
}

int run_http_client(const std::string& base_url, const std::string& prompt, bool tamper) {
    HttpEndpoint endpoint;
    if (!parse_http_url(base_url, endpoint)) {
        std::cout << failure("invalid_url", "use http://host:port").dump() << "\n";
        return 1;
    }
    httplib::Client client(endpoint.host, endpoint.port);
    client.set_connection_timeout(2, 0);
    client.set_read_timeout(10, 0);
    client.set_write_timeout(10, 0);

    const auto challenge_response = client.Post("/v1/e2ee/session", "", "application/json");
    if (!challenge_response || challenge_response->status != 200) {
        std::cout << failure("challenge_failed", "could not obtain an E2EE challenge").dump()
                  << "\n";
        return 1;
    }
    json challenge;
    try {
        challenge = json::parse(challenge_response->body);
    } catch (const std::exception& e) {
        std::cout << failure("challenge_invalid", e.what()).dump() << "\n";
        return 1;
    }

    Error err;
    SessionId session_id{};
    PublicKey server_public{};
    if (!decode_base64(challenge.value("session_id", std::string{}), session_id, err)
        || !decode_base64(challenge.value("server_key", std::string{}), server_public, err)) {
        std::cout << failure(error_code_name(err.code), err.message).dump() << "\n";
        return 1;
    }
    auto client_key = KeyPair::generate(err);
    if (err) {
        std::cout << failure(error_code_name(err.code), err.message).dump() << "\n";
        return 1;
    }
    const auto client_public = client_key.public_key();
    auto session = SecureChannel::initiator(
        std::move(client_key), server_public, session_id, std::string(k_context), err);
    if (err) {
        std::cout << failure(error_code_name(err.code), err.message).dump() << "\n";
        return 1;
    }

    std::string inner;
    try {
        inner = json{
            {"model", "text-fast"},
            {"stream", true},
            {"prompt", prompt},
        }.dump();
    } catch (const std::exception& e) {
        std::cout << failure("invalid_utf8", e.what()).dump() << "\n";
        return 1;
    }
    std::vector<std::uint8_t> frame;
    err = session.seal(
        {reinterpret_cast<const std::uint8_t*>(inner.data()), inner.size()},
        "application/json", frame, k_max_wire);
    if (err) {
        std::cout << failure(error_code_name(err.code), err.message).dump() << "\n";
        return 1;
    }
    if (tamper && !frame.empty())
        frame.back() ^= 0x01;

    const std::string body = json{
        {"schema", "pm.e2ee.chat.request.v1"},
        {"session_id", encode_base64(session_id)},
        {"client_key", encode_base64(client_public)},
        {"frame", encode_base64(frame)},
    }.dump();

    StreamDecoder decoder(session);
    std::size_t receive_callbacks = 0;
    httplib::Request request;
    request.method = "POST";
    request.path = "/v1/chat/completions";
    request.body = body;
    request.set_header("Content-Type", "application/json");
    request.content_receiver = [&](const char* data, std::size_t size,
                                   std::uint64_t, std::uint64_t) {
            ++receive_callbacks;
            return decoder.feed(data, size, err);
        };
    const auto result = client.send(request);
    if (!result) {
        std::cout << failure(err ? error_code_name(err.code) : "http_failed",
                             err ? err.message : "HTTP request failed")
                         .dump()
                  << "\n";
        return 1;
    }
    if (tamper) {
        const bool rejected = result->status == 400;
        std::cout << json{{"ok", rejected}, {"schema", "pm.encryption.client.v1"},
                          {"tamper_rejected", rejected}, {"http_status", result->status}}
                         .dump()
                  << "\n";
        return rejected ? 0 : 1;
    }
    const bool ok = result->status == 200 && !err && decoder.done()
        && decoder.assistant_text() == "ack:" + std::to_string(prompt.size());
    std::cout << json{
                     {"ok", ok},
                     {"schema", "pm.encryption.client.v1"},
                     {"http_status", result->status},
                     {"encrypted_frames", decoder.encrypted_frames()},
                     {"receive_callbacks", receive_callbacks},
                     {"done", decoder.done()},
                     {"assistant", decoder.assistant_text()},
                     {"request_plaintext_bytes", inner.size()},
                     {"request_frame_bytes", frame.size()},
                 }
                     .dump()
              << "\n";
    return ok ? 0 : 1;
}

} // namespace pm::encryption::cli
