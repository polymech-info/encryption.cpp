#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#if PM_ENCRYPTION_HTTP_HARNESS
#include "http_harness.hpp"
#endif

namespace pm::encryption::cli {

int run_http_command(bool server, const std::string& host, int port, bool once,
                     const std::string& url, const std::string& prompt, bool tamper,
                     bool authenticated, const std::string& identity_seed,
                     const std::string& peer_key, LogSink& log) {
#if !PM_ENCRYPTION_HTTP_HARNESS
    (void)server;
    (void)host;
    (void)port;
    (void)once;
    (void)url;
    (void)prompt;
    (void)tamper;
    (void)authenticated;
    (void)identity_seed;
    (void)peer_key;
    log_warn(log, "http", "http harness is not compiled");
    std::cout << nlohmann::json{{"ok", false},
                                {"code", "http_harness_disabled"},
                                {"error", "pm-encryption was built without the HTTP harness"}}
                     .dump()
              << "\n";
    return 1;
#else
    HttpAuth auth;
    if (authenticated || !identity_seed.empty() || !peer_key.empty()) {
        if (!authenticated || identity_seed.empty() || peer_key.empty()) {
            log_warn(log, "http", "authenticated mode is missing a seed or peer key");
            std::cout << nlohmann::json{
                             {"ok", false},
                             {"code", "invalid_usage"},
                             {"error", "--authenticated requires --identity-seed and --peer-key"}}
                             .dump()
                      << "\n";
            return 2;
        }
        if (!parse_seed_hex(identity_seed, auth.identity_seed)) {
            std::cout << nlohmann::json{{"ok", false},
                                        {"code", "invalid_argument"},
                                        {"error", "identity seed must be 64 hex characters"}}
                             .dump()
                      << "\n";
            return 2;
        }
        Error err;
        if (!decode_base64(peer_key, auth.peer_public, err)) {
            std::cout << error_json(err).dump() << "\n";
            return 2;
        }
        auth.enabled = true;
    }
    if (server)
        return run_http_server(host, port, once, auth, log);
    return run_http_client(url, prompt, tamper, auth, log);
#endif
}

} // namespace pm::encryption::cli
