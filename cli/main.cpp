#include "commands.hpp"
#include "stderr_log.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    CLI::App app{"PolyMech encryption protocol test CLI"};
    app.require_subcommand(1);
    std::string log_level = "info";
    app.add_option("--log-level", log_level, "trace, debug, info, warn, error, or off");

    auto* capabilities = app.add_subcommand("capabilities", "Print compiled protocol support");
    auto* selftest = app.add_subcommand("selftest", "Run deterministic E2EE protocol checks");
    auto* scenario = app.add_subcommand("scenario", "Run a named deterministic scenario");
    std::string scenario_name;
    scenario->add_option("name", scenario_name)->required();
    auto* identity = app.add_subcommand("identity", "Print the public key for an identity seed");
    std::string identity_seed;
    identity->add_option("--seed", identity_seed, "64 hex characters")->required();
    auto* roundtrip = app.add_subcommand("roundtrip", "Round-trip one in-memory payload");
    std::string roundtrip_text;
    roundtrip->add_option("--text", roundtrip_text)->required();

    auto* server = app.add_subcommand("server", "Run the standalone encrypted HTTP/SSE harness");
    std::string server_host = "127.0.0.1";
    int server_port = 0;
    bool server_once = false;
    bool server_authenticated = false;
    std::string server_seed;
    std::string server_peer;
    server->add_option("--host", server_host);
    server->add_option("--port", server_port);
    server->add_flag("--once", server_once, "Stop after one completed encrypted chat");
    server->add_flag("--authenticated", server_authenticated, "Require a pinned identity handshake");
    server->add_option("--identity-seed", server_seed, "64 hex characters");
    server->add_option("--peer-key", server_peer, "Pinned peer identity, base64");

    auto* client = app.add_subcommand("client", "Call the standalone encrypted HTTP/SSE harness");
    std::string client_url;
    std::string client_prompt;
    bool client_tamper = false;
    bool client_authenticated = false;
    std::string client_seed;
    std::string client_peer;
    client->add_option("--url", client_url)->required();
    client->add_option("--text", client_prompt)->required();
    client->add_flag("--tamper", client_tamper, "Modify ciphertext; success means rejection");
    client->add_flag("--authenticated", client_authenticated, "Require a pinned identity handshake");
    client->add_option("--identity-seed", client_seed, "64 hex characters");
    client->add_option("--peer-key", client_peer, "Pinned peer identity, base64");

    CLI11_PARSE(app, argc, argv);

    pm::encryption::LogLevel level = pm::encryption::LogLevel::Info;
    if (!pm::encryption::cli::parse_log_level(log_level, level)) {
        std::cout << nlohmann::json{{"ok", false},
                                    {"code", "invalid_usage"},
                                    {"error", "log level must be trace, debug, info, warn, error, or off"}}
                         .dump()
                  << "\n";
        return 2;
    }
    pm::encryption::cli::StderrLog log(level);

    if (*capabilities)
        return pm::encryption::cli::run_capabilities();
    if (*selftest)
        return pm::encryption::cli::run_selftest(log);
    if (*scenario)
        return pm::encryption::cli::run_scenario(scenario_name, log);
    if (*identity)
        return pm::encryption::cli::run_identity(identity_seed);
    if (*roundtrip)
        return pm::encryption::cli::run_roundtrip(roundtrip_text);
    if (*server) {
        return pm::encryption::cli::run_http_command(
            true, server_host, server_port, server_once, {}, {}, false,
            server_authenticated, server_seed, server_peer, log);
    }
    if (*client) {
        return pm::encryption::cli::run_http_command(
            false, {}, 0, false, client_url, client_prompt, client_tamper,
            client_authenticated, client_seed, client_peer, log);
    }
    return 2;
}
