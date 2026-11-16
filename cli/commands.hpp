#pragma once

#include "pm/encryption/log.hpp"

#include <string>

namespace pm::encryption::cli {

int run_capabilities();
int run_selftest(LogSink& log);
int run_scenario(const std::string& name, LogSink& log);
int run_identity(const std::string& seed_hex);
int run_roundtrip(const std::string& text);
int run_http_command(bool server, const std::string& host, int port, bool once,
                     const std::string& url, const std::string& prompt, bool tamper,
                     bool authenticated, const std::string& identity_seed,
                     const std::string& peer_key, LogSink& log);

} // namespace pm::encryption::cli
