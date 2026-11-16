#pragma once

#include "pm/encryption/log.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace pm::encryption::cli {

struct HttpAuth {
    bool enabled = false;
    std::array<std::uint8_t, 32> identity_seed{};
    std::array<std::uint8_t, 32> peer_public{};
};

int run_http_server(const std::string& host, int port, bool once, const HttpAuth& auth,
                   LogSink& log);
int run_http_client(const std::string& base_url, const std::string& prompt, bool tamper,
                    const HttpAuth& auth, LogSink& log);

} // namespace pm::encryption::cli
