#pragma once

#include "pm/encryption/channel.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pm::encryption::cli {

struct Check {
    int passed = 0;
    int failed = 0;
    nlohmann::json failures = nlohmann::json::array();

    void operator()(bool condition, std::string name, std::string detail = {}) {
        if (condition) {
            ++passed;
        } else {
            ++failed;
            failures.push_back({{"name", std::move(name)}, {"detail", std::move(detail)}});
        }
    }
};

std::vector<std::uint8_t> bytes_of(std::string_view text);
std::string text_of(const std::vector<std::uint8_t>& value);
nlohmann::json error_json(const Error& err);
bool parse_seed_hex(std::string_view hex, Seed& out);
SessionId test_session(std::uint8_t suffix = 0);

} // namespace pm::encryption::cli
