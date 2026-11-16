#include "support.hpp"

namespace pm::encryption::cli {

std::vector<std::uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

std::string text_of(const std::vector<std::uint8_t>& value) {
    return {value.begin(), value.end()};
}

nlohmann::json error_json(const Error& err) {
    return {
        {"ok", false},
        {"code", error_code_name(err.code)},
        {"error", err.message},
    };
}

bool parse_seed_hex(std::string_view hex, Seed& out) {
    if (hex.size() != out.size() * 2)
        return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

SessionId test_session(std::uint8_t suffix) {
    SessionId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(0xa0U + i);
    id.back() ^= suffix;
    return id;
}

} // namespace pm::encryption::cli
