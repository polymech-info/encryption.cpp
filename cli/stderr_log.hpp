#pragma once

#include "pm/encryption/log.hpp"

#include <string_view>

namespace pm::encryption::cli {

class StderrLog final : public LogSink {
public:
    explicit StderrLog(LogLevel floor = LogLevel::Info);

    bool enabled(LogLevel level) const override;
    void write(LogLevel level, std::string_view channel, std::string_view message) override;

private:
    LogLevel floor_;
};

bool parse_log_level(std::string_view text, LogLevel& out);

} // namespace pm::encryption::cli
