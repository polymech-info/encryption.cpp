#include "stderr_log.hpp"

#include <iostream>

namespace pm::encryption::cli {
namespace {

int rank(LogLevel level) {
    return static_cast<int>(level);
}

const char* level_name(LogLevel level) {
    switch (level) {
    case LogLevel::Trace: return "trace";
    case LogLevel::Debug: return "debug";
    case LogLevel::Info: return "info";
    case LogLevel::Warn: return "warn";
    case LogLevel::Error: return "error";
    case LogLevel::Off: return "off";
    }
    return "info";
}

} // namespace

StderrLog::StderrLog(LogLevel floor) : floor_(floor) {}

bool StderrLog::enabled(LogLevel level) const {
    return rank(level) >= rank(floor_);
}

void StderrLog::write(LogLevel level, std::string_view channel, std::string_view message) {
    if (!enabled(level))
        return;
    std::cerr << "[" << level_name(level) << "] [" << channel << "] " << message << "\n";
}

bool parse_log_level(std::string_view text, LogLevel& out) {
    if (text == "trace")
        out = LogLevel::Trace;
    else if (text == "debug")
        out = LogLevel::Debug;
    else if (text == "info")
        out = LogLevel::Info;
    else if (text == "warn" || text == "warning")
        out = LogLevel::Warn;
    else if (text == "error" || text == "err")
        out = LogLevel::Error;
    else if (text == "off" || text == "none")
        out = LogLevel::Off;
    else
        return false;
    return true;
}

} // namespace pm::encryption::cli
