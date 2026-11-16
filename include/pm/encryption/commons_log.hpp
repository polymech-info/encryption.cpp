#pragma once

// Host adapter. Include this only from a translation unit whose include path
// provides commons logging/pm_log.hpp. The standalone encryption build does
// not compile this header.

#include "pm/encryption/log.hpp"

#include "logging/pm_log.hpp"

#include <string>

namespace pm::encryption {

class CommonsLog final : public LogSink {
public:
    bool enabled(LogLevel level) const override {
        switch (level) {
        case LogLevel::Trace: return logger::trace_enabled();
        case LogLevel::Debug: return logger::debug_enabled();
        case LogLevel::Info:
        case LogLevel::Warn:
        case LogLevel::Error: return true;
        case LogLevel::Off: return false;
        }
        return false;
    }

    void write(LogLevel level, std::string_view channel, std::string_view message) override {
        const std::string text(message);
        switch (level) {
        case LogLevel::Trace:
            pm::log::trace_lazy(channel, [&] { return text; });
            break;
        case LogLevel::Debug:
            pm::log::debug(channel, text);
            break;
        case LogLevel::Info:
            pm::log::info(channel, text);
            break;
        case LogLevel::Warn:
            pm::log::warn(channel, text);
            break;
        case LogLevel::Error:
            pm::log::error(channel, text);
            break;
        case LogLevel::Off:
            break;
        }
    }
};

} // namespace pm::encryption
