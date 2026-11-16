#pragma once

#include <string_view>

namespace pm::encryption {

/**
 * Host-supplied diagnostic sink.
 *
 * Levels use the same order as pm::log: trace, debug, info, warn, error.
 * The library never owns a process-global logger. A host forwards write() to
 * pm::log (see commons_log.hpp) or any other sink. Messages must stay free of
 * keys, seeds, plaintext, and frame bytes; callers pass error codes and modes.
 */
enum class LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Off = 5,
};

class LogSink {
public:
    virtual ~LogSink() = default;
    virtual bool enabled(LogLevel level) const = 0;
    virtual void write(LogLevel level, std::string_view channel, std::string_view message) = 0;
};

class NullLog final : public LogSink {
public:
    bool enabled(LogLevel) const override { return false; }
    void write(LogLevel, std::string_view, std::string_view) override {}
};

inline void log_at(LogSink& sink, LogLevel level, std::string_view channel,
                   std::string_view message) {
    if (sink.enabled(level))
        sink.write(level, channel, message);
}

inline void log_info(LogSink& sink, std::string_view channel, std::string_view message) {
    log_at(sink, LogLevel::Info, channel, message);
}

inline void log_warn(LogSink& sink, std::string_view channel, std::string_view message) {
    log_at(sink, LogLevel::Warn, channel, message);
}

inline void log_error(LogSink& sink, std::string_view channel, std::string_view message) {
    log_at(sink, LogLevel::Error, channel, message);
}

} // namespace pm::encryption
