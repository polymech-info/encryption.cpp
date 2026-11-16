#include "commands.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

namespace pm::encryption::cli {

int run_scenario(const std::string& name, LogSink& log) {
    if (name != "tanit-chat-wifi") {
        log_warn(log, "scenario", "unknown scenario");
        std::cout << nlohmann::json{{"ok", false},
                                    {"code", "unknown_scenario"},
                                    {"error", "known scenario: tanit-chat-wifi"}}
                         .dump()
                  << "\n";
        return 1;
    }
    return run_selftest(log);
}

} // namespace pm::encryption::cli
