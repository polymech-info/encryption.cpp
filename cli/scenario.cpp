#include "commands.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

namespace pm::encryption::cli {

int run_scenario(const std::string& name, LogSink& log) {
    if (name == "group-file")
        return run_group_file_scenario(log);
    if (name != "tanit-chat-wifi") {
        log_warn(log, "scenario", "unknown scenario");
        std::cout << nlohmann::json{{"ok", false},
                                    {"code", "unknown_scenario"},
                                    {"error", "known scenarios: tanit-chat-wifi, group-file"}}
                         .dump()
                  << "\n";
        return 1;
    }
    return run_selftest(log);
}

} // namespace pm::encryption::cli
