#include "checks.hpp"
#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"

#include <iostream>
#include <string>

namespace pm::encryption::cli {

int run_selftest(LogSink& log) {
    Check check;
    if (run_channel_checks(check) != 0)
        return 1;
#if PM_ENCRYPTION_LIVE_SESSION
    run_handshake_checks(check);
#endif
    const bool ok = check.failed == 0;
    log_info(log, "selftest",
             ok ? "passed" : ("failed=" + std::to_string(check.failed)));
    std::cout << nlohmann::json{{"ok", ok},
                                {"schema", "pm.encryption.selftest.v1"},
                                {"passed", check.passed},
                                {"failed", check.failed},
                                {"failures", check.failures}}
                     .dump()
              << "\n";
    return ok ? 0 : 1;
}

} // namespace pm::encryption::cli
