#include "checks.hpp"
#include "commands.hpp"

#include "pm/encryption/features.hpp"
#include "pm/encryption/policy.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

namespace pm::encryption::cli {
namespace {

nlohmann::json policy_row(PolicyId id, const char* level, const char* scope) {
    return {
        {"id", policy_id_name(id)},
        {"enabled", policy_enabled(id)},
        {"level", level},
        {"scope", scope},
    };
}

int finish(const char* policy, Check& check, LogSink& log) {
    const bool ok = check.failed == 0;
    log_info(log, "policy", ok ? std::string(policy) + " passed"
                               : std::string(policy) + " failed");
    std::cout << nlohmann::json{{"ok", ok},
                                {"schema", "pm.encryption.policy.v1"},
                                {"policy", policy},
                                {"passed", check.passed},
                                {"failed", check.failed},
                                {"failures", check.failures}}
                     .dump()
              << "\n";
    return ok ? 0 : 1;
}

int disabled(const char* policy, std::string message, LogSink& log) {
    log_warn(log, "policy", message);
    std::cout << nlohmann::json{{"ok", false},
                                {"schema", "pm.encryption.policy.v1"},
                                {"policy", policy},
                                {"code", "feature_disabled"},
                                {"error", std::move(message)}}
                     .dump()
              << "\n";
    return 1;
}

} // namespace

int run_policy(const std::string& name, LogSink& log) {
    if (name == "list") {
        std::cout << nlohmann::json{
                         {"ok", true},
                         {"schema", "pm.encryption.policy.v1"},
                         {"policies", nlohmann::json::array({
                             policy_row(PolicyId::LiveSession, "low",
                                        "online pinned channel, one key for the process"),
                             policy_row(PolicyId::UnauthenticatedKx, "low",
                                        "online channel without a device identity"),
                             policy_row(PolicyId::Signal, "session",
                                        "offline one-to-one ratchet"),
                             policy_row(PolicyId::Mls, "session",
                                        "group membership and epochs"),
                         })},
                     }
                         .dump()
                  << "\n";
        return 0;
    }
    if (name == "live") {
        if (!policy_enabled(PolicyId::LiveSession))
            return disabled(name.c_str(), "live session policy is not compiled", log);
#if PM_ENCRYPTION_LIVE_SESSION
        Check check;
        run_handshake_checks(check);
        return finish("live_session", check, log);
#else
        return disabled(name.c_str(), "live session policy is not compiled", log);
#endif
    }
    if (name == "unauthenticated-kx") {
        if (!policy_enabled(PolicyId::UnauthenticatedKx))
            return disabled(name.c_str(), "unauthenticated key agreement is not compiled", log);
        Check check;
        if (run_channel_checks(check) != 0)
            return 1;
        return finish("unauthenticated_kx", check, log);
    }
    if (name == "signal") {
        if (!policy_enabled(PolicyId::Signal))
            return disabled("signal", "signal session policy is not compiled", log);
        return run_signal_room("signal-room", log);
    }
    if (name == "mls") {
        if (!policy_enabled(PolicyId::Mls))
            return disabled("mls", "mls session policy is not compiled", log);
        return disabled("mls", "mls session policy has no isolated suite yet", log);
    }
    log_warn(log, "policy", "unknown policy");
    std::cout << nlohmann::json{{"ok", false},
                                {"schema", "pm.encryption.policy.v1"},
                                {"code", "unknown_policy"},
                                {"error", "known policies: list, live, unauthenticated-kx, signal, mls"}}
                     .dump()
              << "\n";
    return 1;
}

} // namespace pm::encryption::cli
