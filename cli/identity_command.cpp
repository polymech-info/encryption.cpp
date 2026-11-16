#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/identity.hpp"

#include <iostream>

namespace pm::encryption::cli {

int run_identity(const std::string& seed_hex) {
    Seed seed{};
    if (!parse_seed_hex(seed_hex, seed)) {
        std::cout << nlohmann::json{{"ok", false},
                                    {"code", "invalid_argument"},
                                    {"error", "identity seed must be 64 hex characters"}}
                         .dump()
                  << "\n";
        return 1;
    }
    Error err;
    auto key = Identity::from_seed(seed, err);
    if (err) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    std::cout << nlohmann::json{{"ok", true},
                                {"schema", "pm.encryption.identity.v1"},
                                {"public_key", encode_base64(key.public_key())}}
                     .dump()
              << "\n";
    return 0;
}

} // namespace pm::encryption::cli
