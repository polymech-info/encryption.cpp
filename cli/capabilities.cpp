#include "commands.hpp"

#include "pm/encryption/channel.hpp"
#include "pm/encryption/features.hpp"
#include "pm/encryption/policy.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

namespace pm::encryption::cli {

int run_capabilities() {
    std::cout << nlohmann::json{
                     {"ok", true},
                     {"schema", "pm.encryption.capabilities.v1"},
                     {"secure_channel_e2ee", true},
                     {"authenticated_handshake", feature_authenticated_handshake},
                     {"handshake", "sigma-i-v1"},
                     {"handshake_property", "pinned-online"},
                     {"identity_hiding", false},
                     {"channel_key", "one-for-process"},
                     {"ratchet", k_channel_ratchet},
                     {"history", "out-of-channel"},
                     {"replay_window", k_replay_window},
                     {"replay_rule", "sequence-0-then-window-64"},
                     {"broker", false},
                     {"room_broker", "in-process-v1"},
                     {"pairing", "fingerprint-v1"},
                     {"tailnet", false},
                     {"chat_http_sse_harness", feature_http_harness},
                     {"cipher", "XChaCha20-Poly1305"},
                     {"key_agreement", "libsodium-crypto_kx-X25519"},
                     {"frame", "PME2/v1"},
                     {"file_transfer", "sealed-manifest-v1"},
                     {"datagram", "PMD1/v1"},
                     {"facade", "secure-flow"},
                     {"reliable_via_facade", false},
                     {"durable_via_facade", false},
                     {"media_transport", false},
                     {"media_loss", "gap-within-window-64"},
                     {"file_key", "separate-x25519"},
                     {"file_key_is_identity", false},
                     {"device_file_key", "signed-statement-v1"},
                     {"text_session", "pairwise-v1"},
                     {"removal_revokes_ciphertext", false},
                     {"libsignal", feature_libsignal},
                     {"openmls", feature_openmls},
                     {"policies", {
                         {"live_session", policy_enabled(PolicyId::LiveSession)},
                         {"unauthenticated_kx", policy_enabled(PolicyId::UnauthenticatedKx)},
                         {"signal", policy_enabled(PolicyId::Signal)},
                         {"mls", policy_enabled(PolicyId::Mls)},
                     }},
                     {"features", {
                         {"libsodium", feature_libsodium},
                         {"libsignal", feature_libsignal},
                         {"openmls", feature_openmls},
                         {"http_harness", feature_http_harness},
                         {"unauthenticated_kx", feature_unauthenticated_kx},
                         {"live_session", feature_live_session},
                         {"authenticated_handshake", feature_authenticated_handshake},
                         {"vfs", feature_vfs},
                     }},
                 }
                     .dump()
              << "\n";
    return 0;
}

} // namespace pm::encryption::cli
