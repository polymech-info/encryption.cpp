#include "pm/encryption/policy.hpp"

#include "pm/encryption/features.hpp"

namespace pm::encryption {

bool policy_enabled(PolicyId id) noexcept {
    switch (id) {
    case PolicyId::LiveSession: return feature_live_session;
    case PolicyId::UnauthenticatedKx: return feature_unauthenticated_kx;
    case PolicyId::Signal: return feature_libsignal;
    case PolicyId::Mls: return feature_openmls;
    }
    return false;
}

const char* policy_id_name(PolicyId id) noexcept {
    switch (id) {
    case PolicyId::LiveSession: return "live_session";
    case PolicyId::UnauthenticatedKx: return "unauthenticated_kx";
    case PolicyId::Signal: return "signal";
    case PolicyId::Mls: return "mls";
    }
    return "unknown";
}

} // namespace pm::encryption
