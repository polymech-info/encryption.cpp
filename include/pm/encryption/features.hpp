#pragma once

// Compile definitions come from the CMake options. A translation unit that
// includes this header without those definitions sees every optional feature
// as off, which fails closed.

#ifndef PM_ENCRYPTION_LIBSODIUM
#define PM_ENCRYPTION_LIBSODIUM 0
#endif
#ifndef PM_ENCRYPTION_LIBSIGNAL
#define PM_ENCRYPTION_LIBSIGNAL 0
#endif
#ifndef PM_ENCRYPTION_OPENMLS
#define PM_ENCRYPTION_OPENMLS 0
#endif
#ifndef PM_ENCRYPTION_HTTP_HARNESS
#define PM_ENCRYPTION_HTTP_HARNESS 0
#endif
#ifndef PM_ENCRYPTION_UNAUTHENTICATED_KX
#define PM_ENCRYPTION_UNAUTHENTICATED_KX 0
#endif

namespace pm::encryption {

inline constexpr bool feature_libsodium = PM_ENCRYPTION_LIBSODIUM != 0;
inline constexpr bool feature_libsignal = PM_ENCRYPTION_LIBSIGNAL != 0;
inline constexpr bool feature_openmls = PM_ENCRYPTION_OPENMLS != 0;
inline constexpr bool feature_http_harness = PM_ENCRYPTION_HTTP_HARNESS != 0;
inline constexpr bool feature_unauthenticated_kx = PM_ENCRYPTION_UNAUTHENTICATED_KX != 0;
inline constexpr bool feature_authenticated_handshake = true;

} // namespace pm::encryption
