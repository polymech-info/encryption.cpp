cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(pm-encryption
    VERSION 0.1.0
    DESCRIPTION "PolyMech E2EE protocols"
    LANGUAGES CXX)
endif()

option(PM_ENCRYPTION_LIBSODIUM "Enable the libsodium X25519/XChaCha profile" ON)
option(PM_ENCRYPTION_LIBSIGNAL "Enable the AGPL-3.0 libsignal one-to-one adapter" OFF)
option(PM_ENCRYPTION_OPENMLS "Enable the OpenMLS group adapter" OFF)
option(PM_ENCRYPTION_HTTP_HARNESS "Build the standalone HTTP/SSE harness" ON)
option(PM_ENCRYPTION_UNAUTHENTICATED_KX
  "Allow SecureChannel without a pinned device-identity handshake" ON)
option(PM_ENCRYPTION_LIVE_SESSION
  "Enable the low-level online policy: pinned identity handshake and one channel key" ON)
option(PM_ENCRYPTION_VFS
  "Link packages/vfs.cpp into the group-file scenario" ON)

if(NOT PM_ENCRYPTION_LIBSODIUM)
  message(FATAL_ERROR "PM_ENCRYPTION_LIBSODIUM=OFF is not a supported profile yet")
endif()
if(PM_ENCRYPTION_LIBSIGNAL AND NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libsignal/CMakeLists.txt")
  message(FATAL_ERROR
    "PM_ENCRYPTION_LIBSIGNAL=ON is accepted under AGPL-3.0, but packages/libsignal is not vendored yet")
endif()
if(PM_ENCRYPTION_OPENMLS AND NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../openmls/CMakeLists.txt")
  message(FATAL_ERROR
    "PM_ENCRYPTION_OPENMLS=ON requires packages/openmls, which is not vendored yet")
endif()

set(PM_ENCRYPTION_LIBSODIUM_DEF 0)
set(PM_ENCRYPTION_LIBSIGNAL_DEF 0)
set(PM_ENCRYPTION_OPENMLS_DEF 0)
set(PM_ENCRYPTION_HTTP_HARNESS_DEF 0)
set(PM_ENCRYPTION_UNAUTHENTICATED_KX_DEF 0)
set(PM_ENCRYPTION_LIVE_SESSION_DEF 0)
if(PM_ENCRYPTION_LIBSODIUM)
  set(PM_ENCRYPTION_LIBSODIUM_DEF 1)
endif()
if(PM_ENCRYPTION_LIBSIGNAL)
  set(PM_ENCRYPTION_LIBSIGNAL_DEF 1)
endif()
if(PM_ENCRYPTION_OPENMLS)
  set(PM_ENCRYPTION_OPENMLS_DEF 1)
endif()
if(PM_ENCRYPTION_HTTP_HARNESS)
  set(PM_ENCRYPTION_HTTP_HARNESS_DEF 1)
endif()
if(PM_ENCRYPTION_UNAUTHENTICATED_KX)
  set(PM_ENCRYPTION_UNAUTHENTICATED_KX_DEF 1)
endif()
if(PM_ENCRYPTION_LIVE_SESSION)
  set(PM_ENCRYPTION_LIVE_SESSION_DEF 1)
endif()

include(FetchContent)

if(NOT TARGET sodium)
  set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
  FetchContent_Declare(
    libsodium_cmake
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG cfebfd3da486d5a86c644c8b47067e5411c7599c)
  FetchContent_MakeAvailable(libsodium_cmake)
endif()

set(PM_ENCRYPTION_LIB_SOURCES
  src/channel.cpp
  src/identity.cpp
  src/policy.cpp
  src/file.cpp
  src/device_key.cpp
  src/replay.cpp
  src/datagram.cpp
  src/flow.cpp
  src/host/device.cpp
  src/room/pairing.cpp
  src/room/broker.cpp
  src/text_session.cpp
  src/room/text_room.cpp)
if(PM_ENCRYPTION_LIVE_SESSION)
  list(APPEND PM_ENCRYPTION_LIB_SOURCES src/handshake.cpp)
endif()
if(PM_ENCRYPTION_LIBSIGNAL)
  list(APPEND PM_ENCRYPTION_LIB_SOURCES src/signal_session.cpp)
endif()
add_library(pm-encryption-lib STATIC ${PM_ENCRYPTION_LIB_SOURCES})
add_library(pm::encryption ALIAS pm-encryption-lib)
target_include_directories(pm-encryption-lib
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(pm-encryption-lib PUBLIC cxx_std_20)
target_compile_definitions(pm-encryption-lib PUBLIC
  PM_ENCRYPTION_LIBSODIUM=${PM_ENCRYPTION_LIBSODIUM_DEF}
  PM_ENCRYPTION_LIBSIGNAL=${PM_ENCRYPTION_LIBSIGNAL_DEF}
  PM_ENCRYPTION_OPENMLS=${PM_ENCRYPTION_OPENMLS_DEF}
  PM_ENCRYPTION_HTTP_HARNESS=${PM_ENCRYPTION_HTTP_HARNESS_DEF}
  PM_ENCRYPTION_UNAUTHENTICATED_KX=${PM_ENCRYPTION_UNAUTHENTICATED_KX_DEF}
  PM_ENCRYPTION_LIVE_SESSION=${PM_ENCRYPTION_LIVE_SESSION_DEF})
target_link_libraries(pm-encryption-lib PUBLIC sodium)
if(PM_ENCRYPTION_LIBSIGNAL)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../libsignal"
                   "${CMAKE_CURRENT_BINARY_DIR}/pm-libsignal"
                   EXCLUDE_FROM_ALL)
  target_link_libraries(pm-encryption-lib PUBLIC pm-signal)
endif()

if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  if(NOT TARGET pm-commons-lib)
    message(FATAL_ERROR "pm-encryption-lib under a host requires pm-commons-lib (add commons first)")
  endif()
  target_link_libraries(pm-encryption-lib PUBLIC pm-commons-lib)
endif()

if(MSVC)
  target_compile_definitions(pm-encryption-lib PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX)
  target_compile_options(pm-encryption-lib PRIVATE /W4 /utf-8 /EHsc)
else()
  target_compile_options(pm-encryption-lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  if(NOT TARGET CLI11::CLI11)
    set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
      cli11
      GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
      GIT_TAG v2.4.2
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(cli11)
  endif()
  if(NOT TARGET nlohmann_json::nlohmann_json)
    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
      nlohmann_json
      GIT_REPOSITORY https://github.com/nlohmann/json.git
      GIT_TAG v3.11.3
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()

  set(PM_ENCRYPTION_CLI_SOURCES
    cli/main.cpp
    cli/support.cpp
    cli/stderr_log.cpp
    cli/capabilities.cpp
    cli/identity_command.cpp
    cli/channel_checks.cpp
    cli/selftest.cpp
    cli/scenario.cpp
    cli/file_scenario.cpp
    cli/http_command.cpp
    cli/chat_harness.cpp
    cli/chat_command.cpp
    cli/room_harness.cpp
    cli/vectors.cpp
    cli/fuzz.cpp
    cli/signal_room.cpp
    cli/media_room.cpp
    cli/media_host.cpp
    cli/flow_command.cpp
    cli/policy_command.cpp)
  if(PM_ENCRYPTION_LIVE_SESSION)
    list(APPEND PM_ENCRYPTION_CLI_SOURCES cli/handshake_checks.cpp)
  endif()
  if(PM_ENCRYPTION_HTTP_HARNESS)
    if(NOT TARGET httplib::httplib)
      set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
      set(HTTPLIB_REQUIRE_ZLIB OFF CACHE BOOL "" FORCE)
      FetchContent_Declare(
        cpp_httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.16.3
        GIT_SHALLOW TRUE)
      FetchContent_MakeAvailable(cpp_httplib)
    endif()
    list(APPEND PM_ENCRYPTION_CLI_SOURCES cli/http_harness.cpp)
  endif()

  add_executable(pm-encryption ${PM_ENCRYPTION_CLI_SOURCES})
  target_link_libraries(pm-encryption PRIVATE
    pm-encryption-lib
    CLI11::CLI11
    nlohmann_json::nlohmann_json)
  if(PM_ENCRYPTION_VFS)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../vfs.cpp/CMakeLists.txt")
      message(FATAL_ERROR "PM_ENCRYPTION_VFS=ON requires packages/vfs.cpp")
    endif()
    set(PM_VFS_USE_BUNDLED_SANITIZER ON)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../vfs.cpp"
                     "${CMAKE_CURRENT_BINARY_DIR}/pm-vfs"
                     EXCLUDE_FROM_ALL)
    target_compile_definitions(pm-encryption PRIVATE PM_ENCRYPTION_VFS=1)
    target_link_libraries(pm-encryption PRIVATE pm-vfs-lib)
  else()
    target_compile_definitions(pm-encryption PRIVATE PM_ENCRYPTION_VFS=0)
  endif()
  if(PM_ENCRYPTION_HTTP_HARNESS)
    target_link_libraries(pm-encryption PRIVATE httplib::httplib)
  endif()
  if(PM_ENCRYPTION_LIBSIGNAL AND WIN32)
    add_custom_command(TARGET pm-encryption POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "$<TARGET_FILE:pm-signal>"
              "$<TARGET_FILE_DIR:pm-encryption>"
      VERBATIM)
  endif()
  target_compile_features(pm-encryption PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_definitions(pm-encryption PRIVATE
      _CRT_SECURE_NO_WARNINGS
      NOMINMAX)
    target_compile_options(pm-encryption PRIVATE /W4 /utf-8 /EHsc)
  else()
    target_compile_options(pm-encryption PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endif()
