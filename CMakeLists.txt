cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(pm-encryption
    VERSION 0.1.0
    DESCRIPTION "PolyMech E2EE protocols"
    LANGUAGES CXX)
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

add_library(pm-encryption-lib STATIC
  src/channel.cpp)
add_library(pm::encryption ALIAS pm-encryption-lib)
target_include_directories(pm-encryption-lib
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(pm-encryption-lib PUBLIC cxx_std_20)
target_link_libraries(pm-encryption-lib PUBLIC sodium)

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

  add_executable(pm-encryption
    cli/main.cpp
    cli/http_harness.cpp)
  target_link_libraries(pm-encryption PRIVATE
    pm-encryption-lib
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    httplib::httplib)
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
