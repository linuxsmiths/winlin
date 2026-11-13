cmake_minimum_required(VERSION 3.24)
project(winlin VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
include(FetchContent)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(client_default ON)
  set(tcmalloc_default ON)
else()
  set(client_default OFF)
  set(tcmalloc_default OFF)
endif()
option(WINLIN_BUILD_CLIENT "Build the Linux client" ${client_default})
option(WINLIN_BUILD_SERVER "Build the native benchmark server" ON)
option(WINLIN_WINDOWS_HTTPS_TESTS "Run privileged Windows HTTP.sys loopback tests" OFF)
option(WINLIN_USE_TCMALLOC "Use gperftools minimal tcmalloc for Linux executables" ${tcmalloc_default})
if(WINLIN_BUILD_CLIENT AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "The client is Linux-only; configure with -DWINLIN_BUILD_CLIENT=OFF.")
endif()
find_package(Threads REQUIRED)

# Keep allocator selection consistent across the client, server, and C++ tests. An enabled option
# must not silently fall back, since allocator differences can affect benchmark comparisons.
add_library(winlin_allocator INTERFACE)
set(winlin_allocator_name "system")
if(WINLIN_USE_TCMALLOC)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "WINLIN_USE_TCMALLOC is supported only on Linux; configure it OFF on Windows.")
  endif()
  find_library(WINLIN_TCMALLOC_LIBRARY NAMES tcmalloc_minimal)
  if(NOT WINLIN_TCMALLOC_LIBRARY)
    message(FATAL_ERROR
      "WINLIN_USE_TCMALLOC=ON requires gperftools libtcmalloc_minimal. "
      "Install libgoogle-perftools-dev on Ubuntu, or configure -DWINLIN_USE_TCMALLOC=OFF.")
  endif()
  mark_as_advanced(WINLIN_TCMALLOC_LIBRARY)
  target_link_libraries(winlin_allocator INTERFACE "${WINLIN_TCMALLOC_LIBRARY}" Threads::Threads)
  set(winlin_allocator_name "tcmalloc_minimal")
endif()
message(STATUS "Winlin process allocator: ${winlin_allocator_name}")

find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
  # Pin and verify the fallback dependency rather than changing the code used between runs.
  FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(json)
endif()

add_library(winlin_core INTERFACE)
set(benchmark_certificate "${CMAKE_CURRENT_SOURCE_DIR}/certs/benchmark/server.der")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${benchmark_certificate}")
file(SHA256 "${benchmark_certificate}" benchmark_certificate_sha256)
target_include_directories(winlin_core INTERFACE include)
target_compile_features(winlin_core INTERFACE cxx_std_23)
target_compile_definitions(winlin_core INTERFACE
  WINLIN_VERSION="${PROJECT_VERSION}" WINLIN_BUILD_TYPE="$<CONFIG>"
  WINLIN_ALLOCATOR="${winlin_allocator_name}"
  WINLIN_BENCHMARK_CERTIFICATE_SHA256="${benchmark_certificate_sha256}")
target_link_libraries(winlin_core INTERFACE nlohmann_json::nlohmann_json winlin_allocator)
if(MSVC)
  target_compile_options(winlin_core INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus)
else()
  target_compile_options(winlin_core INTERFACE -Wall -Wextra -Wpedantic)
endif()
if(WIN32)
  target_compile_definitions(winlin_core INTERFACE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
  add_library(winlin_windows INTERFACE)
  target_link_libraries(winlin_windows INTERFACE
    winlin_core Threads::Threads httpapi bcrypt advapi32 psapi ws2_32 winhttp)
  if(WINLIN_BUILD_SERVER)
    add_executable(winlin-server src/server_windows.cpp)
    target_link_libraries(winlin-server PRIVATE winlin_windows)
    if(MINGW)
      target_link_options(winlin-server PRIVATE -municode)
    endif()
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND (WINLIN_BUILD_CLIENT OR WINLIN_BUILD_SERVER))
  find_package(OpenSSL 3.0 REQUIRED)
  add_library(winlin_linux INTERFACE)
  target_link_libraries(winlin_linux INTERFACE
    winlin_core OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if(WINLIN_BUILD_SERVER)
    add_executable(winlin-server src/server.cpp)
    target_link_libraries(winlin-server PRIVATE winlin_linux)
  endif()
  if(WINLIN_BUILD_CLIENT)
    add_executable(winlin src/client.cpp)
    target_link_libraries(winlin PRIVATE winlin_linux)
  endif()
elseif(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT WIN32 AND WINLIN_BUILD_SERVER)
  message(FATAL_ERROR "The server supports Linux and Windows only.")
endif()

if(BUILD_TESTING)
  add_executable(winlin-core-tests tests/core.cpp)
  target_link_libraries(winlin-core-tests PRIVATE winlin_core)
  add_test(NAME core COMMAND winlin-core-tests)
  add_executable(winlin-agent-tests tests/agent.cpp)
  target_link_libraries(winlin-agent-tests PRIVATE winlin_core Threads::Threads)
  add_test(NAME agent COMMAND winlin-agent-tests)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME scripts COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts.py")
    if(TARGET winlin)
      add_test(NAME client-errors COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/client_errors.py" "$<TARGET_FILE:winlin>")
    endif()
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET winlin-server AND TARGET winlin)
    add_test(NAME https-integration COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.py"
      "$<TARGET_FILE:winlin-server>" "$<TARGET_FILE:winlin>")
    set_tests_properties(https-integration PROPERTIES TIMEOUT 90)
  endif()
  if(WIN32)
    add_executable(winlin-windows-tests tests/windows.cpp)
    target_link_libraries(winlin-windows-tests PRIVATE winlin_windows)
    add_test(NAME windows-platform COMMAND winlin-windows-tests)
    # Indirect launches from PowerShell 7 inherit incompatible module paths unless reset here.
    add_test(NAME powershell COMMAND "${CMAKE_COMMAND}" -E env --unset=PSModulePath
      powershell.exe -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts.ps1")
    if(WINLIN_WINDOWS_HTTPS_TESTS AND TARGET winlin-server)
      find_package(Python3 COMPONENTS Interpreter REQUIRED)
      add_test(NAME windows-https COMMAND "${CMAKE_COMMAND}" -E env --unset=PSModulePath
        powershell.exe -NoProfile -ExecutionPolicy Bypass
        -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_integration.ps1"
        -ServerExe "$<TARGET_FILE:winlin-server>" -PythonExe "${Python3_EXECUTABLE}")
      set_tests_properties(windows-https PROPERTIES TIMEOUT 120)
    endif()
  endif()
endif()
