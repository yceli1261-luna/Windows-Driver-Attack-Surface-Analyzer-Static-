cmake_minimum_required(VERSION 3.25)

project(DASA
    VERSION 2.0.0
    DESCRIPTION "DASA v2 - Windows kernel driver attack surface analysis platform"
    LANGUAGES CXX
)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(DASA_BUILD_TESTS "Build the DASA test suite" ON)
option(DASA_BUILD_APP "Build the DASA Qt application" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# Dependencies (vcpkg manifest mode expected: configure with
#   -DCMAKE_TOOLCHAIN_FILE=<vcpkg_root>/scripts/buildsystems/vcpkg.cmake)
# Phase 1 only needs Qt + spdlog; core/analysis/dynamic pull in
# LIEF/Capstone/SQLite3/nlohmann-json starting Phase 2, but the targets
# below already declare those link dependencies so later phases don't need
# to touch this top-level file.
# ---------------------------------------------------------------------------
find_package(spdlog CONFIG REQUIRED)

if(DASA_BUILD_APP)
    find_package(Qt6 COMPONENTS Widgets Core Gui REQUIRED)
    qt_standard_project_setup()
endif()

enable_testing()

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
add_subdirectory(core)
add_subdirectory(analysis)
add_subdirectory(dynamic)

if(DASA_BUILD_APP)
    add_subdirectory(app)
endif()

if(DASA_BUILD_TESTS)
    add_subdirectory(tests)
endif()

message(STATUS "DASA ${PROJECT_VERSION} configured (build app=${DASA_BUILD_APP}, tests=${DASA_BUILD_TESTS})")
