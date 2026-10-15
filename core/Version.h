#pragma once

namespace dasa::core {

/// DASA core engine version. Bumped alongside CMakeLists.txt's
/// project(DASA VERSION ...); exposed so the GUI's About dialog and
/// log banner can report which engine build they're running without
/// duplicating the version string.
struct Version {
    static constexpr int major = 2;
    static constexpr int minor = 0;
    static constexpr int patch = 0;

    static const char* string();
};

} // namespace dasa::core
