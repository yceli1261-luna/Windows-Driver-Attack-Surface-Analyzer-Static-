#include <gtest/gtest.h>

#include "core/Version.h"

// Phase 1's only real test: confirms the core library actually links and
// that its version string matches the CMake project version. Every later
// phase adds its suite under tests/core/ alongside this one (one file per
// core/ module, per the architecture proposal) rather than replacing it.

TEST(Version, StringMatchesComponents) {
    using dasa::core::Version;
    const std::string expected =
        std::to_string(Version::major) + "." +
        std::to_string(Version::minor) + "." +
        std::to_string(Version::patch);
    EXPECT_EQ(std::string(Version::string()), expected);
}

TEST(Version, MajorIsTwo) {
    EXPECT_EQ(dasa::core::Version::major, 2);
}
