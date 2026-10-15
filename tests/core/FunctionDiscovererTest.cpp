#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <set>

#include "core/functions/FunctionDiscoverer.h"
#include "core/pe/PEParser.h"

// Expected values for the fixture drivers come from the generator that
// produced them (the v1 repo's samples/_build_sample.py and
// _build_risky_sample.py), i.e. from the code bytes as they were written,
// not from DASA's own output:
//   - DriverEntry at RVA 0x1000: 20-byte prologue, eight
//     `mov rax, imm64; mov [rcx+off], rax` pairs storing handler VAs,
//     `xor eax, eax`, 6-byte epilogue -> 25 instructions, 161 bytes, no
//     branches.
//   - The handler VAs point at RVAs 0x1400, 0x1800, 0x1C00, 0x2000, 0x5000,
//     0x6000, 0x7000, 0x8000. Only 0x5000 holds code; the rest of .text is
//     INT3 (0xCC) fill.
//   - DASARiskyDriver's handler at 0x5000 (_ioctl_handler_for, 24 codes):
//     `sub rsp, 0x28`, 24 x (`cmp dword ptr [rdx+8], imm32; je stub`),
//     3-instruction default path, 3-instruction success stub -> 55
//     instructions, 26 basic blocks, 333 bytes.

namespace fs = std::filesystem;
using namespace dasa::core;
using functions::Function;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

} // namespace

TEST(FunctionDiscoverer, RiskyDriverFindsEntryAndHandler) {
    const pe::PEImage image = pe::parsePE(fixture("DASARiskyDriver.sys"));
    EXPECT_TRUE(image.runtimeFunctions.empty()); // fixture has no .pdata

    const auto set = functions::discoverFunctions(image);
    ASSERT_EQ(set.functions.size(), 2u);

    const Function* entry = set.find(0x1000);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->name, "EntryPoint");
    EXPECT_TRUE(entry->sources & functions::kEntryPoint);
    EXPECT_EQ(entry->instructions.size(), 25u);
    EXPECT_EQ(entry->codeBytes, 161u);
    EXPECT_EQ(entry->blocks.size(), 1u);
    EXPECT_TRUE(entry->calls.empty());
    EXPECT_EQ(entry->instructions.back().mnemonic, "ret");

    const Function* handler = set.find(0x5000);
    ASSERT_NE(handler, nullptr);
    EXPECT_EQ(handler->name, "sub_5000");
    EXPECT_TRUE(handler->sources & functions::kAddressTaken);
    EXPECT_EQ(handler->instructions.size(), 55u);
    EXPECT_EQ(handler->codeBytes, 333u);
    EXPECT_EQ(handler->blocks.size(), 26u);
    EXPECT_FALSE(handler->hasUnresolvedIndirectJump);
    EXPECT_FALSE(handler->truncated);

    // Every compare block ends in je with two successors (stub, next cmp);
    // the last compare falls through to the default path.
    const auto& first = handler->blocks.front();
    EXPECT_EQ(first.start, 0x5000u);
    EXPECT_EQ(first.instructionCount, 3u); // sub, cmp, je
    EXPECT_EQ(first.successors.size(), 2u);
    const std::size_t returns =
        std::count_if(handler->instructions.begin(), handler->instructions.end(),
                      [](const auto& i) { return i.mnemonic == "ret"; });
    EXPECT_EQ(returns, 2u);
}

TEST(FunctionDiscoverer, PointersIntoPaddingAreRejected) {
    const pe::PEImage image = pe::parsePE(fixture("DASARiskyDriver.sys"));
    const auto set = functions::discoverFunctions(image);
    const std::set<std::uint64_t> rejected(set.rejectedSeeds.begin(), set.rejectedSeeds.end());
    const std::set<std::uint64_t> expected{0x1400, 0x1800, 0x1C00, 0x2000, 0x6000, 0x7000, 0x8000};
    EXPECT_EQ(rejected, expected);
}

TEST(FunctionDiscoverer, SampleDriverEntry) {
    const pe::PEImage image = pe::parsePE(fixture("DASASampleDriver.sys"));
    const auto set = functions::discoverFunctions(image);
    const Function* entry = set.find(0x1000);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->instructions.size(), 25u);
    EXPECT_NE(set.find(0x5000), nullptr);
}

// A real x64 driver: the anchors that are independently known from its
// headers - entry point, every non-forwarded export, every primary .pdata
// entry - must all come out as functions, and the call graph must be
// consistent. Counts vary by Windows build, so they aren't pinned.
TEST(FunctionDiscoverer, SystemDriverAnchorsAreFunctions) {
    const fs::path cng = "C:/Windows/System32/drivers/cng.sys";
    if (!fs::exists(cng)) {
        GTEST_SKIP() << "cng.sys not present on this machine";
    }
    const pe::PEImage image = pe::parsePE(cng);
    ASSERT_FALSE(image.runtimeFunctions.empty());
    const auto set = functions::discoverFunctions(image);

    ASSERT_NE(set.find(image.entryPointRva), nullptr);
    for (const auto& e : image.exports) {
        if (e.forwarder.empty() && image.isExecutable(e.rva)) {
            const Function* fn = set.find(e.rva);
            ASSERT_NE(fn, nullptr) << e.name;
            EXPECT_EQ(fn->name, e.name);
            EXPECT_TRUE(fn->sources & functions::kExport);
        }
    }
    std::size_t primaries = 0;
    for (const auto& rf : image.runtimeFunctions) {
        if (!rf.isChained()) {
            ++primaries;
            EXPECT_NE(set.find(rf.begin), nullptr) << std::hex << rf.begin;
        }
    }
    EXPECT_GE(set.functions.size(), primaries);

    std::size_t importCalls = 0;
    for (const auto& fn : set.functions) {
        EXPECT_FALSE(fn.instructions.empty()) << fn.name;
        EXPECT_FALSE(fn.blocks.empty()) << fn.name;
        for (const auto& call : fn.calls) {
            if (call.target && !call.isTailCall) {
                const Function* callee = set.find(*call.target);
                const bool rejected = std::find(set.rejectedSeeds.begin(), set.rejectedSeeds.end(),
                                                *call.target) != set.rejectedSeeds.end();
                EXPECT_TRUE(callee != nullptr || rejected) << std::hex << *call.target;
                if (callee) {
                    EXPECT_NE(std::find(callee->callers.begin(), callee->callers.end(), fn.rva),
                              callee->callers.end());
                }
            }
            if (!call.importName.empty()) {
                ++importCalls;
            }
        }
    }
    // cng.sys calls into ntoskrnl through its IAT all over the place.
    EXPECT_GT(importCalls, 100u);
}
