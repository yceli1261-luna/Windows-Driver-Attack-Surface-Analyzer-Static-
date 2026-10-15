#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>

#include "core/driver/DriverAnalyzer.h"
#include "core/ioctl/IoctlExtractor.h"
#include "core/pe/PEParser.h"
#include "core/security/KernelApiAnalyzer.h"

// Kernel API classification and reachability (Phase 6). Expected call
// sites and reachability come from the fixture generators: in
// DASAWdmSample.sys (gen_wdm_fixture.py) DriverEntry (0x1000) calls
// IoCreateDevice / IoCreateSymbolicLink and resolves ZwQuerySystemInformation
// through MmGetSystemRoutineAddress; the IOCTL helper (0x1300), called only
// from the IRP_MJ_DEVICE_CONTROL routine, calls MmMapIoSpace and executes
// wrmsr and `in al, dx`. Risk levels are DASA's own catalog (ApiCatalog.cpp)
// and are checked as such.

namespace fs = std::filesystem;
using namespace dasa::core;
using security::ApiCategory;
using security::ApiRisk;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

security::KernelApiAnalysis analyze(const fs::path& path) {
    const pe::PEImage image = pe::parsePE(path);
    const auto functions = functions::discoverFunctions(image);
    const auto driver = driver::analyzeDriver(image, functions);
    const auto ioctls = ioctl::extractIoctls(image, functions, driver);
    return security::analyzeKernelApis(image, functions, driver, ioctls);
}

const security::ApiUse* find(const security::KernelApiAnalysis& a, const std::string& name, bool runtime = false) {
    for (const auto& u : a.apis) {
        if (u.name == name && u.resolvedAtRuntime == runtime) {
            return &u;
        }
    }
    return nullptr;
}

} // namespace

TEST(ApiCatalog, Classification) {
    const auto map = security::classifyApi("MmMapIoSpace");
    EXPECT_TRUE(map.catalogued);
    EXPECT_EQ(map.category, ApiCategory::PhysicalMemory);
    EXPECT_EQ(map.risk, ApiRisk::Critical);
    EXPECT_FALSE(map.why.empty());

    EXPECT_EQ(security::classifyApi("ZwOpenProcess").risk, ApiRisk::High);
    EXPECT_EQ(security::classifyApi("ProbeForRead").category, ApiCategory::Validation);
    EXPECT_EQ(security::classifyApi("ExAllocatePoolWithTag").risk, ApiRisk::Info);

    // Not in the catalog: categorised by prefix, risk info.
    const auto other = security::classifyApi("KeAcquireSpinLockRaiseToDpc");
    EXPECT_FALSE(other.catalogued);
    EXPECT_EQ(other.category, ApiCategory::Synchronization);
    EXPECT_EQ(other.risk, ApiRisk::Info);
    EXPECT_EQ(security::classifyApi("WdfRequestComplete").category, ApiCategory::Framework);
}

TEST(KernelApis, ReachabilityFromHandlers) {
    const auto a = analyze(fixture("DASAWdmSample.sys"));

    const auto* map = find(a, "MmMapIoSpace");
    ASSERT_NE(map, nullptr);
    EXPECT_EQ(map->info.risk, ApiRisk::Critical);
    EXPECT_EQ(map->callers, (std::vector<std::uint64_t>{0x1300}));
    EXPECT_EQ(map->reachableFrom, (std::set<std::string>{"IRP_MJ_DEVICE_CONTROL"}));

    const auto* create = find(a, "IoCreateDevice");
    ASSERT_NE(create, nullptr);
    EXPECT_EQ(create->callers, (std::vector<std::uint64_t>{0x1000}));
    EXPECT_EQ(create->reachableFrom, (std::set<std::string>{"DriverEntry"}));

    const auto* complete = find(a, "IofCompleteRequest");
    ASSERT_NE(complete, nullptr);
    EXPECT_TRUE(complete->callers.empty()); // imported, never called

    // Sorted highest risk first.
    ASSERT_FALSE(a.apis.empty());
    EXPECT_EQ(a.apis.front().info.risk, ApiRisk::Critical);
}

TEST(KernelApis, RuntimeResolvedRoutine) {
    const auto a = analyze(fixture("DASAWdmSample.sys"));
    const auto* resolved = find(a, "ZwQuerySystemInformation", /*runtime=*/true);
    ASSERT_NE(resolved, nullptr);
    EXPECT_EQ(resolved->library, "MmGetSystemRoutineAddress");
    EXPECT_FALSE(resolved->imported);
    EXPECT_EQ(resolved->callers, (std::vector<std::uint64_t>{0x1000}));
    EXPECT_EQ(resolved->reachableFrom, (std::set<std::string>{"DriverEntry"}));
    EXPECT_EQ(resolved->info.category, ApiCategory::DynamicResolution);
}

TEST(KernelApis, PrivilegedInstructions) {
    const auto a = analyze(fixture("DASAWdmSample.sys"));
    ASSERT_EQ(a.privileged.size(), 2u);
    const auto& wrmsr = a.privileged[0];
    EXPECT_EQ(wrmsr.rva, 0x132Cu);
    EXPECT_EQ(wrmsr.kind, "MSR write");
    EXPECT_EQ(wrmsr.risk, ApiRisk::Critical);
    EXPECT_EQ(wrmsr.function, 0x1300u);
    EXPECT_EQ(wrmsr.reachableFrom, (std::set<std::string>{"IRP_MJ_DEVICE_CONTROL"}));
    const auto& in = a.privileged[1];
    EXPECT_EQ(in.rva, 0x132Eu);
    EXPECT_EQ(in.kind, "Port I/O read");
}

// DASARiskyDriver imports a list of dangerous APIs (_build_risky_sample.py)
// but its code never calls them: they're classified, with no call sites.
TEST(KernelApis, RiskyFixtureImportsWithoutCalls) {
    const auto a = analyze(fixture("DASARiskyDriver.sys"));
    EXPECT_EQ(a.apis.size(), 33u);
    for (const char* name : {"MmMapIoSpace", "ZwMapViewOfSection", "ZwLoadDriver", "HalSetBusDataByOffset"}) {
        const auto* u = find(a, name);
        ASSERT_NE(u, nullptr) << name;
        EXPECT_EQ(u->info.risk, ApiRisk::Critical) << name;
        EXPECT_TRUE(u->callers.empty()) << name;
    }
    EXPECT_TRUE(a.privileged.empty());
}
