#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <string>

#include "core/driver/DriverAnalyzer.h"
#include "core/driver/WdfFunctionTable.h"
#include "core/pe/PEParser.h"

// Expected values come from the generators that wrote the fixtures' code
// bytes (v1's samples/_build_sample.py for DASARiskyDriver.sys,
// tests/fixtures/drivers/gen_kmdf_fixture.py for DASAKmdfSample.sys), from
// Microsoft's public WDF headers (wdffuncenum.h, wdfio.h, wdfdriver.h,
// fxldr.h) and from wdm.h's DRIVER_OBJECT layout - not from DASA output.

namespace fs = std::filesystem;
using namespace dasa::core;
using driver::DriverAnalysis;
using driver::ModelKind;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

DriverAnalysis analyze(const fs::path& path) {
    const pe::PEImage image = pe::parsePE(path);
    const auto functions = functions::discoverFunctions(image);
    return driver::analyzeDriver(image, functions);
}

const driver::WdfCallback* findCallback(const std::vector<driver::WdfCallback>& cbs, const char* name) {
    for (const auto& cb : cbs) {
        if (cb.name == name) {
            return &cb;
        }
    }
    return nullptr;
}

} // namespace

TEST(WdfFunctionTable, MatchesHeaderIndices) {
    EXPECT_EQ(driver::wdfFunctionCount(), 458u);
    EXPECT_STREQ(driver::wdfFunctionName(0), "WdfChildListCreate");
    EXPECT_STREQ(driver::wdfFunctionName(61), "WdfDeviceInitSetIoType");
    EXPECT_STREQ(driver::wdfFunctionName(75), "WdfDeviceCreate");
    EXPECT_STREQ(driver::wdfFunctionName(116), "WdfDriverCreate");
    EXPECT_STREQ(driver::wdfFunctionName(152), "WdfIoQueueCreate");
    EXPECT_STREQ(driver::wdfFunctionName(269), "WdfRequestRetrieveInputBuffer");
    EXPECT_EQ(driver::wdfFunctionName(458), nullptr);
}

TEST(DriverAnalyzer, IrpMajorNames) {
    EXPECT_STREQ(driver::irpMajorName(0x00), "IRP_MJ_CREATE");
    EXPECT_STREQ(driver::irpMajorName(0x0E), "IRP_MJ_DEVICE_CONTROL");
    EXPECT_STREQ(driver::irpMajorName(0x12), "IRP_MJ_CLEANUP");
    EXPECT_STREQ(driver::irpMajorName(0x1B), "IRP_MJ_PNP");
}

// DASARiskyDriver: DriverEntry at 0x1000 stores handler VAs into
// [rcx+0x70/0x80/0x88/0x90/0xE0/0xE8/0x100] and [rcx+0x58].
TEST(DriverAnalyzer, WdmFixtureDispatchTable) {
    const DriverAnalysis d = analyze(fixture("DASARiskyDriver.sys"));

    EXPECT_EQ(d.model.kind, ModelKind::Wdm);
    EXPECT_EQ(d.model.confidence, driver::Confidence::High);
    ASSERT_TRUE(d.driverEntry.has_value());
    EXPECT_EQ(*d.driverEntry, 0x1000u);
    EXPECT_EQ(d.entryChain, (std::vector<std::uint64_t>{0x1000}));
    EXPECT_FALSE(d.wdfBind.has_value());

    const std::map<unsigned, std::uint64_t> expected{
        {0x00, 0x1400}, {0x02, 0x1800}, {0x03, 0x1C00}, {0x04, 0x2000},
        {0x0E, 0x5000}, {0x0F, 0x6000}, {0x12, 0x7000},
    };
    std::map<unsigned, std::uint64_t> actual;
    for (const auto& e : d.majorFunctions) {
        actual[e.major] = e.handler;
        EXPECT_EQ(e.inFunction, 0x1000u);
        EXPECT_EQ(e.how, "direct store");
        // Only the IOCTL handler at 0x5000 holds code; the rest of the
        // fixture's handler pointers aim at INT3 padding.
        EXPECT_EQ(e.handlerIsFunction, e.handler == 0x5000) << std::hex << e.handler;
    }
    EXPECT_EQ(actual, expected);

    // [rcx+0x58] is DRIVER_OBJECT.DriverInit on x64 (wdm.h), whatever the
    // generator's comment calls it.
    ASSERT_EQ(d.driverObjectWrites.size(), 1u);
    EXPECT_EQ(d.driverObjectWrites[0].offset, 0x58u);
    EXPECT_EQ(d.driverObjectWrites[0].field, "DriverInit");
    EXPECT_EQ(d.driverObjectWrites[0].value.value_or(0), 0x8000u);
}

TEST(DriverAnalyzer, KmdfFixtureModelAndEntry) {
    const DriverAnalysis d = analyze(fixture("DASAKmdfSample.sys"));

    EXPECT_EQ(d.model.kind, ModelKind::Kmdf);
    EXPECT_EQ(d.model.confidence, driver::Confidence::High);

    ASSERT_TRUE(d.wdfBind.has_value());
    EXPECT_EQ(d.wdfBind->rva, 0x3000u);
    EXPECT_EQ(d.wdfBind->size, 0x30u);
    EXPECT_EQ(d.wdfBind->major, 1u);
    EXPECT_EQ(d.wdfBind->minor, 15u);
    EXPECT_EQ(d.wdfBind->build, 0u);
    EXPECT_EQ(d.wdfBind->functionCount, 444u);
    EXPECT_EQ(d.wdfBind->functionTableVariable, 0x3040u);

    // FxDriverEntry -> FxDriverEntryWorker -> (after WdfVersionBind) DriverEntry
    EXPECT_EQ(d.entryChain, (std::vector<std::uint64_t>{0x1000, 0x1100, 0x1200}));
    EXPECT_EQ(d.driverEntry.value_or(0), 0x1200u);

    // A KMDF driver doesn't fill MajorFunction[] itself.
    EXPECT_TRUE(d.majorFunctions.empty());
}

TEST(DriverAnalyzer, KmdfFixtureWdfCalls) {
    const DriverAnalysis d = analyze(fixture("DASAKmdfSample.sys"));

    std::vector<std::pair<std::uint64_t, std::string>> calls;
    for (const auto& c : d.wdfCalls) {
        calls.emplace_back(c.inFunction, c.name);
    }
    std::sort(calls.begin(), calls.end());
    const std::vector<std::pair<std::uint64_t, std::string>> expected{
        {0x1200, "WdfDriverCreate"},
        {0x1300, "WdfDeviceCreateDeviceInterface"},
        {0x1300, "WdfDeviceCreateSymbolicLink"},
        {0x1300, "WdfDeviceInitAssignName"},
        {0x1300, "WdfDeviceInitSetCharacteristics"},
        {0x1300, "WdfDeviceInitSetDeviceType"},
        {0x1300, "WdfDeviceInitSetIoType"},
        {0x1300, "WdfIoQueueCreate"},
        {0x1300, "WdfIoQueueCreate"},
    };
    EXPECT_EQ(calls, expected);

    ASSERT_EQ(d.wdfIoTypes.size(), 1u);
    EXPECT_EQ(d.wdfIoTypes[0].ioType, "Direct");
}

TEST(DriverAnalyzer, KmdfFixtureDriverConfig) {
    const DriverAnalysis d = analyze(fixture("DASAKmdfSample.sys"));
    ASSERT_EQ(d.wdfDrivers.size(), 1u);
    const auto& reg = d.wdfDrivers[0];
    EXPECT_TRUE(reg.configResolved);
    EXPECT_EQ(reg.inFunction, 0x1200u);

    const auto* add = findCallback(reg.callbacks, "EvtDriverDeviceAdd");
    ASSERT_NE(add, nullptr);
    EXPECT_EQ(add->function, 0x1300u);
    EXPECT_TRUE(add->isFunction);
    const auto* unload = findCallback(reg.callbacks, "EvtDriverUnload");
    ASSERT_NE(unload, nullptr);
    EXPECT_EQ(unload->function, 0x1500u);
}

TEST(DriverAnalyzer, KmdfFixtureQueues) {
    const DriverAnalysis d = analyze(fixture("DASAKmdfSample.sys"));
    ASSERT_EQ(d.wdfQueues.size(), 2u);

    // Queue 1: through the CFG dispatch thunk.
    const auto& q1 = d.wdfQueues[0];
    EXPECT_TRUE(q1.configResolved);
    EXPECT_EQ(q1.inFunction, 0x1300u);
    EXPECT_EQ(q1.dispatchType, "Parallel");
    EXPECT_EQ(q1.defaultQueue, std::optional<bool>(true));
    ASSERT_EQ(q1.callbacks.size(), 2u);
    ASSERT_NE(findCallback(q1.callbacks, "EvtIoRead"), nullptr);
    EXPECT_EQ(findCallback(q1.callbacks, "EvtIoRead")->function, 0x1520u);
    ASSERT_NE(findCallback(q1.callbacks, "EvtIoDeviceControl"), nullptr);
    EXPECT_EQ(findCallback(q1.callbacks, "EvtIoDeviceControl")->function, 0x1600u);

    // Queue 2: `call [rax + WdfIoQueueCreate*8]` directly.
    const auto& q2 = d.wdfQueues[1];
    EXPECT_TRUE(q2.configResolved);
    EXPECT_EQ(q2.dispatchType, "Sequential");
    EXPECT_EQ(q2.defaultQueue, std::optional<bool>(false));
    ASSERT_EQ(q2.callbacks.size(), 1u);
    EXPECT_EQ(q2.callbacks[0].name, "EvtIoInternalDeviceControl");
    EXPECT_EQ(q2.callbacks[0].function, 0x1530u);

    for (const auto& q : d.wdfQueues) {
        for (const auto& cb : q.callbacks) {
            EXPECT_TRUE(cb.isFunction) << cb.name;
        }
    }
}

// Real drivers from the machine running the tests. Their exact addresses
// change between Windows builds, so these check properties that hold for
// any build: the model, that DriverEntry was reached through the stub, and
// that every recovered handler/callback is a discovered function.

TEST(DriverAnalyzer, RealWdmDriver) {
    const fs::path beep = "C:/Windows/System32/drivers/beep.sys";
    if (!fs::exists(beep)) {
        GTEST_SKIP() << "beep.sys not present";
    }
    const DriverAnalysis d = analyze(beep);
    EXPECT_EQ(d.model.kind, ModelKind::Wdm);
    EXPECT_EQ(d.model.confidence, driver::Confidence::High);
    EXPECT_GE(d.entryChain.size(), 2u); // GsDriverEntry -> DriverEntry
    ASSERT_NE(d.dispatchFor(0x0E), nullptr) << "IRP_MJ_DEVICE_CONTROL";
    for (const auto& e : d.majorFunctions) {
        EXPECT_TRUE(e.handlerIsFunction) << driver::irpMajorName(e.major);
    }
    const bool hasUnload = std::any_of(d.driverObjectWrites.begin(), d.driverObjectWrites.end(),
                                       [](const auto& w) { return w.field == "DriverUnload" && w.value; });
    EXPECT_TRUE(hasUnload);
}

TEST(DriverAnalyzer, RealKmdfDrivers) {
    int checked = 0;
    for (const char* name : {"CAD.sys", "1394ohci.sys", "BTHUSB.SYS"}) {
        const fs::path path = fs::path("C:/Windows/System32/drivers") / name;
        if (!fs::exists(path)) {
            continue;
        }
        ++checked;
        SCOPED_TRACE(name);
        const DriverAnalysis d = analyze(path);
        EXPECT_EQ(d.model.kind, ModelKind::Kmdf);
        EXPECT_EQ(d.model.confidence, driver::Confidence::High);
        ASSERT_TRUE(d.wdfBind.has_value());
        EXPECT_EQ(d.wdfBind->major, 1u);
        EXPECT_GE(d.entryChain.size(), 3u); // FxDriverEntry -> worker -> DriverEntry
        EXPECT_FALSE(d.wdfCalls.empty());

        ASSERT_FALSE(d.wdfDrivers.empty());
        const auto* add = findCallback(d.wdfDrivers[0].callbacks, "EvtDriverDeviceAdd");
        ASSERT_NE(add, nullptr);
        EXPECT_TRUE(add->isFunction);

        ASSERT_FALSE(d.wdfQueues.empty());
        std::size_t callbacks = 0;
        for (const auto& q : d.wdfQueues) {
            for (const auto& cb : q.callbacks) {
                EXPECT_TRUE(cb.isFunction) << cb.name;
                ++callbacks;
            }
        }
        EXPECT_GT(callbacks, 0u);
    }
    if (checked == 0) {
        GTEST_SKIP() << "none of the sample KMDF drivers are present";
    }
}

TEST(DriverAnalyzer, RealMinifilter) {
    const fs::path wof = "C:/Windows/System32/drivers/Wof.sys";
    if (!fs::exists(wof)) {
        GTEST_SKIP() << "Wof.sys not present";
    }
    const DriverAnalysis d = analyze(wof);
    EXPECT_EQ(d.model.kind, ModelKind::Minifilter);
    EXPECT_FALSE(d.notes.empty()); // says callback decoding isn't done yet
}
