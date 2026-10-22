#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <set>
#include <string>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/dataflow/TaintAnalyzer.h"

// Data flow (Phase 10). DASATaintSample.sys is written by
// tests/fixtures/drivers/gen_taint_fixture.py; which request data reaches
// which operation is spelled out in that script:
//   0x00222000 -> MapHelper 0x1400: MmMapIoSpace(PhysicalAddress = buf[0], NumberOfBytes = buf[8])
//   0x00222004 -> memcpy(Destination = buf[0x10], Source = buf + 0x18, Length = InputBufferLength)
//   0x00222008 -> wrmsr with ecx/eax/edx = buf[0]/buf[4]/buf[8]                (at 0x128F)
//   0x0022200F -> read through Type3InputBuffer without ProbeForRead           (at 0x12CB)
//   0x00222010 -> *(buf[0x20]) = buf[0x28]                                      (at 0x130C)
//   0x00222017 -> ProbedHelper 0x1440: ProbeForRead(p) then *p - no flow       (read at 0x1454)
// DASAWdmSample.sys (gen_wdm_fixture.py) reaches MmMapIoSpace, wrmsr and
// `in` from its IOCTL handler with constant arguments only.

namespace fs = std::filesystem;
using namespace dasa;
using namespace dasa::core::dataflow;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

DataFlowAnalysis analyze(const char* name) {
    const auto r = analysis::runStaticAnalysis(fixture(name));
    return analyzeDataFlow(*r->image, *r->functions, *r->driver, *r->ioctls);
}

const TaintFlow* flowAt(const DataFlowAnalysis& a, std::uint64_t at) {
    for (const auto& f : a.flows) {
        if (f.at == at) {
            return &f;
        }
    }
    return nullptr;
}

std::set<std::string> operandNames(const TaintFlow& f) {
    std::set<std::string> s;
    for (const auto& o : f.operands) {
        s.insert(o.name);
    }
    return s;
}

const TaintedOperand* operandNamed(const TaintFlow& f, const std::string& name) {
    for (const auto& o : f.operands) {
        if (o.name == name) {
            return &o;
        }
    }
    return nullptr;
}

} // namespace

TEST(DataFlow, MmMapIoSpaceThroughHelper) {
    const auto a = analyze("DASATaintSample.sys");
    const auto* f = flowAt(a, 0x1407); // call [MmMapIoSpace] in MapHelper
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->kind, SinkKind::ApiArgument);
    EXPECT_EQ(f->sink, "MmMapIoSpace");
    EXPECT_EQ(f->severity, Severity::Critical);
    EXPECT_EQ(f->entry, "IRP_MJ_DEVICE_CONTROL");
    EXPECT_EQ(f->function, 0x1400u);
    EXPECT_EQ(f->path, (std::vector<std::uint64_t>{0x1100, 0x1400}));
    EXPECT_EQ(operandNames(*f), (std::set<std::string>{"PhysicalAddress", "NumberOfBytes"}));
    const auto* phys = operandNamed(*f, "PhysicalAddress");
    EXPECT_EQ(phys->labels, static_cast<std::uint32_t>(kUserData));
    EXPECT_EQ(phys->source, "[Irp->AssociatedIrp.SystemBuffer]");
    EXPECT_EQ(phys->sourceAt, 0x1204u);
    EXPECT_EQ(operandNamed(*f, "NumberOfBytes")->source, "[Irp->AssociatedIrp.SystemBuffer + 0x8]");
    EXPECT_EQ(f->ioctls, (std::vector<std::uint32_t>{0x00222000}));
    EXPECT_TRUE(f->ioctlsExact);
}

TEST(DataFlow, MemcpyDestinationAndLength) {
    const auto a = analyze("DASATaintSample.sys");
    const auto* f = flowAt(a, 0x1257);
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->sink, "memcpy");
    EXPECT_EQ(f->severity, Severity::Critical);
    // Source is the system buffer itself - a normal, safe use.
    EXPECT_EQ(operandNames(*f), (std::set<std::string>{"Destination", "Length"}));
    EXPECT_EQ(operandNamed(*f, "Length")->labels, static_cast<std::uint32_t>(kUserLength));
    EXPECT_EQ(operandNamed(*f, "Length")->source, "IrpSp->Parameters.DeviceIoControl.InputBufferLength");
    EXPECT_EQ(operandNamed(*f, "Destination")->source, "[Irp->AssociatedIrp.SystemBuffer + 0x10]");
    EXPECT_EQ(f->ioctls, (std::vector<std::uint32_t>{0x00222004}));
}

TEST(DataFlow, WrmsrWriteWhatWhereAndUnprobedRead) {
    const auto a = analyze("DASATaintSample.sys");
    const auto* msr = flowAt(a, 0x128F);
    ASSERT_NE(msr, nullptr);
    EXPECT_EQ(msr->kind, SinkKind::Instruction);
    EXPECT_EQ(msr->severity, Severity::Critical);
    EXPECT_EQ(operandNames(*msr).size(), 3u); // ecx, eax and edx all from the request
    EXPECT_EQ(msr->ioctls, (std::vector<std::uint32_t>{0x00222008}));

    const auto* www = flowAt(a, 0x130C);
    ASSERT_NE(www, nullptr);
    EXPECT_EQ(www->kind, SinkKind::MemoryWrite);
    EXPECT_EQ(www->severity, Severity::Critical);
    EXPECT_EQ(operandNamed(*www, "address")->source, "[Irp->AssociatedIrp.SystemBuffer + 0x20]");
    EXPECT_EQ(operandNamed(*www, "value")->source, "[Irp->AssociatedIrp.SystemBuffer + 0x28]");
    EXPECT_EQ(www->ioctls, (std::vector<std::uint32_t>{0x00222010}));

    const auto* read = flowAt(a, 0x12CB);
    ASSERT_NE(read, nullptr);
    EXPECT_EQ(read->kind, SinkKind::MemoryRead);
    EXPECT_EQ(operandNamed(*read, "address")->labels, static_cast<std::uint32_t>(kUserPointer));
    EXPECT_EQ(operandNamed(*read, "address")->source, "IrpSp->Parameters.DeviceIoControl.Type3InputBuffer");
    EXPECT_EQ(read->ioctls, (std::vector<std::uint32_t>{0x0022200F}));
}

TEST(DataFlow, ProbedPointerAndNothingElse) {
    const auto a = analyze("DASATaintSample.sys");
    EXPECT_EQ(flowAt(a, 0x1454), nullptr); // read after ProbeForRead
    // Exactly the five flows the generator put in, most severe first.
    std::set<std::uint64_t> ats;
    for (const auto& f : a.flows) {
        ats.insert(f.at);
    }
    EXPECT_EQ(ats, (std::set<std::uint64_t>{0x1407, 0x1257, 0x128F, 0x12CB, 0x130C}));
    for (std::size_t i = 1; i < a.flows.size(); ++i) {
        EXPECT_GE(a.flows[i - 1].severity, a.flows[i].severity);
    }
    ASSERT_EQ(a.entries.size(), 1u);
    EXPECT_EQ(a.entries[0].rfind("IRP_MJ_DEVICE_CONTROL", 0), 0u);
}

TEST(DataFlow, WdmFixtureCallsUseConstants) {
    const auto a = analyze("DASAWdmSample.sys");
    EXPECT_TRUE(a.flows.empty());
    const auto it = std::find_if(a.checkedCalls.begin(), a.checkedCalls.end(),
                                 [](const CheckedCall& c) { return c.api == "MmMapIoSpace"; });
    ASSERT_NE(it, a.checkedCalls.end());
    EXPECT_EQ(it->at, 0x1320u);
    EXPECT_FALSE(it->anyUserControlled());
    ASSERT_EQ(it->args.size(), 2u);
    EXPECT_EQ(it->args[0].kind, CheckedCall::Arg::Kind::Constant); // xor ecx, ecx
    EXPECT_EQ(it->args[0].value, 0);
    EXPECT_EQ(it->args[1].kind, CheckedCall::Arg::Kind::Constant); // mov edx, 0x1000
    EXPECT_EQ(it->args[1].value, 0x1000);
}

TEST(DataFlow, FindingsFromFlows) {
    const auto r = analysis::runStaticAnalysis(fixture("DASATaintSample.sys"));
    std::multiset<std::string> ids;
    for (const auto& f : r->findings->findings) {
        ids.insert(f.ruleId);
    }
    EXPECT_EQ(ids.count("DASA-TAINT-API"), 2u);        // MmMapIoSpace, memcpy
    EXPECT_EQ(ids.count("DASA-TAINT-INSTRUCTION"), 1u); // wrmsr
    EXPECT_EQ(ids.count("DASA-TAINT-WRITE"), 1u);
    EXPECT_EQ(ids.count("DASA-UNPROBED-USER-POINTER"), 1u);
    EXPECT_EQ(ids.count("DASA-TAINT-READ"), 0u);
    const auto it = std::find_if(r->findings->findings.begin(), r->findings->findings.end(), [](const auto& f) {
        return f.ruleId == "DASA-TAINT-API" && f.title.find("MmMapIoSpace") != std::string::npos;
    });
    ASSERT_NE(it, r->findings->findings.end());
    EXPECT_EQ(it->severity, core::findings::Severity::Critical);
    ASSERT_EQ(it->evidence.size(), 1u);
    using K = core::findings::EvidenceStep::Kind;
    const auto& chain = it->evidence[0];
    auto has = [&](K kind, const std::string& label) {
        return std::any_of(chain.begin(), chain.end(), [&](const auto& s) { return s.kind == kind && s.label == label; });
    };
    EXPECT_TRUE(has(K::UserModeName, R"(\DosDevices\DasaTaint)"));
    EXPECT_TRUE(has(K::EntryPoint, "IRP_MJ_DEVICE_CONTROL"));
    EXPECT_TRUE(has(K::Ioctl, "IOCTL 0x00222000"));
    EXPECT_TRUE(has(K::DataSource, "[Irp->AssociatedIrp.SystemBuffer]"));
    EXPECT_TRUE(has(K::Call, "MmMapIoSpace"));
    EXPECT_EQ(chain.back().rva, std::optional<std::uint64_t>(0x1407));
}

TEST(DataFlow, ReachFindingNotesConstantArguments) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    bool found = false;
    for (const auto& f : r->findings->findings) {
        if (f.ruleId != "DASA-REACH-CRITICAL" || f.title.find("MmMapIoSpace") == std::string::npos) {
            continue;
        }
        for (const auto& chain : f.evidence) {
            for (const auto& step : chain) {
                if (step.label == "Data flow: the arguments are constants") {
                    found = true;
                    EXPECT_NE(step.detail.find("PhysicalAddress = 0x0"), std::string::npos) << step.detail;
                    EXPECT_NE(step.detail.find("NumberOfBytes = 0x1000"), std::string::npos) << step.detail;
                }
            }
        }
    }
    EXPECT_TRUE(found);
}

