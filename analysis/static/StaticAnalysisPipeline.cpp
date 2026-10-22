#include "analysis/static/StaticAnalysisPipeline.h"

#include <chrono>

#include <spdlog/spdlog.h>

#include "analysis/heuristics/FindingRules.h"
#include "core/driver/DriverAnalyzer.h"
#include "core/pe/PEParser.h"

namespace dasa::analysis {

namespace {

double secondsSince(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

} // namespace

std::shared_ptr<const AnalysisResult> runStaticAnalysis(const std::filesystem::path& path) {
    auto result = std::make_shared<AnalysisResult>();

    auto start = std::chrono::steady_clock::now();
    auto image = std::make_shared<const core::pe::PEImage>(core::pe::parsePE(path));
    result->parseSeconds = secondsSince(start);

    start = std::chrono::steady_clock::now();
    result->functions =
        std::make_shared<const core::functions::FunctionSet>(core::functions::discoverFunctions(*image));
    result->functionSeconds = secondsSince(start);

    start = std::chrono::steady_clock::now();
    result->driver = std::make_shared<const core::driver::DriverAnalysis>(
        core::driver::analyzeDriver(*image, *result->functions));
    result->driverSeconds = secondsSince(start);

    start = std::chrono::steady_clock::now();
    result->ioctls = std::make_shared<const core::ioctl::IoctlAnalysis>(
        core::ioctl::extractIoctls(*image, *result->functions, *result->driver));
    result->devices = std::make_shared<const core::driver::DeviceAnalysis>(
        core::driver::analyzeDevices(*image, *result->functions, *result->driver));
    result->kernelApis = std::make_shared<const core::security::KernelApiAnalysis>(
        core::security::analyzeKernelApis(*image, *result->functions, *result->driver, *result->ioctls));
    result->dataflow = std::make_shared<const core::dataflow::DataFlowAnalysis>(
        core::dataflow::analyzeDataFlow(*image, *result->functions, *result->driver, *result->ioctls));
    result->findings = std::make_shared<const core::findings::FindingsReport>(generateFindings(
        FindingInputs{*image, *result->functions, *result->driver, *result->ioctls, *result->devices,
                      *result->kernelApis, *result->dataflow}));
    result->surfaceSeconds = secondsSince(start);
    result->image = std::move(image);

    spdlog::info("Static analysis of {}: parse {:.3f}s, functions {:.3f}s, driver model {:.3f}s, "
                 "IOCTLs/devices {:.3f}s",
                 result->image->fileName, result->parseSeconds, result->functionSeconds,
                 result->driverSeconds, result->surfaceSeconds);
    return result;
}

} // namespace dasa::analysis
