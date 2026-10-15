#include "analysis/static/StaticAnalysisPipeline.h"

#include <chrono>

#include <spdlog/spdlog.h>

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
    result->image = std::move(image);

    spdlog::info("Static analysis of {}: parse {:.3f}s, functions {:.3f}s",
                 result->image->fileName, result->parseSeconds, result->functionSeconds);
    return result;
}

} // namespace dasa::analysis
