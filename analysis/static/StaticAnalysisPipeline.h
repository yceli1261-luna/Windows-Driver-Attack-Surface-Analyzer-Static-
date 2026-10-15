#pragma once

#include <filesystem>
#include <memory>

#include "core/driver/DeviceObjects.h"
#include "core/driver/DriverModel.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/ioctl/IoctlExtractor.h"
#include "core/pe/PEImage.h"
#include "core/findings/Finding.h"
#include "core/security/KernelApiAnalyzer.h"

namespace dasa::analysis {

/// Everything the static pipeline produced for one driver. Immutable once
/// built and shared between the views, so it's handed around by
/// shared_ptr-to-const.
struct AnalysisResult {
    std::shared_ptr<const core::pe::PEImage> image;
    std::shared_ptr<const core::functions::FunctionSet> functions;
    std::shared_ptr<const core::driver::DriverAnalysis> driver;
    std::shared_ptr<const core::ioctl::IoctlAnalysis> ioctls;
    std::shared_ptr<const core::driver::DeviceAnalysis> devices;
    std::shared_ptr<const core::security::KernelApiAnalysis> kernelApis;
    std::shared_ptr<const core::findings::FindingsReport> findings;
    double parseSeconds = 0.0;
    double functionSeconds = 0.0;
    double driverSeconds = 0.0;
    double surfaceSeconds = 0.0; // IOCTLs, devices, kernel APIs
};

/// The single entry point for static analysis of a driver; the GUI (and a
/// future CLI) call this and nothing below it. Runs synchronously - callers
/// put it on a worker thread. Stages: PE parse, function discovery, driver
/// model and dispatch/callback recovery, IOCTLs and device objects, kernel
/// API risk and privileged instructions, findings and the risk score.
/// Throws core::pe::PEParseError if the file isn't a usable PE.
std::shared_ptr<const AnalysisResult> runStaticAnalysis(const std::filesystem::path& path);

} // namespace dasa::analysis
