#pragma once

#include "core/driver/DeviceObjects.h"
#include "core/dataflow/TaintAnalyzer.h"
#include "core/driver/DriverModel.h"
#include "core/findings/Finding.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/ioctl/IoctlExtractor.h"
#include "core/pe/PEImage.h"
#include "core/security/KernelApiAnalyzer.h"

namespace dasa::analysis {

struct FindingInputs {
    const core::pe::PEImage& image;
    const core::functions::FunctionSet& functions;
    const core::driver::DriverAnalysis& driver;
    const core::ioctl::IoctlAnalysis& ioctls;
    const core::driver::DeviceAnalysis& devices;
    const core::security::KernelApiAnalysis& kernelApis;
    const core::dataflow::DataFlowAnalysis& dataflow;
};

/// Turns the static analysis results into findings with evidence chains
/// and scores them. Rules (ruleId):
///
///   DASA-REACH-CRITICAL / DASA-REACH-HIGH
///       A critical/high kernel API or privileged instruction is reachable
///       through the call graph from a user-request handler
///       (IRP_MJ_DEVICE_CONTROL / READ / WRITE, EvtIoDeviceControl / Read /
///       Write / Default). Chain: user-mode name -> handler -> IOCTL codes
///       compared on the path -> call path -> the call. Severity drops one
///       level when no user-mode-openable name or interface was recovered.
///   DASA-REACH-INTERNAL
///       Same, from IRP_MJ_INTERNAL_DEVICE_CONTROL / EvtIoInternalDevice
///       Control only (kernel-mode senders).
///   DASA-DEVICE-NO-SECURE-OPEN, DASA-DEVICE-DEFAULT-ACL,
///   DASA-UNPROTECTED-SYMLINK
///       Device object security as created in code.
///   DASA-METHOD-NEITHER, DASA-ANY-ACCESS
///       IOCTL transfer method / access requirements.
///   DASA-RUNTIME-RESOLVED, DASA-SYSTEM-CALLBACKS
///       Capability hidden from imports; system-wide monitoring.
///   DASA-WX-SECTION, DASA-NO-NX, DASA-NO-ASLR, DASA-NO-EMBEDDED-SIGNATURE
///       Image hardening.
///   DASA-UNCALLED-CRITICAL-IMPORT
///       Critical API imported with no call site found (low confidence).
///   DASA-TAINT-API, DASA-TAINT-INSTRUCTION, DASA-TAINT-WRITE,
///   DASA-TAINT-READ, DASA-UNPROBED-USER-POINTER
///       Request data traced (core/dataflow) into a sensitive API argument,
///       a privileged instruction, or the address of a memory access.
///       Chain: user-mode name -> handler -> IOCTL whose case leads there ->
///       where each value was read -> call path -> the operation.
///
/// DASA-REACH-* say the dangerous call can be reached from a user request;
/// their evidence notes what data flow found at that call (arguments that
/// are constants, or a DASA-TAINT finding).
core::findings::FindingsReport generateFindings(const FindingInputs& in);

} // namespace dasa::analysis
