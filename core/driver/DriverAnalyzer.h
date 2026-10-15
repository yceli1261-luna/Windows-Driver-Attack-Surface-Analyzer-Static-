#pragma once

#include "core/driver/DriverModel.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/pe/PEImage.h"

namespace dasa::core::driver {

/// Classifies the driver model and recovers how the driver registers its
/// request handlers. Built on the Phase 3 function set and the value
/// tracker (ValueTracker.h), not on fixed byte windows.
///
/// What it does:
///   - Model: framework imports (WDFLDR!WdfVersionBind, FLTMGR!
///     FltRegisterFilter, NDIS/Storport/ScsiPort/HID/KS registration
///     calls), the WDF_BIND_INFO structure and observed WDF function-table
///     calls for KMDF; recovered MajorFunction[] stores for WDM.
///   - DriverEntry: steps from the PE entry point through stubs that only
///     forward (DriverObject, RegistryPath) - GsDriverEntry, and for KMDF
///     FxDriverEntry/FxDriverEntryWorker past the WdfVersionBind call.
///   - WDM: tracks DriverObject from DriverEntry, following calls that pass
///     it on (depth 3), and records stores to MajorFunction[] (direct,
///     indexed loops, rep stos), DriverUnload, DriverStartIo and
///     DriverExtension->AddDevice.
///   - KMDF: finds WdfFunctions_01xxx via WDF_BIND_INFO, labels every call
///     through the function table (direct, `call [rax+i*8]`, or via the
///     CFG dispatch thunk), and reads WDF_DRIVER_CONFIG / WDF_IO_QUEUE_CONFIG
///     from the stack at WdfDriverCreate / WdfIoQueueCreate calls to recover
///     EvtDriverDeviceAdd and the EvtIo* callbacks with each queue's
///     dispatch type.
///
/// Limitations (reported in DriverAnalysis::notes where they apply):
///   - Value tracking is per function and flow-insensitive; values that
///     differ per branch, or configs built in a helper and passed by
///     pointer from another function, are not resolved.
///   - KMDF callback recovery is x64 only; on x86 the model and WDF calls
///     are still reported.
///   - Port/miniport frameworks (NDIS, Storport, Filter Manager, ...) are
///     identified, but their callback structures are not decoded yet.
DriverAnalysis analyzeDriver(const pe::PEImage& image, const functions::FunctionSet& functions);

} // namespace dasa::core::driver
