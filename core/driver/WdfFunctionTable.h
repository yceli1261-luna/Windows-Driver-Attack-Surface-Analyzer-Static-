#pragma once

#include <cstddef>

namespace dasa::core::driver {

// KMDF DDIs are called through a per-driver pointer to the framework's
// function table (WdfFunctions_01xxx), indexed by WDFFUNCENUM. These are the
// indices the analyzers care about; wdfFunctionName() names the rest.
// Values are from wdffuncenum.h (see WdfFunctionTable.cpp).
namespace wdf_index {
inline constexpr std::size_t kDeviceInitSetIoType = 61;
inline constexpr std::size_t kDeviceCreate = 75;
inline constexpr std::size_t kDeviceCreateDeviceInterface = 77;
inline constexpr std::size_t kDriverCreate = 116;
inline constexpr std::size_t kIoQueueCreate = 152;
} // namespace wdf_index

/// Name of the KMDF DDI at `index` in the function table (e.g.
/// "WdfIoQueueCreate"), or nullptr if out of range.
const char* wdfFunctionName(std::size_t index);
std::size_t wdfFunctionCount();

} // namespace dasa::core::driver
