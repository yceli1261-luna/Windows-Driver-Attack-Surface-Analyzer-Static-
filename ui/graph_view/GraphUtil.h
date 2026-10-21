#pragma once

#include <QString>

#include <cstdint>
#include <optional>
#include <string>

#include "core/functions/FunctionDiscoverer.h"

class QBoxLayout;
class QWidget;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

class GraphView;

/// "00001312"
QString hex8(std::uint64_t value);
/// "0x00001312"
QString hexRva(std::uint64_t value);
/// "ntoskrnl.exe!IoCreateDevice" -> "IoCreateDevice"
std::string importShortName(const std::string& importName);

/// The function starting at `rva`, else the one whose instructions cover it.
const core::functions::Function* functionContaining(const core::functions::FunctionSet& set, std::uint64_t rva);
/// Parses a function name (exact, then case-insensitive), an entry-point
/// role ("DriverEntry", "IRP_MJ_DEVICE_CONTROL", ...) or a hex RVA.
std::optional<std::uint64_t> findFunction(const analysis::AnalysisResult& result, const QString& text);
/// DriverEntry when known, else the entry point's function, else the first function.
std::optional<std::uint64_t> defaultFunction(const analysis::AnalysisResult& result);

/// Adds Fit / 100% / - / + buttons for `view` to `layout`.
void addZoomButtons(QBoxLayout* layout, GraphView* view, QWidget* parent);

} // namespace dasa::ui
