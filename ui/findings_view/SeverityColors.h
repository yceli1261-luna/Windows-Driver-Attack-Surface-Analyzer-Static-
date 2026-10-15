#pragma once

#include <QColor>
#include <QString>

#include "core/findings/Finding.h"

namespace dasa::ui {

inline QColor severityColor(core::findings::Severity s) {
    switch (s) {
    case core::findings::Severity::Critical: return QColor(0xF1, 0x70, 0x6B);
    case core::findings::Severity::High: return QColor(0xE5, 0xA5, 0x4B);
    case core::findings::Severity::Medium: return QColor(0xD8, 0xC8, 0x6A);
    case core::findings::Severity::Low: return QColor(0x7F, 0xB2, 0xE5);
    case core::findings::Severity::Info: break;
    }
    return QColor(0xB0, 0xB0, 0xB0);
}

inline QColor riskLevelColor(const QString& level) {
    if (level == QLatin1String("Critical")) return severityColor(core::findings::Severity::Critical);
    if (level == QLatin1String("High")) return severityColor(core::findings::Severity::High);
    if (level == QLatin1String("Medium")) return severityColor(core::findings::Severity::Medium);
    if (level == QLatin1String("Low")) return severityColor(core::findings::Severity::Low);
    return QColor(0x6C, 0xC6, 0x8A);
}

} // namespace dasa::ui
