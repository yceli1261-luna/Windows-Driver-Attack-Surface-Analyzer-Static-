#pragma once

class QApplication;

namespace dasa::app {

/// Applies the dark, professional-tool theme (QPalette + QSS) the product
/// brief asks for ("closer to IDA/Ghidra/Binary Ninja than a generic
/// dashboard"). A single static entry point so main() stays a one-liner;
/// grows a light-theme counterpart only if that's ever requested.
class ThemeManager {
public:
    static void applyDarkTheme(QApplication& app);
};

} // namespace dasa::app
