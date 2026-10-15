#include "app/ThemeManager.h"

#include <QApplication>
#include <QFile>
#include <QPalette>
#include <QStyleFactory>
#include <spdlog/spdlog.h>

namespace dasa::app {

void ThemeManager::applyDarkTheme(QApplication& app) {
    app.setStyle(QStyleFactory::create("Fusion"));

    // Base palette: dark neutral grays with a desaturated blue accent,
    // close to the Ghidra/IDA-style tool palette the brief asks for rather
    // than a generic dark-mode inversion.
    QPalette palette;
    const QColor windowColor(37, 37, 38);
    const QColor baseColor(30, 30, 30);
    const QColor altBaseColor(45, 45, 48);
    const QColor textColor(220, 220, 220);
    const QColor disabledTextColor(127, 127, 127);
    const QColor accentColor(14, 99, 156);

    palette.setColor(QPalette::Window, windowColor);
    palette.setColor(QPalette::WindowText, textColor);
    palette.setColor(QPalette::Base, baseColor);
    palette.setColor(QPalette::AlternateBase, altBaseColor);
    palette.setColor(QPalette::ToolTipBase, windowColor);
    palette.setColor(QPalette::ToolTipText, textColor);
    palette.setColor(QPalette::Text, textColor);
    palette.setColor(QPalette::Disabled, QPalette::Text, disabledTextColor);
    palette.setColor(QPalette::Button, windowColor);
    palette.setColor(QPalette::ButtonText, textColor);
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, disabledTextColor);
    palette.setColor(QPalette::BrightText, Qt::red);
    palette.setColor(QPalette::Link, accentColor);
    palette.setColor(QPalette::Highlight, accentColor);
    palette.setColor(QPalette::HighlightedText, Qt::white);

    app.setPalette(palette);

    QFile qss(":/qss/dark_theme.qss");
    if (qss.open(QFile::ReadOnly | QFile::Text)) {
        app.setStyleSheet(QString::fromUtf8(qss.readAll()));
        qss.close();
    } else {
        spdlog::warn("ThemeManager: could not load :/qss/dark_theme.qss; using palette only");
    }
}

} // namespace dasa::app
