#include "ui/graph_view/GraphUtil.h"

#include <QBoxLayout>
#include <QToolButton>

#include <algorithm>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "ui/graph_view/GraphView.h"

namespace dasa::ui {

QString hex8(std::uint64_t value) {
    return QStringLiteral("%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
}

QString hexRva(std::uint64_t value) {
    return QStringLiteral("0x") + hex8(value);
}

std::string importShortName(const std::string& importName) {
    const auto bang = importName.find('!');
    return bang == std::string::npos ? importName : importName.substr(bang + 1);
}

const core::functions::Function* functionContaining(const core::functions::FunctionSet& set, std::uint64_t rva) {
    if (const auto* f = set.find(rva)) {
        return f;
    }
    for (const auto& f : set.functions) {
        if (rva < f.lowRva || rva >= f.highRva) {
            continue;
        }
        const bool covered = std::any_of(f.instructions.begin(), f.instructions.end(),
                                         [&](const auto& i) { return rva >= i.rva && rva < i.endRva(); });
        if (covered) {
            return &f;
        }
    }
    return nullptr;
}

std::optional<std::uint64_t> findFunction(const analysis::AnalysisResult& result, const QString& text) {
    const auto& set = *result.functions;
    const QString t = text.trimmed();
    if (t.isEmpty()) {
        return std::nullopt;
    }
    for (const auto& f : set.functions) {
        if (QString::fromStdString(f.name) == t) {
            return f.rva;
        }
    }
    for (const auto& f : set.functions) {
        if (QString::fromStdString(f.name).compare(t, Qt::CaseInsensitive) == 0) {
            return f.rva;
        }
    }
    for (const auto& [role, rva] : result.kernelApis->entryPointFunctions) {
        if (QString::fromStdString(role).compare(t, Qt::CaseInsensitive) == 0) {
            return rva;
        }
    }
    QString digits = t;
    if (digits.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)) {
        digits = digits.mid(2);
    } else if (digits.startsWith(QLatin1String("sub_"), Qt::CaseInsensitive)) {
        digits = digits.mid(4);
    }
    bool ok = false;
    const std::uint64_t rva = digits.toULongLong(&ok, 16);
    if (ok) {
        if (const auto* f = functionContaining(set, rva)) {
            return f->rva;
        }
    }
    return std::nullopt;
}

std::optional<std::uint64_t> defaultFunction(const analysis::AnalysisResult& r) {
    const auto& set = *r.functions;
    if (r.driver->driverEntry && set.find(*r.driver->driverEntry)) {
        return *r.driver->driverEntry;
    }
    if (set.find(r.image->entryPointRva)) {
        return r.image->entryPointRva;
    }
    if (!set.functions.empty()) {
        return set.functions.front().rva;
    }
    return std::nullopt;
}

void addZoomButtons(QBoxLayout* layout, GraphView* view, QWidget* parent) {
    const struct {
        const char* text;
        const char* tip;
        void (GraphView::*slot)();
    } buttons[] = {
        {"Fit", "Fit the whole graph in the view", &GraphView::fitAll},
        {"100%", "Actual size", &GraphView::zoomReset},
        {"−", "Zoom out (or mouse wheel)", &GraphView::zoomOut},
        {"+", "Zoom in (or mouse wheel)", &GraphView::zoomIn},
    };
    for (const auto& b : buttons) {
        auto* button = new QToolButton(parent);
        button->setText(QString::fromUtf8(b.text));
        button->setToolTip(QObject::tr(b.tip));
        button->setMinimumWidth(36);
        QObject::connect(button, &QToolButton::clicked, view, b.slot);
        layout->addWidget(button);
    }
}

} // namespace dasa::ui
