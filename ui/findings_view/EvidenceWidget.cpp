#include "ui/findings_view/EvidenceWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace fnd = dasa::core::findings;

namespace {

constexpr int kFunctionRole = Qt::UserRole + 1;

QString kindName(fnd::EvidenceStep::Kind k) {
    using K = fnd::EvidenceStep::Kind;
    switch (k) {
    case K::UserModeName: return QObject::tr("User-mode name");
    case K::Device: return QObject::tr("Device");
    case K::EntryPoint: return QObject::tr("Entry point");
    case K::Ioctl: return QObject::tr("IOCTL");
    case K::Function: return QObject::tr("Function");
    case K::Call: return QObject::tr("Call");
    case K::Instruction: return QObject::tr("Instruction");
    case K::Header: return QObject::tr("PE header");
    case K::Note: break;
    }
    return QObject::tr("Note");
}

QString hex(std::uint64_t v) {
    return QStringLiteral("0x") + QString::number(v, 16).toUpper().rightJustified(8, QLatin1Char('0'));
}

} // namespace

EvidenceWidget::EvidenceWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    m_title = new QLabel(this);
    m_title->setTextFormat(Qt::RichText);
    m_title->setWordWrap(true);
    layout->addWidget(m_title);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(4);
    m_tree->setHeaderLabels({tr("Step"), tr("What"), tr("Detail"), tr("Address")});
    m_tree->setAlternatingRowColors(true);
    m_tree->setUniformRowHeights(true);
    m_tree->setToolTip(tr("Double-click a step to open its function"));
    layout->addWidget(m_tree, 1);

    connect(m_tree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int) {
        const QVariant v = item->data(0, kFunctionRole);
        if (v.isValid()) {
            emit functionActivated(v.toULongLong());
        }
    });
    clear();
}

void EvidenceWidget::clear() {
    m_result.reset();
    m_tree->clear();
    m_title->setText(tr("<h3>No finding selected</h3>"));
}

void EvidenceWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_tree->clear();
    m_title->setText(tr("<h3>Select a finding in the Findings tab</h3>"));
}

void EvidenceWidget::showFinding(int index) {
    m_tree->clear();
    if (!m_result || index < 0 || index >= static_cast<int>(m_result->findings->findings.size())) {
        m_title->setText(tr("<h3>No finding selected</h3>"));
        return;
    }
    const fnd::Finding& f = m_result->findings->findings[static_cast<std::size_t>(index)];
    m_title->setText(tr("<span style='font-size:13pt; font-weight:600'>%1</span>&nbsp;&nbsp;"
                        "<span style='color:%2'>%3</span>")
                         .arg(QString::fromStdString(f.title).toHtmlEscaped(), severityColor(f.severity).name(),
                              QString::fromLatin1(fnd::severityName(f.severity))));
    int n = 1;
    for (const auto& chain : f.evidence) {
        auto* top = new QTreeWidgetItem(m_tree, {tr("Chain %1").arg(n++)});
        QFont bold = top->font(0);
        bold.setBold(true);
        top->setFont(0, bold);
        top->setFirstColumnSpanned(true);
        int step = 1;
        for (const auto& s : chain) {
            auto* item = new QTreeWidgetItem(top, {QStringLiteral("%1. %2").arg(step++).arg(kindName(s.kind)),
                                                   QString::fromStdString(s.label), QString::fromStdString(s.detail),
                                                   s.rva ? hex(*s.rva) : QString()});
            for (int c = 0; c < 4; ++c) {
                item->setToolTip(c, item->text(c));
            }
            if (s.function) {
                item->setData(0, kFunctionRole, QVariant::fromValue<qulonglong>(*s.function));
            }
        }
        top->setExpanded(true);
    }
    for (int c = 0; c < 4; ++c) {
        m_tree->resizeColumnToContents(c);
    }
}

} // namespace dasa::ui
