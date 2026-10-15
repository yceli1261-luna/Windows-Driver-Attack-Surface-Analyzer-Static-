#include "ui/findings_view/FindingsWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QScrollArea>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace fnd = dasa::core::findings;

namespace {
constexpr int kIndexRole = Qt::UserRole + 1;
}

FindingsWidget::FindingsWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(10);

    m_score = new QLabel(this);
    m_score->setTextFormat(Qt::RichText);
    m_score->setWordWrap(true);
    layout->addWidget(m_score);

    auto* splitter = new QSplitter(Qt::Horizontal, this);
    m_table = new QTableWidget(0, 4, splitter);
    m_table->setHorizontalHeaderLabels({tr("Severity"), tr("Finding"), tr("Category"), tr("Confidence")});
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(28);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    auto* detailScroll = new QScrollArea(splitter);
    detailScroll->setWidgetResizable(true);
    detailScroll->setFrameShape(QFrame::NoFrame);
    m_detail = new QLabel(detailScroll);
    m_detail->setTextFormat(Qt::RichText);
    m_detail->setWordWrap(true);
    m_detail->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    m_detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_detail->setMargin(12);
    detailScroll->setWidget(m_detail);

    splitter->addWidget(m_table);
    splitter->addWidget(detailScroll);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    splitter->setSizes({600, 400});
    layout->addWidget(splitter, 1);

    connect(m_table, &QTableWidget::currentCellChanged, this, [this](int row, int, int, int) {
        const QTableWidgetItem* item = row >= 0 ? m_table->item(row, 0) : nullptr;
        const int index = item ? item->data(kIndexRole).toInt() : -1;
        showDetail(index);
        emit findingSelected(index);
    });
    clear();
}

void FindingsWidget::clear() {
    m_result.reset();
    m_table->setRowCount(0);
    m_score->setText(tr("<h3>No driver loaded</h3>"));
    m_detail->clear();
}

void FindingsWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    const fnd::FindingsReport& r = *m_result->findings;

    QStringList counts;
    for (auto s : {fnd::Severity::Critical, fnd::Severity::High, fnd::Severity::Medium, fnd::Severity::Low,
                   fnd::Severity::Info}) {
        if (const int n = r.count(s)) {
            counts << QStringLiteral("<span style='color:%1'>%2 %3</span>")
                          .arg(severityColor(s).name())
                          .arg(n)
                          .arg(QString::fromLatin1(fnd::severityName(s)).toLower());
        }
    }
    m_score->setText(
        tr("<span style='font-size:20pt; font-weight:600; color:%1'>%2</span>"
           "<span style='font-size:12pt; color:#9a9a9a'>/100</span>&nbsp;&nbsp;"
           "<span style='font-size:14pt; color:%1'>%3 risk</span>&nbsp;&nbsp;&nbsp;%4"
           "<br><span style='color:#9a9a9a'>A weighted sum of the findings for triage - not a measure of "
           "exploitability. Select a finding to see its evidence in the Evidence tab.</span>")
            .arg(riskLevelColor(QString::fromStdString(r.risk.level)).name())
            .arg(r.risk.score)
            .arg(QString::fromStdString(r.risk.level))
            .arg(counts.isEmpty() ? tr("no findings") : counts.join(QStringLiteral(" &middot; "))));

    m_table->setRowCount(static_cast<int>(r.findings.size()));
    for (int i = 0; i < static_cast<int>(r.findings.size()); ++i) {
        const auto& f = r.findings[static_cast<std::size_t>(i)];
        auto* sev = new QTableWidgetItem(QString::fromLatin1(fnd::severityName(f.severity)));
        sev->setForeground(QBrush(severityColor(f.severity)));
        sev->setData(kIndexRole, i);
        m_table->setItem(i, 0, sev);
        auto* title = new QTableWidgetItem(QString::fromStdString(f.title));
        title->setToolTip(title->text());
        m_table->setItem(i, 1, title);
        m_table->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(f.category)));
        m_table->setItem(i, 3, new QTableWidgetItem(QString::fromLatin1(fnd::confidenceName(f.confidence))));
    }
    m_table->resizeColumnToContents(0);
    m_table->resizeColumnToContents(2);
    m_table->resizeColumnToContents(3);
    if (!r.findings.empty()) {
        m_table->setCurrentCell(0, 0);
    } else {
        QStringList notes;
        for (const auto& n : r.notes) {
            notes << QString::fromStdString(n).toHtmlEscaped();
        }
        m_detail->setText(tr("<p>No findings.</p>") + notes.join(QStringLiteral("<br>")));
    }
}

void FindingsWidget::showDetail(int index) {
    if (!m_result || index < 0) {
        m_detail->clear();
        return;
    }
    const auto& f = m_result->findings->findings[static_cast<std::size_t>(index)];
    m_detail->setText(
        tr("<p style='font-size:13pt; font-weight:600'>%1</p>"
           "<p><span style='color:%2'>%3</span> &middot; %4 &middot; %5 confidence &middot; "
           "<span style='color:#9a9a9a'>%6</span></p>"
           "<p>%7</p><p><b>Recommendation.</b> %8</p>"
           "<p style='color:#9a9a9a'>%9 evidence chain(s) - see the Evidence tab.</p>")
            .arg(QString::fromStdString(f.title).toHtmlEscaped(), severityColor(f.severity).name(),
                 QString::fromLatin1(fnd::severityName(f.severity)), QString::fromStdString(f.category),
                 QString::fromLatin1(fnd::confidenceName(f.confidence)), QString::fromStdString(f.ruleId),
                 QString::fromStdString(f.description).toHtmlEscaped(),
                 QString::fromStdString(f.recommendation).toHtmlEscaped())
            .arg(f.evidence.size()));
}

} // namespace dasa::ui
