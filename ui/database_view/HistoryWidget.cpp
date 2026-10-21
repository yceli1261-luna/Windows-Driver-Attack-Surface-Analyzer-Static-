#include "ui/database_view/HistoryWidget.h"

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <algorithm>

#include "core/database/AnalysisDatabase.h"
#include "ui/database_view/ComparisonHtml.h"
#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace {
constexpr int kIdRole = Qt::UserRole + 1;
constexpr int kPathRole = Qt::UserRole + 2;
constexpr int kSortRole = Qt::UserRole + 3;

// Sorts numerically instead of as text ("10" after "9").
class NumberItem : public QTableWidgetItem {
public:
    explicit NumberItem(qint64 v) : QTableWidgetItem(QString::number(v)) { setData(kSortRole, v); }
    bool operator<(const QTableWidgetItem& other) const override {
        return data(kSortRole).toLongLong() < other.data(kSortRole).toLongLong();
    }
};
} // namespace

HistoryWidget::HistoryWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    auto* top = new QHBoxLayout;
    top->setSpacing(8);
    m_header = new QLabel(this);
    // No word wrap: a wrapped label beside the buttons reports a tall minimum
    // height (wrapped at its narrowest), which pushed the window past the screen.
    m_header->setMinimumWidth(1);
    m_header->setTextInteractionFlags(Qt::TextSelectableByMouse);
    top->addWidget(m_header, 1);
    m_open = new QPushButton(tr("Open Driver"), this);
    m_compare = new QPushButton(tr("Compare"), this);
    m_export = new QPushButton(tr("Export JSON..."), this);
    m_delete = new QPushButton(tr("Delete"), this);
    m_open->setToolTip(tr("Analyze the selected driver file again"));
    m_compare->setToolTip(tr("Select two analyses (Ctrl+click) to compare them"));
    m_export->setToolTip(tr("Save the stored JSON report of the selected analysis"));
    m_delete->setToolTip(tr("Remove the selected analyses from the database"));
    for (auto* b : {m_open, m_compare, m_export, m_delete}) {
        top->addWidget(b);
    }
    layout->addLayout(top);

    m_table = new QTableWidget(0, 9, this);
    m_table->setHorizontalHeaderLabels({tr("#"), tr("Analyzed"), tr("File"), tr("Risk"), tr("Level"), tr("Model"),
                                        tr("Findings"), tr("IOCTLs"), tr("SHA-256")});
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(26);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setAlternatingRowColors(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_table->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
    m_table->setMinimumHeight(60);
    layout->addWidget(m_table, 1);

    connect(m_table, &QTableWidget::itemSelectionChanged, this, &HistoryWidget::updateButtons);
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        emit openDriverRequested(m_table->item(row, 0)->data(kPathRole).toString());
    });
    connect(m_open, &QPushButton::clicked, this, [this] {
        const auto rows = m_table->selectionModel()->selectedRows();
        if (rows.size() == 1) {
            emit openDriverRequested(m_table->item(rows.first().row(), 0)->data(kPathRole).toString());
        }
    });
    connect(m_compare, &QPushButton::clicked, this, [this] {
        const auto rows = m_table->selectionModel()->selectedRows();
        if (rows.size() == 2) {
            const qint64 a = idAt(rows[0].row());
            const qint64 b = idAt(rows[1].row());
            emit compareRequested(std::min(a, b), std::max(a, b));
        }
    });
    connect(m_export, &QPushButton::clicked, this, &HistoryWidget::exportSelected);
    connect(m_delete, &QPushButton::clicked, this, &HistoryWidget::deleteSelected);
    updateButtons();
}

void HistoryWidget::setDatabase(std::shared_ptr<core::database::AnalysisDatabase> db, const QString& location,
                                const QString& error) {
    m_db = std::move(db);
    m_location = location;
    if (!m_db) {
        m_header->setText(tr("<span style='color:#f1706b'>Analysis database unavailable</span> (%1): %2")
                              .arg(QDir::toNativeSeparators(location).toHtmlEscaped(), error.toHtmlEscaped()));
    }
    refresh();
}

qint64 HistoryWidget::idAt(int row) const {
    return m_table->item(row, 0)->data(kIdRole).toLongLong();
}

void HistoryWidget::refresh() {
    if (!m_db) {
        m_table->setRowCount(0);
        updateButtons();
        return;
    }
    std::vector<core::database::AnalysisSummary> rows;
    try {
        rows = m_db->list();
    } catch (const std::exception& ex) {
        m_header->setText(tr("Could not read the analysis database: %1")
                              .arg(QString::fromStdString(ex.what()).toHtmlEscaped()));
        return;
    }
    m_header->setText(tr("%1 stored analyses &middot; <span style='color:#9a9a9a'>%2</span>")
                          .arg(rows.size())
                          .arg(QDir::toNativeSeparators(m_location).toHtmlEscaped()));
    m_table->setSortingEnabled(false);
    m_table->clearSelection();
    m_table->setRowCount(static_cast<int>(rows.size()));
    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
        const auto& s = rows[static_cast<std::size_t>(i)];
        auto* id = new NumberItem(s.id);
        id->setData(kIdRole, static_cast<qlonglong>(s.id));
        id->setData(kPathRole, QString::fromStdString(s.filePath));
        m_table->setItem(i, 0, id);
        m_table->setItem(i, 1, new QTableWidgetItem(localTime(s.analyzedAt)));
        auto* file = new QTableWidgetItem(QString::fromStdString(s.fileName));
        file->setToolTip(QString::fromStdString(s.filePath));
        m_table->setItem(i, 2, file);
        m_table->setItem(i, 3, new NumberItem(s.riskScore));
        auto* level = new QTableWidgetItem(QString::fromStdString(s.riskLevel));
        level->setForeground(QBrush(riskLevelColor(level->text())));
        m_table->setItem(i, 4, level);
        m_table->setItem(i, 5, new QTableWidgetItem(QString::fromStdString(s.model)));
        m_table->setItem(i, 6, new NumberItem(s.findingCount));
        m_table->setItem(i, 7, new NumberItem(s.ioctlCount));
        m_table->setItem(i, 8, new QTableWidgetItem(QString::fromStdString(s.sha256)));
    }
    m_table->setSortingEnabled(true);
    m_table->sortByColumn(0, Qt::DescendingOrder);
    for (int c = 0; c < 8; ++c) {
        m_table->resizeColumnToContents(c);
    }
    updateButtons();
}

void HistoryWidget::updateButtons() {
    const auto n = m_table->selectionModel()->selectedRows().size();
    m_open->setEnabled(n == 1);
    m_compare->setEnabled(n == 2);
    m_export->setEnabled(n == 1);
    m_delete->setEnabled(n >= 1);
}

void HistoryWidget::exportSelected() {
    const auto rows = m_table->selectionModel()->selectedRows();
    if (rows.size() != 1 || !m_db) {
        return;
    }
    const qint64 id = idAt(rows.first().row());
    const auto json = m_db->reportJson(id);
    if (!json) {
        return;
    }
    const QString base = QFileInfo(m_table->item(rows.first().row(), 2)->text()).completeBaseName();
    const QString path = QFileDialog::getSaveFileName(this, tr("Export Stored Report"),
                                                      QStringLiteral("%1-analysis-%2.json").arg(base).arg(id),
                                                      tr("JSON (*.json)"));
    if (path.isEmpty()) {
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
        f.write(json->data(), static_cast<qint64>(json->size())) != static_cast<qint64>(json->size())) {
        QMessageBox::warning(this, tr("Export failed"), tr("Could not write %1: %2").arg(path, f.errorString()));
    }
}

void HistoryWidget::deleteSelected() {
    const auto rows = m_table->selectionModel()->selectedRows();
    if (rows.isEmpty() || !m_db) {
        return;
    }
    const QString question = rows.size() == 1
                                 ? tr("Delete this stored analysis? The driver file is not touched.")
                                 : tr("Delete %1 stored analyses? The driver files are not touched.").arg(rows.size());
    if (QMessageBox::question(this, tr("Delete analyses"), question) != QMessageBox::Yes) {
        return;
    }
    std::vector<qint64> ids;
    for (const auto& r : rows) {
        ids.push_back(idAt(r.row()));
    }
    try {
        for (auto id : ids) {
            m_db->remove(id);
        }
    } catch (const std::exception& ex) {
        QMessageBox::warning(this, tr("Delete failed"), QString::fromStdString(ex.what()));
    }
    refresh();
    emit historyChanged();
}

} // namespace dasa::ui
