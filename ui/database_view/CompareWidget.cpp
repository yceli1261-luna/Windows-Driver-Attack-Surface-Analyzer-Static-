#include "ui/database_view/CompareWidget.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <algorithm>

#include "core/database/AnalysisDatabase.h"
#include "ui/database_view/ComparisonHtml.h"

namespace dasa::ui {

namespace db = core::database;

namespace {

QTextBrowser* makeView(QWidget* parent) {
    auto* view = new QTextBrowser(parent);
    view->setOpenLinks(false);
    view->setFrameShape(QFrame::NoFrame);
    view->setMinimumHeight(60);
    return view;
}

// Loads both analyses and renders their comparison, or explains why not.
QString renderComparison(db::AnalysisDatabase& database, qint64 a, qint64 b, const QString& aName, const QString& bName) {
    try {
        const auto sa = database.load(a);
        const auto sb = database.load(b);
        if (!sa || !sb) {
            return QObject::tr("<p>That analysis is no longer in the database.</p>");
        }
        return comparisonHtml(db::compare(*sa, *sb), aName, bName);
    } catch (const std::exception& ex) {
        return QObject::tr("<p>Could not read the analysis database: %1</p>")
            .arg(QString::fromStdString(ex.what()).toHtmlEscaped());
    }
}

} // namespace

CompareWidget::CompareWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    auto* pick = new QHBoxLayout;
    pick->setSpacing(8);
    m_a = new QComboBox(this);
    m_b = new QComboBox(this);
    m_a->setMinimumContentsLength(28);
    m_b->setMinimumContentsLength(28);
    pick->addWidget(new QLabel(tr("A (baseline)"), this));
    pick->addWidget(m_a, 1);
    pick->addSpacing(12);
    pick->addWidget(new QLabel(tr("B"), this));
    pick->addWidget(m_b, 1);
    layout->addLayout(pick);

    m_view = makeView(this);
    layout->addWidget(m_view, 1);

    connect(m_a, &QComboBox::currentIndexChanged, this, &CompareWidget::showComparison);
    connect(m_b, &QComboBox::currentIndexChanged, this, &CompareWidget::showComparison);
}

void CompareWidget::setDatabase(std::shared_ptr<db::AnalysisDatabase> database) {
    m_db = std::move(database);
    refresh();
}

void CompareWidget::refresh() {
    const QVariant keepA = m_a->currentData();
    const QVariant keepB = m_b->currentData();
    std::vector<db::AnalysisSummary> rows;
    if (m_db) {
        try {
            rows = m_db->list();
        } catch (const std::exception&) {
            rows.clear();
        }
    }
    for (QComboBox* box : {m_a, m_b}) {
        const QSignalBlocker block(box);
        box->clear();
        for (const auto& s : rows) {
            box->addItem(analysisLabel(s), static_cast<qlonglong>(s.id));
        }
    }
    const auto restore = [](QComboBox* box, const QVariant& id, int fallback) {
        const QSignalBlocker block(box);
        const int i = id.isValid() ? box->findData(id) : -1;
        box->setCurrentIndex(i >= 0 ? i : std::min(fallback, box->count() - 1));
    };
    // Default: the second-newest as baseline against the newest.
    restore(m_a, keepA, 1);
    restore(m_b, keepB, 0);
    showComparison();
}

void CompareWidget::compare(qint64 olderId, qint64 newerId) {
    refresh();
    {
        const QSignalBlocker ba(m_a);
        const QSignalBlocker bb(m_b);
        m_a->setCurrentIndex(m_a->findData(static_cast<qlonglong>(olderId)));
        m_b->setCurrentIndex(m_b->findData(static_cast<qlonglong>(newerId)));
    }
    showComparison();
}

void CompareWidget::showComparison() {
    if (!m_db) {
        m_view->setHtml(tr("<p>The analysis database is unavailable; see Analysis History.</p>"));
        return;
    }
    if (m_a->count() < 2) {
        m_view->setHtml(tr("<p>Analyze at least two drivers (or two versions of one) to compare them. Every "
                           "analysis is saved automatically.</p>"));
        return;
    }
    const qint64 a = m_a->currentData().toLongLong();
    const qint64 b = m_b->currentData().toLongLong();
    if (a == b) {
        m_view->setHtml(tr("<p>Pick two different analyses.</p>"));
        return;
    }
    m_view->setHtml(renderComparison(*m_db, a, b, tr("A (#%1)").arg(a), tr("B (#%1)").arg(b)));
}

// ------------------------------------------------------------------------

PreviousFindingsWidget::PreviousFindingsWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    auto* top = new QHBoxLayout;
    top->setSpacing(8);
    m_header = new QLabel(this);
    m_header->setMinimumWidth(1); // unwrapped; see HistoryWidget
    top->addWidget(m_header, 1);
    m_earlier = new QComboBox(this);
    m_earlier->setMinimumContentsLength(28);
    top->addWidget(m_earlier);
    layout->addLayout(top);

    m_view = makeView(this);
    layout->addWidget(m_view, 1);

    connect(m_earlier, &QComboBox::currentIndexChanged, this, &PreviousFindingsWidget::showComparison);
    clear();
}

void PreviousFindingsWidget::setDatabase(std::shared_ptr<db::AnalysisDatabase> database) {
    m_db = std::move(database);
}

void PreviousFindingsWidget::clear() {
    m_currentId = 0;
    const QSignalBlocker block(m_earlier);
    m_earlier->clear();
    m_earlier->setVisible(false);
    m_header->setText(tr("No driver loaded."));
    m_view->clear();
}

void PreviousFindingsWidget::showFor(qint64 currentId, const QString& sha256, const QString& fileName) {
    clear();
    m_currentId = currentId;
    if (!m_db || currentId <= 0) {
        m_header->setText(tr("This analysis wasn't saved, so there is nothing to compare it with."));
        return;
    }
    std::vector<db::AnalysisSummary> earlier;
    try {
        earlier = m_db->history(sha256.toStdString(), fileName.toStdString(), currentId);
    } catch (const std::exception& ex) {
        m_header->setText(tr("Could not read the analysis database: %1").arg(QString::fromStdString(ex.what())));
        return;
    }
    if (earlier.empty()) {
        m_header->setText(tr("First analysis of %1 - nothing earlier to compare with.").arg(fileName));
        return;
    }
    m_header->setText(tr("%1 earlier analyses of %2 (same SHA-256 or file name). Compare with:")
                          .arg(earlier.size())
                          .arg(fileName));
    {
        const QSignalBlocker block(m_earlier);
        for (const auto& s : earlier) {
            QString label = analysisLabel(s);
            if (s.sha256 != sha256.toStdString()) {
                label += tr("  (different file)");
            }
            m_earlier->addItem(label, static_cast<qlonglong>(s.id));
        }
        m_earlier->setCurrentIndex(0);
        m_earlier->setVisible(true);
    }
    showComparison();
}

void PreviousFindingsWidget::showComparison() {
    if (!m_db || m_currentId <= 0 || m_earlier->count() == 0) {
        return;
    }
    const qint64 earlier = m_earlier->currentData().toLongLong();
    m_view->setHtml(renderComparison(*m_db, earlier, m_currentId, tr("Earlier (#%1)").arg(earlier),
                           tr("Current (#%1)").arg(m_currentId)));
}

} // namespace dasa::ui
