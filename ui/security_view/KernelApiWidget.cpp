#include "ui/security_view/KernelApiWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QMap>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::ui {

namespace sec = dasa::core::security;

namespace {

constexpr int kRvaRole = Qt::UserRole + 1;

QColor riskColor(sec::ApiRisk r) {
    switch (r) {
    case sec::ApiRisk::Critical: return QColor(0xF1, 0x70, 0x6B);
    case sec::ApiRisk::High: return QColor(0xE5, 0xA5, 0x4B);
    case sec::ApiRisk::Medium: return QColor(0xD8, 0xC8, 0x6A);
    case sec::ApiRisk::Info: break;
    }
    return QColor(0xB0, 0xB0, 0xB0);
}

QString hex(std::uint64_t v) {
    return QStringLiteral("0x") + QString::number(v, 16).toUpper().rightJustified(8, QLatin1Char('0'));
}

QString joinSet(const std::set<std::string>& s) {
    QStringList out;
    for (const auto& x : s) {
        out << QString::fromStdString(x);
    }
    return out.join(QStringLiteral(", "));
}

QTreeWidgetItem* section(QTreeWidget* tree, const QString& title, bool expanded) {
    auto* item = new QTreeWidgetItem(tree);
    item->setText(0, title);
    QFont f = item->font(0);
    f.setBold(true);
    item->setFont(0, f);
    item->setFirstColumnSpanned(true);
    item->setExpanded(expanded);
    return item;
}

} // namespace

KernelApiWidget::KernelApiWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::RichText);
    m_summary->setWordWrap(true);
    layout->addWidget(m_summary);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(5);
    m_tree->setHeaderLabels({tr("API / instruction"), tr("Category"), tr("Why it matters"), tr("Called from"),
                             tr("Reachable from")});
    m_tree->setAlternatingRowColors(true);
    m_tree->setUniformRowHeights(true);
    m_tree->setToolTip(tr("Double-click a row to open the first function that uses it"));
    layout->addWidget(m_tree, 1);

    m_notes = new QLabel(this);
    m_notes->setTextFormat(Qt::RichText);
    m_notes->setWordWrap(true);
    m_notes->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_notes);

    connect(m_tree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int) {
        const QVariant v = item->data(0, kRvaRole);
        if (v.isValid()) {
            emit functionActivated(v.toULongLong());
        }
    });
    clear();
}

void KernelApiWidget::clear() {
    m_tree->clear();
    m_summary->clear();
    m_notes->clear();
}

void KernelApiWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_tree->clear();
    const sec::KernelApiAnalysis& a = *result->kernelApis;
    const auto& fns = *result->functions;
    auto fnName = [&](std::uint64_t rva) {
        const auto* f = fns.find(rva);
        return f ? QString::fromStdString(f->name) : hex(rva);
    };

    int counts[4] = {0, 0, 0, 0};
    int reachableRisky = 0;
    for (const auto& u : a.apis) {
        counts[static_cast<int>(u.info.risk)]++;
        if (u.info.risk >= sec::ApiRisk::High && !u.reachableFrom.empty()) {
            ++reachableRisky;
        }
    }
    m_summary->setText(
        tr("<span style='color:%1'>%2 critical</span> &middot; <span style='color:%3'>%4 high</span> &middot; "
           "<span style='color:%5'>%6 medium</span> APIs, <b>%7</b> of the critical/high ones reachable from an "
           "entry point; <span style='color:%1'>%8 privileged instructions</span>.")
            .arg(riskColor(sec::ApiRisk::Critical).name())
            .arg(counts[3])
            .arg(riskColor(sec::ApiRisk::High).name())
            .arg(counts[2])
            .arg(riskColor(sec::ApiRisk::Medium).name())
            .arg(counts[1])
            .arg(reachableRisky)
            .arg(a.privileged.size()));

    auto addApi = [&](QTreeWidgetItem* parent, const sec::ApiUse& u) {
        QString name = QString::fromStdString(u.name);
        if (u.resolvedAtRuntime) {
            name += tr("  (resolved at runtime)");
        }
        QStringList callers;
        for (auto c : u.callers) {
            callers << fnName(c);
        }
        const QString calledFrom = callers.isEmpty() ? tr("(imported, no call site found)")
                                                     : callers.join(QStringLiteral(", "));
        auto* item = new QTreeWidgetItem(parent, {name, QString::fromLatin1(sec::categoryName(u.info.category)),
                                                  QString::fromStdString(u.info.why), calledFrom,
                                                  u.reachableFrom.empty() ? QString() : joinSet(u.reachableFrom)});
        for (int c = 0; c < 5; ++c) {
            item->setToolTip(c, item->text(c));
        }
        item->setForeground(0, QBrush(riskColor(u.info.risk)));
        if (!u.callers.empty()) {
            item->setData(0, kRvaRole, QVariant::fromValue<qulonglong>(u.callers.front()));
        }
    };

    static const std::pair<sec::ApiRisk, const char*> kLevels[] = {
        {sec::ApiRisk::Critical, "Critical"}, {sec::ApiRisk::High, "High"}, {sec::ApiRisk::Medium, "Medium"}};
    for (const auto& [risk, label] : kLevels) {
        if (counts[static_cast<int>(risk)] == 0) {
            continue;
        }
        auto* s = section(m_tree, tr("%1 (%2)").arg(QString::fromLatin1(label)).arg(counts[static_cast<int>(risk)]),
                          true);
        for (const auto& u : a.apis) {
            if (u.info.risk == risk) {
                addApi(s, u);
            }
        }
    }

    if (!a.privileged.empty()) {
        auto* s = section(m_tree, tr("Privileged instructions (%1)").arg(a.privileged.size()), true);
        for (const auto& p : a.privileged) {
            auto* item = new QTreeWidgetItem(
                s, {QStringLiteral("%1  @ %2").arg(QString::fromStdString(p.text), hex(p.rva)),
                    QString::fromStdString(p.kind), tr("Executes directly on the CPU / hardware; never an import"),
                    fnName(p.function), joinSet(p.reachableFrom)});
            item->setForeground(0, QBrush(riskColor(p.risk)));
            item->setData(0, kRvaRole, QVariant::fromValue<qulonglong>(p.function));
        }
    }

    // Mitigations and everything else, by category.
    QMap<QString, QList<const sec::ApiUse*>> rest;
    for (const auto& u : a.apis) {
        if (u.info.risk == sec::ApiRisk::Info) {
            rest[QString::fromLatin1(sec::categoryName(u.info.category))].append(&u);
        }
    }
    if (!rest.isEmpty()) {
        auto* s = section(m_tree, tr("Other APIs by category (%1)").arg(counts[0]), false);
        for (auto it = rest.cbegin(); it != rest.cend(); ++it) {
            auto* cat = new QTreeWidgetItem(s, {tr("%1 (%2)").arg(it.key()).arg(it.value().size())});
            cat->setFirstColumnSpanned(true);
            for (const auto* u : it.value()) {
                addApi(cat, *u);
            }
        }
    }
    for (int c = 0; c < 5; ++c) {
        m_tree->resizeColumnToContents(c);
    }
    m_tree->setColumnWidth(2, std::min(m_tree->columnWidth(2), 420));

    QStringList notes;
    notes << tr("Risk rates what an API can do if its arguments come from user mode, not whether this driver "
                "is vulnerable. Reachability follows direct calls from: %1.")
                 .arg(a.entryPoints.empty() ? tr("(no entry points)")
                                            : QString::fromStdString([&] {
                                                  std::string s;
                                                  for (const auto& e : a.entryPoints) {
                                                      s += (s.empty() ? "" : ", ") + e;
                                                  }
                                                  return s;
                                              }()).toHtmlEscaped());
    for (const auto& n : a.notes) {
        notes << QString::fromStdString(n).toHtmlEscaped();
    }
    m_notes->setText(notes.join(QStringLiteral("<br>")));
}

} // namespace dasa::ui
