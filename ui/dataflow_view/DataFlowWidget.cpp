#include "ui/dataflow_view/DataFlowWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QSplitter>
#include <QTableWidget>
#include <QTextBrowser>
#include <QUrl>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/ioctl/IoctlCodec.h"
#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace df = core::dataflow;
namespace fnd = core::findings;

namespace {

constexpr int kRowRole = Qt::UserRole + 1;

QColor flowColor(df::Severity s) {
    switch (s) {
    case df::Severity::Critical: return severityColor(fnd::Severity::Critical);
    case df::Severity::High: return severityColor(fnd::Severity::High);
    case df::Severity::Medium: break;
    }
    return severityColor(fnd::Severity::Medium);
}

QString hexRva(std::uint64_t v) {
    return QStringLiteral("0x%1").arg(v, 8, 16, QLatin1Char('0')).toUpper().replace(QStringLiteral("0X"),
                                                                                       QStringLiteral("0x"));
}

QString q(const std::string& s) {
    return QString::fromStdString(s).toHtmlEscaped();
}

} // namespace

DataFlowWidget::DataFlowWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(10);

    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::RichText);
    m_summary->setMinimumWidth(1);
    layout->addWidget(m_summary);

    auto* splitter = new QSplitter(Qt::Horizontal, this);
    m_table = new QTableWidget(0, 5, splitter);
    m_table->setHorizontalHeaderLabels({tr("Severity"), tr("Operation"), tr("Controlled by the request"),
                                        tr("IOCTL"), tr("Function")});
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(28);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    m_detail = new QTextBrowser(splitter);
    m_detail->setOpenLinks(false);
    m_detail->setFrameShape(QFrame::NoFrame);

    splitter->addWidget(m_table);
    splitter->addWidget(m_detail);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    splitter->setSizes({620, 420});
    layout->addWidget(splitter, 1);

    connect(m_table, &QTableWidget::currentCellChanged, this, [this](int row, int, int, int) { showDetail(row); });
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (!m_result || row < 0) {
            return;
        }
        const int index = m_table->item(row, 0)->data(kRowRole).toInt();
        emit functionActivated(m_result->dataflow->flows[static_cast<std::size_t>(index)].function);
    });
    connect(m_detail, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
        bool ok = false;
        const auto rva = url.path().toULongLong(&ok, 16);
        if (ok && url.scheme() == QLatin1String("fn")) {
            emit functionActivated(rva);
        }
    });
    clear();
}

void DataFlowWidget::clear() {
    m_result.reset();
    m_table->setRowCount(0);
    m_summary->setText(tr("<h3>No driver loaded</h3>"));
    m_detail->clear();
}

void DataFlowWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    const auto& a = *m_result->dataflow;
    const auto& set = *m_result->functions;
    auto fnName = [&](std::uint64_t rva) {
        const auto* f = set.find(rva);
        return f ? QString::fromStdString(f->name) : hexRva(rva);
    };

    std::size_t constantCalls = 0;
    for (const auto& c : a.checkedCalls) {
        if (!c.anyUserControlled()) {
            ++constantCalls;
        }
    }
    QString summary;
    if (a.entries.empty()) {
        summary = tr("<b>No request data traced.</b> ");
    } else {
        summary = tr("<b>%1</b> &nbsp;<span style='color:#9a9a9a'>from %2 &middot; %3 function walks</span>")
                      .arg(a.flows.empty() ? tr("No request data reaches a sensitive operation")
                                           : tr("%n flow(s) of request data into sensitive operations", nullptr,
                                                static_cast<int>(a.flows.size())))
                      .arg(QString::fromStdString([&] {
                               std::string s;
                               for (const auto& e : a.entries) {
                                   s += (s.empty() ? "" : ", ") + e;
                               }
                               return s;
                           }()).toHtmlEscaped())
                      .arg(a.functionsAnalysed);
    }
    if (constantCalls) {
        summary += tr("<br><span style='color:#9a9a9a'>%1 sensitive call(s) reached with arguments the request "
                      "doesn't control - listed below the selected flow.</span>")
                       .arg(constantCalls);
    }
    for (const auto& n : a.notes) {
        summary += QStringLiteral("<br><span style='color:#9a9a9a'>") + q(n) + QStringLiteral("</span>");
    }
    m_summary->setText(summary);

    m_table->setRowCount(static_cast<int>(a.flows.size()));
    for (int i = 0; i < static_cast<int>(a.flows.size()); ++i) {
        const auto& f = a.flows[static_cast<std::size_t>(i)];
        auto* sev = new QTableWidgetItem(QString::fromLatin1(df::severityName(f.severity)));
        sev->setForeground(QBrush(flowColor(f.severity)));
        sev->setData(kRowRole, i);
        m_table->setItem(i, 0, sev);
        auto* op = new QTableWidgetItem(QString::fromStdString(f.sink) + QStringLiteral("  ") +
                                        QStringLiteral("(%1)").arg(QString::fromLatin1(df::sinkKindName(f.kind))));
        op->setToolTip(QString::fromStdString(f.impact));
        m_table->setItem(i, 1, op);
        QStringList operands;
        for (const auto& o : f.operands) {
            operands << QString::fromStdString(o.name);
        }
        auto* ctl = new QTableWidgetItem(operands.join(QStringLiteral(", ")));
        ctl->setToolTip(QString::fromStdString(f.impact));
        m_table->setItem(i, 2, ctl);
        QStringList codes;
        for (auto c : f.ioctls) {
            codes << QString::fromStdString(core::ioctl::hexCode(c));
        }
        m_table->setItem(i, 3, new QTableWidgetItem(codes.isEmpty() ? QStringLiteral("-") : codes.join(QStringLiteral(", "))));
        m_table->setItem(i, 4, new QTableWidgetItem(fnName(f.function)));
    }
    m_table->resizeColumnToContents(0);
    m_table->resizeColumnToContents(1);
    m_table->resizeColumnToContents(3);
    m_table->resizeColumnToContents(4);
    if (!a.flows.empty()) {
        m_table->setCurrentCell(0, 0);
    } else {
        showDetail(-1);
    }
}

void DataFlowWidget::showDetail(int row) {
    if (!m_result) {
        m_detail->clear();
        return;
    }
    const auto& a = *m_result->dataflow;
    const auto& set = *m_result->functions;
    auto fnLink = [&](std::uint64_t rva) {
        const auto* f = set.find(rva);
        return QStringLiteral("<a href='fn:%1'>%2</a>")
            .arg(rva, 0, 16)
            .arg(f ? QString::fromStdString(f->name).toHtmlEscaped() : hexRva(rva));
    };

    QString html;
    if (row >= 0) {
        const auto& f = a.flows[static_cast<std::size_t>(m_table->item(row, 0)->data(kRowRole).toInt())];
        html += QStringLiteral("<p style='font-size:13pt; font-weight:600'>%1</p>").arg(q(f.sink));
        html += QStringLiteral("<p><span style='color:%1'>%2</span> &middot; %3</p>")
                    .arg(flowColor(f.severity).name(), QString::fromLatin1(df::severityName(f.severity)), q(f.impact));
        html += tr("<p><b>Entry:</b> %1 &nbsp; <b>IOCTL:</b> %2</p>")
                    .arg(q(f.entry))
                    .arg([&] {
                        if (f.ioctls.empty()) {
                            return tr("not resolved");
                        }
                        QStringList c;
                        for (auto code : f.ioctls) {
                            c << QString::fromStdString(core::ioctl::hexCode(code));
                        }
                        return c.join(QStringLiteral(", ")) +
                               (f.ioctlsExact ? tr(" (its case leads here)") : tr(" (compared on the path)"));
                    }());
        html += tr("<p><b>Where the data comes from</b></p><ul>");
        for (const auto& o : f.operands) {
            html += QStringLiteral("<li><b>%1</b> &larr; <code>%2</code>%3 <span style='color:#9a9a9a'>%4</span></li>")
                        .arg(q(o.name), q(o.source.empty() ? std::string("request data") : o.source),
                             o.sourceAt ? tr(" read at %1").arg(hexRva(o.sourceAt)) : QString(),
                             q(df::describeLabels(o.labels)));
        }
        html += QStringLiteral("</ul>");
        html += tr("<p><b>Path</b> (click to open)</p><p>");
        for (std::size_t i = 0; i < f.path.size(); ++i) {
            html += (i ? QStringLiteral(" &rarr; ") : QString()) + fnLink(f.path[i]);
        }
        html += tr(" &rarr; %1 at %2</p>").arg(q(f.sink), hexRva(f.at));
        if (f.requestorModeChecked) {
            html += tr("<p style='color:#e5a54b'>The handler reads Irp->RequestorMode - it may accept this only "
                       "from kernel-mode callers. Check whether that guards this path.</p>");
        }
        html += tr("<p style='color:#9a9a9a'>Traced through registers, stack slots and direct calls. Range checks "
                   "aren't recognised: confirm whether the value is validated before this point.</p>");
    } else if (a.flows.empty() && !a.entries.empty()) {
        html += tr("<p>No request data was traced into a sensitive API argument, privileged instruction or "
                   "memory address.</p>");
    }

    std::vector<const df::CheckedCall*> others;
    for (const auto& c : a.checkedCalls) {
        if (!c.anyUserControlled()) {
            others.push_back(&c);
        }
    }
    if (!others.empty()) {
        html += tr("<hr><p><b>Sensitive calls reached without request data in their arguments</b></p><ul>");
        for (const auto* c : others) {
            QStringList args;
            for (const auto& arg : c->args) {
                using K = df::CheckedCall::Arg::Kind;
                args << QStringLiteral("%1 = %2").arg(
                    q(arg.name), arg.kind == K::Constant
                                     ? QStringLiteral("0x%1").arg(static_cast<qulonglong>(arg.value), 0, 16).toUpper().replace(
                                           QStringLiteral("0X"), QStringLiteral("0x"))
                                     : tr("not traced"));
            }
            html += tr("<li><code>%1</code> in %2 at %3 <span style='color:#9a9a9a'>(%4)</span><br>%5</li>")
                        .arg(q(c->api), fnLink(c->function), hexRva(c->at), q(c->entry), args.join(QStringLiteral(", ")));
        }
        html += QStringLiteral("</ul>");
    }
    m_detail->setHtml(html);
}

} // namespace dasa::ui
