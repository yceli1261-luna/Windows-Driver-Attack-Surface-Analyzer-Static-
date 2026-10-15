#include "ui/driver_view/DriverModelWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QMap>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::ui {

namespace drv = dasa::core::driver;

namespace {

constexpr int kRvaRole = Qt::UserRole + 1;

QString hex(std::uint64_t v) {
    return QStringLiteral("0x") + QString::number(v, 16).toUpper().rightJustified(8, QLatin1Char('0'));
}

QString qs(const std::string& s) {
    return QString::fromStdString(s);
}

QString confidenceColor(drv::Confidence c) {
    switch (c) {
    case drv::Confidence::High: return QStringLiteral("#6cc68a");
    case drv::Confidence::Medium: return QStringLiteral("#e5a54b");
    case drv::Confidence::Low: break;
    }
    return QStringLiteral("#f1706b");
}

QTreeWidgetItem* section(QTreeWidget* tree, const QString& title) {
    auto* item = new QTreeWidgetItem(tree);
    item->setText(0, title);
    QFont f = item->font(0);
    f.setBold(true);
    item->setFont(0, f);
    item->setFirstColumnSpanned(true);
    return item;
}

} // namespace

DriverModelWidget::DriverModelWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(10);

    m_header = new QLabel(this);
    m_header->setTextFormat(Qt::RichText);
    m_header->setWordWrap(true);
    m_header->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(m_header);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(4);
    m_tree->setHeaderLabels({tr("Entry"), tr("Handler"), tr("Function"), tr("Registered at")});
    m_tree->setAlternatingRowColors(true);
    m_tree->setUniformRowHeights(true);
    m_tree->setToolTip(tr("Double-click a handler to open it in the Functions tab"));
    layout->addWidget(m_tree, 1);

    m_notes = new QLabel(this);
    m_notes->setTextFormat(Qt::RichText);
    m_notes->setWordWrap(true);
    m_notes->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_notes);

    connect(m_tree, &QTreeWidget::itemDoubleClicked, this,
            [this](QTreeWidgetItem* item, int) { onItemActivated(item); });
    clear();
}

void DriverModelWidget::clear() {
    m_result.reset();
    m_tree->clear();
    m_header->setText(tr("<h3>No driver loaded</h3>"));
    m_notes->clear();
}

QString DriverModelWidget::functionLabel(std::uint64_t rva) const {
    if (const auto* fn = m_result->functions->find(rva)) {
        return qs(fn->name);
    }
    return tr("(not a discovered function)");
}

void DriverModelWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_tree->clear();
    const drv::DriverAnalysis& d = *m_result->driver;

    // Header: model, confidence, evidence, DriverEntry chain.
    QString html = tr("<span style='font-size:15pt; font-weight:600'>%1</span>"
                      "&nbsp;&nbsp;<span style='color:%2'>%3 confidence</span>")
                       .arg(QString::fromLatin1(drv::modelName(d.model.kind)),
                            confidenceColor(d.model.confidence),
                            QString::fromLatin1(drv::confidenceName(d.model.confidence)));
    if (!d.model.additionalFrameworks.empty()) {
        QStringList also;
        for (auto k : d.model.additionalFrameworks) {
            also << QString::fromLatin1(drv::modelName(k));
        }
        html += tr("&nbsp;&nbsp;<span style='color:#9a9a9a'>also: %1</span>").arg(also.join(QStringLiteral(", ")));
    }
    html += QStringLiteral("<ul style='margin-top:4px'>");
    for (const auto& e : d.model.evidence) {
        html += QStringLiteral("<li>%1</li>").arg(qs(e).toHtmlEscaped());
    }
    html += QStringLiteral("</ul>");
    if (d.driverEntry) {
        QStringList chain;
        for (auto rva : d.entryChain) {
            chain << QStringLiteral("%1 (%2)").arg(functionLabel(rva).toHtmlEscaped(), hex(rva));
        }
        html += tr("<b>DriverEntry:</b> %1<br><span style='color:#9a9a9a'>%2</span>")
                    .arg(chain.join(QStringLiteral(" &rarr; ")), qs(d.driverEntryNote).toHtmlEscaped());
    } else {
        html += tr("<b>DriverEntry:</b> not found. %1").arg(qs(d.driverEntryNote).toHtmlEscaped());
    }
    m_header->setText(html);

    auto addHandler = [this](QTreeWidgetItem* parent, const QString& entry, std::uint64_t rva,
                             bool isFunction, const QString& where) {
        auto* item = new QTreeWidgetItem(parent);
        item->setText(0, entry);
        item->setText(1, hex(rva));
        item->setText(2, isFunction ? functionLabel(rva) : tr("(no code there)"));
        item->setText(3, where);
        item->setData(0, kRvaRole, QVariant::fromValue<qulonglong>(rva));
        if (!isFunction) {
            for (int c = 0; c < 4; ++c) {
                item->setForeground(c, QBrush(QColor(0xE5, 0xA5, 0x4B)));
            }
            item->setToolTip(2, tr("The pointer doesn't lead to a discovered function "
                                   "(e.g. padding or data)."));
        }
        return item;
    };
    auto site = [this](std::uint64_t at, std::uint64_t in) {
        return tr("%1 in %2").arg(hex(at), functionLabel(in));
    };

    // WDM dispatch table.
    if (!d.majorFunctions.empty() || !d.driverObjectWrites.empty()) {
        auto* mf = section(m_tree, tr("DriverObject->MajorFunction[] (%1 of 28 set)").arg(d.majorFunctions.size()));
        for (const auto& e : d.majorFunctions) {
            auto* item = addHandler(mf,
                                    QStringLiteral("%1 (0x%2)")
                                        .arg(QString::fromLatin1(drv::irpMajorName(e.major)))
                                        .arg(e.major, 2, 16, QLatin1Char('0')),
                                    e.handler, e.handlerIsFunction, site(e.setAt, e.inFunction));
            if (e.how != "direct store") {
                item->setText(3, item->text(3) + QStringLiteral(" (") + qs(e.how) + QStringLiteral(")"));
            }
        }
        if (!d.driverObjectWrites.empty()) {
            auto* other = section(m_tree, tr("Other DRIVER_OBJECT fields"));
            for (const auto& w : d.driverObjectWrites) {
                if (w.value) {
                    addHandler(other, qs(w.field), *w.value,
                               m_result->functions->find(*w.value) != nullptr, site(w.setAt, w.inFunction));
                } else {
                    auto* item = new QTreeWidgetItem(other);
                    item->setText(0, qs(w.field));
                    item->setText(1, tr("(runtime value)"));
                    item->setText(3, site(w.setAt, w.inFunction));
                }
            }
        }
    }

    // KMDF registrations.
    for (const auto& reg : d.wdfDrivers) {
        auto* s = section(m_tree, tr("WdfDriverCreate at %1").arg(hex(reg.createCall)));
        if (!reg.configResolved) {
            (new QTreeWidgetItem(s))->setText(0, tr("WDF_DRIVER_CONFIG not traced"));
        }
        for (const auto& cb : reg.callbacks) {
            addHandler(s, qs(cb.name), cb.function, cb.isFunction, site(reg.createCall, reg.inFunction));
        }
    }
    int n = 1;
    for (const auto& q : d.wdfQueues) {
        QString title = tr("I/O queue %1: %2").arg(n++).arg(qs(q.dispatchType));
        if (q.defaultQueue) {
            title += *q.defaultQueue ? tr(", default queue") : tr(", not default");
        }
        title += tr(" (WdfIoQueueCreate at %1)").arg(hex(q.createCall));
        auto* s = section(m_tree, title);
        if (!q.configResolved) {
            (new QTreeWidgetItem(s))->setText(0, tr("WDF_IO_QUEUE_CONFIG not traced"));
        } else if (q.callbacks.empty()) {
            (new QTreeWidgetItem(s))->setText(0, tr("No EvtIo* callbacks set (manual queue or set elsewhere)"));
        }
        for (const auto& cb : q.callbacks) {
            addHandler(s, qs(cb.name), cb.function, cb.isFunction, site(q.createCall, q.inFunction));
        }
    }
    for (const auto& t : d.wdfIoTypes) {
        auto* item = new QTreeWidgetItem(m_tree);
        item->setText(0, tr("WdfDeviceInitSetIoType: %1").arg(qs(t.ioType)));
        item->setText(3, hex(t.call));
        item->setFirstColumnSpanned(true);
    }
    if (!d.wdfCalls.empty()) {
        QMap<QString, int> counts;
        for (const auto& c : d.wdfCalls) {
            counts[qs(c.name)]++;
        }
        auto* s = section(m_tree, tr("WDF API calls (%1 calls, %2 distinct)").arg(d.wdfCalls.size()).arg(counts.size()));
        for (auto it = counts.cbegin(); it != counts.cend(); ++it) {
            auto* item = new QTreeWidgetItem(s);
            item->setText(0, it.key());
            item->setText(1, tr("x%1").arg(it.value()));
        }
        s->setExpanded(false);
    }

    if (m_tree->topLevelItemCount() == 0) {
        (new QTreeWidgetItem(m_tree))->setText(0, tr("No handler registrations were recovered."));
    }
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* top = m_tree->topLevelItem(i);
        if (!top->text(0).startsWith(tr("WDF API calls"))) {
            top->setExpanded(true);
        }
    }
    for (int c = 0; c < 4; ++c) {
        m_tree->resizeColumnToContents(c);
    }

    QStringList notes;
    for (const auto& note : d.notes) {
        notes << qs(note).toHtmlEscaped();
    }
    m_notes->setText(notes.isEmpty() ? QString() : tr("<b>Notes:</b> ") + notes.join(QStringLiteral("<br>")));
}

void DriverModelWidget::onItemActivated(QTreeWidgetItem* item) {
    const QVariant v = item->data(0, kRvaRole);
    if (v.isValid()) {
        emit functionActivated(v.toULongLong());
    }
}

} // namespace dasa::ui
