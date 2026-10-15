#include "ui/ioctl_view/IoctlWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::ui {

namespace io = dasa::core::ioctl;

namespace {

constexpr int kFunctionRole = Qt::UserRole + 1;
const QColor kWarn(0xE5, 0xA5, 0x4B);

QString hex(std::uint64_t v) {
    return QStringLiteral("0x") + QString::number(v, 16).toUpper().rightJustified(8, QLatin1Char('0'));
}

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

enum Column { kCode, kDeviceType, kFunction, kMethod, kAccess, kHandler, kComparedIn, kCase, kEvidence, kCount };

} // namespace

IoctlWidget::IoctlWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::RichText);
    m_summary->setWordWrap(true);
    layout->addWidget(m_summary);

    m_table = new QTableWidget(0, kCount, this);
    m_table->setHorizontalHeaderLabels({tr("IOCTL code"), tr("Device type"), tr("Function"), tr("Method"),
                                        tr("Access"), tr("Handler"), tr("Compared in"), tr("Case at"),
                                        tr("Found by")});
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(26);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setAlternatingRowColors(true);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_table->setToolTip(tr("Double-click a row to open the function that compares the code"));
    layout->addWidget(m_table, 1);

    m_notes = new QLabel(this);
    m_notes->setTextFormat(Qt::RichText);
    m_notes->setWordWrap(true);
    m_notes->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_notes);

    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (auto* item = m_table->item(row, 0)) {
            emit functionActivated(item->data(kFunctionRole).toULongLong());
        }
    });
    clear();
}

void IoctlWidget::clear() {
    m_result.reset();
    m_table->setRowCount(0);
    m_summary->setText(tr("<h3>No driver loaded</h3>"));
    m_notes->clear();
}

void IoctlWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    const io::IoctlAnalysis& a = *m_result->ioctls;
    const auto& fns = *m_result->functions;
    auto fnName = [&](std::uint64_t rva) {
        const auto* f = fns.find(rva);
        return f ? QString::fromStdString(f->name) : hex(rva);
    };

    int neither = 0, anyAccess = 0;
    for (const auto& e : a.ioctls) {
        neither += e.decoded.isMethodNeither() ? 1 : 0;
        anyAccess += e.decoded.isAnyAccess() ? 1 : 0;
    }
    QStringList anchors;
    for (const auto& s : a.anchors) {
        anchors << QString::fromStdString(s).toHtmlEscaped();
    }
    m_summary->setText(
        tr("<span style='font-size:15pt; font-weight:600'>%1 IOCTL codes</span>"
           "&nbsp;&nbsp;<span style='color:%2'>%3 METHOD_NEITHER</span>, "
           "<span style='color:%2'>%4 FILE_ANY_ACCESS</span>"
           "<br><span style='color:#9a9a9a'>Handlers analysed: %5</span>")
            .arg(a.ioctls.size())
            .arg(kWarn.name())
            .arg(neither)
            .arg(anyAccess)
            .arg(anchors.isEmpty() ? tr("none") : anchors.join(QStringLiteral(", "))));

    m_table->setSortingEnabled(false);
    m_table->setRowCount(static_cast<int>(a.ioctls.size()));
    int r = 0;
    for (const auto& e : a.ioctls) {
        const auto& d = e.decoded;
        auto* code = cell(QString::fromStdString(io::hexCode(d.code)));
        code->setData(kFunctionRole, QVariant::fromValue<qulonglong>(e.comparedIn));
        m_table->setItem(r, kCode, code);
        m_table->setItem(r, kDeviceType, cell(QString::fromStdString(io::deviceTypeName(d.deviceType))));
        m_table->setItem(r, kFunction, cell(QStringLiteral("0x") + QString::number(d.function, 16).toUpper().rightJustified(3, QLatin1Char('0'))));
        auto* method = cell(QString::fromLatin1(io::methodName(d.method)));
        if (d.isMethodNeither()) {
            method->setForeground(QBrush(kWarn));
            method->setToolTip(tr("METHOD_NEITHER: the driver gets raw user-mode pointers"));
        }
        m_table->setItem(r, kMethod, method);
        auto* access = cell(QString::fromLatin1(io::accessName(d.access)));
        if (d.isAnyAccess()) {
            access->setForeground(QBrush(kWarn));
            access->setToolTip(tr("FILE_ANY_ACCESS: any handle to the device can send this code"));
        }
        m_table->setItem(r, kAccess, access);
        m_table->setItem(r, kHandler, cell(QString::fromStdString(e.handler)));
        m_table->setItem(r, kComparedIn, cell(QStringLiteral("%1 (%2)").arg(fnName(e.comparedIn), hex(e.at))));
        m_table->setItem(r, kCase, cell(e.caseTarget ? hex(*e.caseTarget) : QString()));
        m_table->setItem(r, kEvidence, cell(QString::fromLatin1(io::evidenceName(e.evidence))));
        ++r;
    }
    m_table->horizontalHeader()->setSortIndicator(-1, Qt::AscendingOrder);
    m_table->setSortingEnabled(true);
    m_table->resizeColumnsToContents();

    QStringList notes;
    for (const auto& n : a.notes) {
        notes << QString::fromStdString(n).toHtmlEscaped();
    }
    notes << tr("<i>IoControlCode compare</i>: compared against the request's tracked IoControlCode. "
                "<i>Constant in handler</i>: an IOCTL-shaped constant in a handler where the code "
                "itself couldn't be tracked.");
    m_notes->setText(notes.join(QStringLiteral("<br>")));
}

} // namespace dasa::ui
