#include "ui/driver_view/DevicesWidget.h"

#include <QHeaderView>
#include <QLabel>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/ioctl/IoctlCodec.h"

namespace dasa::ui {

namespace drv = dasa::core::driver;

namespace {

const QColor kWarn(0xE5, 0xA5, 0x4B);
const QColor kGood(0x6C, 0xC6, 0x8A);

QString hex(std::uint64_t v) {
    return QStringLiteral("0x") + QString::number(v, 16).toUpper().rightJustified(8, QLatin1Char('0'));
}

QTreeWidgetItem* section(QTreeWidget* tree, const QString& title) {
    auto* item = new QTreeWidgetItem(tree);
    item->setText(0, title);
    QFont f = item->font(0);
    f.setBold(true);
    item->setFont(0, f);
    item->setFirstColumnSpanned(true);
    item->setExpanded(true);
    return item;
}

QTreeWidgetItem* row(QTreeWidgetItem* parent, const QStringList& cols) {
    auto* item = new QTreeWidgetItem(parent, cols);
    for (int c = 0; c < cols.size(); ++c) {
        item->setToolTip(c, cols[c]);
    }
    return item;
}

} // namespace

DevicesWidget::DevicesWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::RichText);
    m_summary->setWordWrap(true);
    layout->addWidget(m_summary);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(5);
    m_tree->setHeaderLabels({tr("Name"), tr("Type / target"), tr("Secure open"), tr("Access control"),
                             tr("Created at")});
    m_tree->setAlternatingRowColors(true);
    m_tree->setUniformRowHeights(true);
    layout->addWidget(m_tree, 1);

    m_notes = new QLabel(this);
    m_notes->setTextFormat(Qt::RichText);
    m_notes->setWordWrap(true);
    m_notes->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_notes);
    clear();
}

void DevicesWidget::clear() {
    m_tree->clear();
    m_summary->setText(tr("<h3>No driver loaded</h3>"));
    m_notes->clear();
}

void DevicesWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_tree->clear();
    const drv::DeviceAnalysis& a = *result->devices;
    const auto& fns = *result->functions;
    auto where = [&](const std::string& api, std::uint64_t at, std::uint64_t in) {
        const auto* f = fns.find(in);
        return QStringLiteral("%1 at %2 in %3")
            .arg(QString::fromStdString(api), hex(at), f ? QString::fromStdString(f->name) : hex(in));
    };

    m_summary->setText(tr("<span style='font-size:15pt; font-weight:600'>%1 device objects</span>"
                          "&nbsp;&nbsp;<span style='color:#9a9a9a'>%2 symbolic links, %3 device "
                          "interfaces</span>")
                           .arg(a.devices.size())
                           .arg(a.symbolicLinks.size())
                           .arg(a.interfaces.size()));

    if (!a.devices.empty()) {
        auto* s = section(m_tree, tr("Device objects"));
        for (const auto& d : a.devices) {
            const QString name = !d.name.empty()      ? QString::fromStdString(d.name)
                                 : d.nameResolved      ? tr("(unnamed)")
                                                       : tr("(name not resolved)");
            const QString type = d.deviceType ? QString::fromStdString(dasa::core::ioctl::deviceTypeName(*d.deviceType))
                                              : tr("?");
            QString secure = tr("unknown");
            if (auto so = d.secureOpen()) {
                secure = *so ? tr("yes") : tr("no");
            }
            QString acl = d.sddl.empty() ? tr("default (no SDDL)") : QString::fromStdString(d.sddl);
            if (d.exclusive && *d.exclusive) {
                acl += tr(", exclusive");
            }
            auto* item = row(s, {name, type, secure, acl, where(d.api, d.at, d.inFunction)});
            if (d.secureOpen() == std::optional<bool>(false)) {
                item->setForeground(2, QBrush(kWarn));
                item->setToolTip(2, tr("FILE_DEVICE_SECURE_OPEN is not set: the device's security "
                                       "descriptor isn't applied to opens of names below the device "
                                       "(\\Device\\X\\anything)."));
            } else if (d.secureOpen() == std::optional<bool>(true)) {
                item->setForeground(2, QBrush(kGood));
            }
            if (d.sddl.empty()) {
                item->setForeground(3, QBrush(kWarn));
            }
        }
    }
    if (!a.symbolicLinks.empty()) {
        auto* s = section(m_tree, tr("Symbolic links (user-mode names)"));
        for (const auto& l : a.symbolicLinks) {
            const QString link = l.link.empty() ? tr("(not resolved)") : QString::fromStdString(l.link);
            const QString target = l.target.empty() ? (l.api.rfind("Wdf", 0) == 0 ? tr("this WDF device")
                                                                                   : tr("(not resolved)"))
                                                    : tr("-> %1").arg(QString::fromStdString(l.target));
            row(s, {link, target, QString(), QString(), where(l.api, l.at, l.inFunction)});
        }
    }
    if (!a.interfaces.empty()) {
        auto* s = section(m_tree, tr("Device interfaces"));
        for (const auto& i : a.interfaces) {
            row(s, {i.guid.empty() ? tr("(GUID not resolved)") : QString::fromStdString(i.guid), QString(),
                    QString(), QString(), where(i.api, i.at, i.inFunction)});
        }
    }
    if (!a.deviceNameStrings.empty() || !a.linkNameStrings.empty()) {
        auto* s = section(m_tree, tr("Device/link names found as strings"));
        for (const auto& n : a.deviceNameStrings) {
            row(s, {QString::fromStdString(n), tr("device name string")});
        }
        for (const auto& n : a.linkNameStrings) {
            row(s, {QString::fromStdString(n), tr("link name string")});
        }
        s->setExpanded(a.devices.empty() && a.symbolicLinks.empty());
    }
    if (m_tree->topLevelItemCount() == 0) {
        (new QTreeWidgetItem(m_tree))->setText(0, tr("No device objects, links or name strings found."));
    }
    for (int c = 0; c < 5; ++c) {
        m_tree->resizeColumnToContents(c);
    }

    QStringList notes;
    for (const auto& n : a.notes) {
        notes << QString::fromStdString(n).toHtmlEscaped();
    }
    m_notes->setText(notes.join(QStringLiteral("<br>")));
}

} // namespace dasa::ui
