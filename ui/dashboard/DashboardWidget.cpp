#include "ui/dashboard/DashboardWidget.h"

#include <QBrush>
#include <QColor>
#include <QHeaderView>
#include <QLabel>
#include <QScrollArea>
#include <QStackedWidget>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

#include "core/pe/PEImage.h"

namespace dasa::ui {

namespace pe = dasa::core::pe;

namespace {

// Fixed-width, zero-padded hex so lexical sorting in the tables is numeric.
QString hex(std::uint64_t value, int width = 8) {
    return QStringLiteral("0x") +
           QString::number(value, 16).toUpper().rightJustified(width, QLatin1Char('0'));
}

QString qs(const std::string& s) {
    return QString::fromStdString(s);
}

QString joined(const std::vector<std::string>& items, const char* separator = ", ") {
    QStringList list;
    for (const auto& item : items) {
        list << qs(item);
    }
    return list.join(QLatin1String(separator));
}

QTableWidget* makeTable(const QStringList& headers, QWidget* parent) {
    auto* table = new QTableWidget(0, static_cast<int>(headers.size()), parent);
    table->setHorizontalHeaderLabels(headers);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    return table;
}

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

void finishTable(QTableWidget* table) {
    // Enabling sorting re-sorts by the current indicator (column 0,
    // descending, by default). Clear it so rows stay in file order until the
    // user clicks a header.
    table->horizontalHeader()->setSortIndicator(-1, Qt::AscendingOrder);
    table->setSortingEnabled(true);
    table->resizeColumnsToContents();
}

QString row(const QString& key, const QString& value) {
    return QStringLiteral("<tr><td style='color:#9a9a9a; padding-right:14px'>%1</td>"
                          "<td>%2</td></tr>")
        .arg(key, value);
}

const QColor kWarn(0xE5, 0xA5, 0x4B);
const QColor kBad(0xF1, 0x70, 0x6B);
const QColor kGood(0x6C, 0xC6, 0x8A);

QString colored(const QString& text, const QColor& color) {
    return QStringLiteral("<span style='color:%1'>%2</span>").arg(color.name(), text);
}

} // namespace

DashboardWidget::DashboardWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    m_stack = new QStackedWidget(this);
    m_stack->addWidget(buildMessagePage());
    m_stack->addWidget(buildImagePage());
    layout->addWidget(m_stack);
    showEmpty();
}

QWidget* DashboardWidget::buildMessagePage() {
    m_message = new QLabel(this);
    m_message->setAlignment(Qt::AlignCenter);
    m_message->setWordWrap(true);
    m_message->setTextFormat(Qt::RichText);
    m_message->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_message->setMargin(32);
    return m_message;
}

QWidget* DashboardWidget::buildImagePage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(20, 16, 20, 12);
    layout->setSpacing(10);

    m_title = new QLabel(page);
    m_title->setTextFormat(Qt::RichText);
    m_title->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(m_title);

    m_subtitle = new QLabel(page);
    m_subtitle->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    m_subtitle->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_subtitle->setWordWrap(true);
    layout->addWidget(m_subtitle);

    m_facts = new QLabel(page);
    m_facts->setTextFormat(Qt::RichText);
    m_facts->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(m_facts);

    m_hashes = new QLabel(page);
    m_hashes->setTextFormat(Qt::RichText);
    m_hashes->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(m_hashes);

    m_tabs = new QTabWidget(page);

    m_sections = makeTable({tr("Name"), tr("Virtual address"), tr("Virtual size"),
                            tr("Raw offset"), tr("Raw size"), tr("Entropy"),
                            tr("Characteristics"), tr("Flags")},
                           m_tabs);
    m_tabs->addTab(m_sections, tr("Sections"));

    m_imports = new QTreeWidget(m_tabs);
    m_imports->setColumnCount(4);
    m_imports->setHeaderLabels({tr("Library / function"), tr("Ordinal"), tr("Hint"), tr("IAT RVA")});
    m_imports->setAlternatingRowColors(true);
    m_imports->setUniformRowHeights(true);
    m_tabs->addTab(m_imports, tr("Imports"));

    m_exports = makeTable({tr("Ordinal"), tr("Name"), tr("RVA"), tr("Forwarded to")}, m_tabs);
    m_tabs->addTab(m_exports, tr("Exports"));

    m_headers = makeTable({tr("Field"), tr("Value")}, m_tabs);
    m_tabs->addTab(m_headers, tr("Headers"));

    auto* sigScroll = new QScrollArea(m_tabs);
    sigScroll->setWidgetResizable(true);
    sigScroll->setFrameShape(QFrame::NoFrame);
    m_signature = new QLabel(sigScroll);
    m_signature->setTextFormat(Qt::RichText);
    m_signature->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_signature->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    m_signature->setWordWrap(true);
    m_signature->setMargin(12);
    sigScroll->setWidget(m_signature);
    m_tabs->addTab(sigScroll, tr("Signature"));

    // Keep the tables usable even when the dock is short; the dock grows to
    // fit rather than collapsing the table to a single row.
    m_tabs->setMinimumHeight(260);
    layout->addWidget(m_tabs, 1);
    return page;
}

void DashboardWidget::showEmpty() {
    m_message->setText(tr("<h2>No driver loaded</h2>"
                          "<p style='color:#9a9a9a'>Drag a <b>.sys</b> file onto the window, "
                          "or press <b>Ctrl+O</b>.</p>"));
    m_stack->setCurrentIndex(0);
}

void DashboardWidget::showLoading(const QString& path) {
    m_message->setText(tr("<h2>Parsing&hellip;</h2><p style='color:#9a9a9a'>%1</p>")
                           .arg(path.toHtmlEscaped()));
    m_stack->setCurrentIndex(0);
}

void DashboardWidget::showError(const QString& path, const QString& message) {
    m_message->setText(tr("<h2 style='color:%1'>Could not parse driver</h2>"
                          "<p>%2</p><p style='color:#9a9a9a'>%3</p>")
                           .arg(kBad.name(), message.toHtmlEscaped(), path.toHtmlEscaped()));
    m_stack->setCurrentIndex(0);
}

void DashboardWidget::showImage(const pe::PEImage& image) {
    fillSummary(image);
    fillSections(image);
    fillImports(image);
    fillExports(image);
    fillHeaders(image);
    fillSignature(image);

    m_tabs->setTabText(0, tr("Sections (%1)").arg(image.sections.size()));
    m_tabs->setTabText(1, tr("Imports (%1)").arg(image.importedFunctionCount()));
    m_tabs->setTabText(2, tr("Exports (%1)").arg(image.exports.size()));
    m_stack->setCurrentIndex(1);
}

void DashboardWidget::fillSummary(const pe::PEImage& image) {
    m_title->setText(QStringLiteral("<span style='font-size:18pt; font-weight:600'>%1</span>")
                         .arg(qs(image.fileName).toHtmlEscaped()));
    m_subtitle->setText(QString::fromStdWString(image.path.wstring()));

    QString signature;
    if (!image.signature.hasEmbeddedSignature) {
        signature = colored(tr("No embedded signature"), kWarn);
    } else if (image.signature.digestValid) {
        const QString signer = image.signature.signers.empty()
                                   ? QString()
                                   : qs(image.signature.signers.front().subject);
        signature = colored(tr("Embedded, digest valid"), kGood) +
                    (signer.isEmpty() ? QString() : QStringLiteral(" &middot; ") + signer.toHtmlEscaped());
    } else {
        signature = colored(tr("Embedded, verification failed: %1")
                                .arg(qs(image.signature.verification).toHtmlEscaped()),
                            kBad);
    }

    const QString checksum =
        image.checksumMatches()
            ? hex(image.headerChecksum) + QStringLiteral(" ") + colored(tr("(matches)"), kGood)
            : hex(image.headerChecksum) + QStringLiteral(" ") +
                  colored(tr("(computed %1)").arg(hex(image.computedChecksum)), kWarn);

    const QString left =
        row(tr("Architecture"), qs(image.machineName) + (image.is64Bit ? " (PE32+)" : " (PE32)")) +
        row(tr("Subsystem"), qs(image.subsystemName)) +
        row(tr("Image base"), hex(image.imageBase, image.is64Bit ? 16 : 8)) +
        row(tr("Entry point"), tr("RVA %1").arg(hex(image.entryPointRva))) +
        row(tr("Size"), tr("%1 bytes, image %2").arg(image.fileSize).arg(hex(image.sizeOfImage)));
    const QString right =
        row(tr("Linker"), QStringLiteral("%1.%2").arg(image.linkerMajor).arg(image.linkerMinor)) +
        row(tr("Timestamp"), image.timestampUtc.empty() ? tr("(none)") : qs(image.timestampUtc)) +
        row(tr("Checksum"), checksum) +
        row(tr("Signature"), signature) +
        row(tr("PDB"), image.pdbPath.empty() ? tr("(none)") : qs(image.pdbPath).toHtmlEscaped());

    m_facts->setText(QStringLiteral("<table><tr><td valign='top'><table>%1</table></td>"
                                    "<td width='40'></td>"
                                    "<td valign='top'><table>%2</table></td></tr></table>")
                         .arg(left, right));

    m_hashes->setText(
        QStringLiteral("<table style='font-family:Consolas,monospace'>%1%2%3</table>")
            .arg(row(QStringLiteral("SHA-256"), qs(image.hashes.sha256)),
                 row(QStringLiteral("SHA-1"), qs(image.hashes.sha1)),
                 row(QStringLiteral("MD5"), qs(image.hashes.md5))));
}

void DashboardWidget::fillSections(const pe::PEImage& image) {
    m_sections->setSortingEnabled(false);
    m_sections->setRowCount(static_cast<int>(image.sections.size()));
    int r = 0;
    for (const auto& s : image.sections) {
        m_sections->setItem(r, 0, cell(qs(s.name)));
        m_sections->setItem(r, 1, cell(hex(s.virtualAddress)));
        m_sections->setItem(r, 2, cell(hex(s.virtualSize)));
        m_sections->setItem(r, 3, cell(hex(s.rawOffset)));
        m_sections->setItem(r, 4, cell(hex(s.rawSize)));
        m_sections->setItem(r, 5, cell(QString::number(s.entropy, 'f', 3)));
        m_sections->setItem(r, 6, cell(hex(s.characteristics)));
        m_sections->setItem(r, 7, cell(joined(s.flags, " | ")));
        // Writable + executable sections are worth noticing in a driver.
        if (s.isExecutable() && s.isWritable()) {
            for (int c = 0; c < m_sections->columnCount(); ++c) {
                m_sections->item(r, c)->setForeground(QBrush(kBad));
            }
            m_sections->item(r, 7)->setToolTip(tr("Section is both writable and executable"));
        }
        ++r;
    }
    finishTable(m_sections);
}

void DashboardWidget::fillImports(const pe::PEImage& image) {
    m_imports->clear();
    for (const auto& lib : image.imports) {
        auto* libItem = new QTreeWidgetItem(m_imports);
        libItem->setText(0, tr("%1  (%2)").arg(qs(lib.name)).arg(lib.functions.size()));
        QFont bold = libItem->font(0);
        bold.setBold(true);
        libItem->setFont(0, bold);
        for (const auto& fn : lib.functions) {
            auto* item = new QTreeWidgetItem(libItem);
            item->setText(0, fn.name.empty() ? tr("(by ordinal)") : qs(fn.name));
            item->setText(1, fn.ordinal ? QString::number(*fn.ordinal) : QString());
            item->setText(2, fn.ordinal ? QString() : QString::number(fn.hint));
            item->setText(3, hex(fn.iatRva));
        }
    }
    m_imports->expandAll();
    for (int c = 0; c < m_imports->columnCount(); ++c) {
        m_imports->resizeColumnToContents(c);
    }
}

void DashboardWidget::fillExports(const pe::PEImage& image) {
    m_exports->setSortingEnabled(false);
    m_exports->setRowCount(static_cast<int>(image.exports.size()));
    int r = 0;
    for (const auto& e : image.exports) {
        auto* ordinal = new QTableWidgetItem;
        ordinal->setData(Qt::DisplayRole, static_cast<int>(e.ordinal));
        m_exports->setItem(r, 0, ordinal);
        m_exports->setItem(r, 1, cell(e.name.empty() ? tr("(unnamed)") : qs(e.name)));
        m_exports->setItem(r, 2, cell(hex(e.rva)));
        m_exports->setItem(r, 3, cell(qs(e.forwarder)));
        ++r;
    }
    finishTable(m_exports);
}

void DashboardWidget::fillHeaders(const pe::PEImage& image) {
    const QList<QPair<QString, QString>> fields = {
        {tr("Machine"), QStringLiteral("%1 (%2)").arg(hex(image.machine, 4), qs(image.machineName))},
        {tr("Optional header magic"), image.is64Bit ? QStringLiteral("0x020B (PE32+)")
                                                    : QStringLiteral("0x010B (PE32)")},
        {tr("Subsystem"), QStringLiteral("%1 (%2)").arg(image.subsystem).arg(qs(image.subsystemName))},
        {tr("Subsystem version"),
         QStringLiteral("%1.%2").arg(image.subsystemMajor).arg(image.subsystemMinor)},
        {tr("OS version"), QStringLiteral("%1.%2").arg(image.osMajor).arg(image.osMinor)},
        {tr("Linker version"), QStringLiteral("%1.%2").arg(image.linkerMajor).arg(image.linkerMinor)},
        {tr("Image base"), hex(image.imageBase, image.is64Bit ? 16 : 8)},
        {tr("Entry point RVA"), hex(image.entryPointRva)},
        {tr("Entry point VA"), hex(image.entryPointVa(), image.is64Bit ? 16 : 8)},
        {tr("Size of image"), hex(image.sizeOfImage)},
        {tr("Size of headers"), hex(image.sizeOfHeaders)},
        {tr("Section alignment"), hex(image.sectionAlignment)},
        {tr("File alignment"), hex(image.fileAlignment)},
        {tr("Timestamp"), QStringLiteral("%1 (%2)").arg(hex(image.timestamp)).arg(
                              image.timestampUtc.empty() ? tr("none") : qs(image.timestampUtc))},
        {tr("Checksum (header)"), hex(image.headerChecksum)},
        {tr("Checksum (computed)"), hex(image.computedChecksum)},
        {tr("File characteristics"), QStringLiteral("%1  %2").arg(
                                         hex(image.fileCharacteristics, 4),
                                         joined(image.fileCharacteristicFlags, " | "))},
        {tr("DLL characteristics"), QStringLiteral("%1  %2").arg(
                                        hex(image.dllCharacteristics, 4),
                                        joined(image.dllCharacteristicFlags, " | "))},
        {tr("Number of sections"), QString::number(image.sections.size())},
        {tr("PDB path"), qs(image.pdbPath)},
    };
    m_headers->setSortingEnabled(false);
    m_headers->setRowCount(static_cast<int>(fields.size()));
    int r = 0;
    for (const auto& [key, value] : fields) {
        m_headers->setItem(r, 0, cell(key));
        m_headers->setItem(r, 1, cell(value));
        ++r;
    }
    m_headers->resizeColumnsToContents();
}

void DashboardWidget::fillSignature(const pe::PEImage& image) {
    const pe::SignatureInfo& sig = image.signature;
    QString html;
    if (!sig.hasEmbeddedSignature) {
        html = tr("<h3>No embedded signature</h3>"
                  "<p style='color:#9a9a9a'>The security directory is empty. Windows inbox "
                  "drivers are often catalog-signed instead, which this check doesn't see.</p>");
        m_signature->setText(html);
        return;
    }

    html += tr("<h3>Embedded Authenticode signature</h3>");
    html += QStringLiteral("<table>") +
            row(tr("Security directory"),
                tr("offset %1, %2 bytes").arg(hex(sig.securityDirectoryOffset)).arg(sig.securityDirectorySize)) +
            row(tr("Digest check"), sig.digestValid ? colored(tr("OK"), kGood)
                                                    : colored(qs(sig.verification).toHtmlEscaped(), kBad)) +
            QStringLiteral("</table>");
    html += tr("<p style='color:#9a9a9a'>The digest check confirms the signature blob is "
               "well-formed and matches the file. It does not check the chain against the "
               "Windows root store.</p>");

    int n = 1;
    for (const auto& signer : sig.signers) {
        html += tr("<h4>Signer %1</h4>").arg(n++);
        html += QStringLiteral("<table>") + row(tr("Subject"), qs(signer.subject).toHtmlEscaped()) +
                row(tr("Issuer"), qs(signer.issuer).toHtmlEscaped()) +
                row(tr("Serial"), qs(signer.serialNumber)) +
                row(tr("Digest"), qs(signer.digestAlgorithm)) +
                row(tr("Signing time"),
                    signer.signingTime.empty() ? tr("(not in signer attributes)") : qs(signer.signingTime)) +
                QStringLiteral("</table>");
    }
    if (!sig.certificateSubjects.empty()) {
        html += tr("<h4>Certificates in signature</h4><ul>");
        for (const auto& subject : sig.certificateSubjects) {
            html += QStringLiteral("<li>%1</li>").arg(qs(subject).toHtmlEscaped());
        }
        html += QStringLiteral("</ul>");
    }
    m_signature->setText(html);
}

} // namespace dasa::ui
