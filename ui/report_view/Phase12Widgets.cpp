#include "ui/report_view/Phase12Widgets.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QShowEvent>
#include <QSplitter>
#include <QTableWidget>
#include <QTextBrowser>
#include <QThreadPool>
#include <QUrl>
#include <QVBoxLayout>

#include <set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#endif

#include "analysis/diff/AnalysisDiff.h"
#include "analysis/report/Assessment.h"
#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/database/AnalysisDatabase.h"
#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace {

constexpr int kRvaRole = Qt::UserRole + 1;
constexpr int kPathRole = Qt::UserRole + 2;

QString q(const std::string& s) {
    return QString::fromStdString(s).toHtmlEscaped();
}

QString hexRva(std::uint64_t v) {
    return QStringLiteral("0x") + QStringLiteral("%1").arg(v, 8, 16, QLatin1Char('0')).toUpper();
}

QVBoxLayout* dockLayout(QWidget* w) {
    auto* layout = new QVBoxLayout(w);
    layout->setContentsMargins(16, 10, 16, 10);
    layout->setSpacing(8);
    return layout;
}

QTextBrowser* makeBrowser(QWidget* parent) {
    auto* b = new QTextBrowser(parent);
    b->setOpenLinks(false);
    b->setFrameShape(QFrame::NoFrame);
    b->setMinimumHeight(60);
    return b;
}

QString list(const std::vector<std::string>& items) {
    if (items.empty()) {
        return QStringLiteral("<p style='color:#9a9a9a'>none</p>");
    }
    QString html = QStringLiteral("<ul>");
    for (const auto& s : items) {
        html += QStringLiteral("<li>") + q(s) + QStringLiteral("</li>");
    }
    return html + QStringLiteral("</ul>");
}

} // namespace

// ============================================================= Assessment ==

AssessmentWidget::AssessmentWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    auto* bar = new QHBoxLayout;
    bar->addStretch(1);
    m_export = new QPushButton(tr("Export HTML Report..."), this);
    bar->addWidget(m_export);
    layout->addLayout(bar);
    m_view = makeBrowser(this);
    layout->addWidget(m_view, 1);
    connect(m_export, &QPushButton::clicked, this, &AssessmentWidget::exportRequested);
    connect(m_view, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
        bool ok = false;
        const auto rva = url.path().toULongLong(&ok, 16);
        if (ok && url.scheme() == QLatin1String("fn")) {
            emit functionActivated(rva);
        }
    });
    clear();
}

void AssessmentWidget::clear() {
    m_export->setEnabled(false);
    m_view->setHtml(tr("<p style='color:#9a9a9a'>Load a driver for its security assessment.</p>"));
}

void AssessmentWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    const auto a = analysis::assess(*result);
    m_export->setEnabled(true);
    QString html;
    html += QStringLiteral("<p style='font-size:14pt; font-weight:600'>%1</p>").arg(q(a.headline));
    html += QStringLiteral("<p><span style='font-size:13pt; color:%1'><b>%2/100 &middot; %3 risk</b></span></p>")
                .arg(riskLevelColor(QString::fromStdString(a.level)).name())
                .arg(a.score)
                .arg(q(a.level));
    html += QStringLiteral("<p>") + q(a.verdict) + QStringLiteral("</p>");
    html += tr("<h3>How user mode reaches it</h3>") + list(a.exposure);
    html += tr("<h3>Top risks</h3>");
    if (a.topRisks.empty()) {
        html += tr("<p style='color:#9a9a9a'>No medium-or-higher findings.</p>");
    } else {
        html += QStringLiteral("<ol>");
        for (const auto& r : a.topRisks) {
            const QColor c = riskLevelColor(QString::fromStdString(r.severity));
            html += QStringLiteral("<li><span style='color:%1'><b>%2</b></span> &middot; %3 <span style='color:#9a9a9a'>"
                                   "(%4 confidence, %5)</span>")
                        .arg(c.name(), q(r.severity), q(r.title), q(r.confidence), q(r.ruleId));
            if (r.function) {
                html += tr(" &middot; <a href='fn:%1'>open code</a>").arg(*r.function, 0, 16);
            }
            html += QStringLiteral("</li>");
        }
        html += QStringLiteral("</ol>");
    }
    html += tr("<h3>Protections in place</h3>") + list(a.protections);
    html += tr("<h3>Missing protections</h3>") + list(a.gaps);
    html += tr("<h3>Next steps</h3>") + list(a.nextSteps);
    html += tr("<h3>Coverage and limits</h3>") + list(a.coverage);
    html += tr("<p style='color:#9a9a9a'>Generated from the findings and analysis stages; the score is for triage, "
               "not a measure of exploitability.</p>");
    m_view->setHtml(html);
}

// ======================================================= Current analysis ==

CurrentAnalysisWidget::CurrentAnalysisWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    m_view = makeBrowser(this);
    layout->addWidget(m_view, 1);
    clear();
}

void CurrentAnalysisWidget::clear() {
    m_view->setHtml(tr("<p style='color:#9a9a9a'>No driver loaded. Drop a .sys file on the window or press "
                       "Ctrl+O.</p>"));
}

void CurrentAnalysisWidget::showLoading(const QString& path) {
    m_view->setHtml(tr("<p><b>Analysing</b> %1 ...</p>").arg(path.toHtmlEscaped()));
}

void CurrentAnalysisWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result, qint64 storedId) {
    const auto& r = *result;
    auto row = [](const QString& stage, const QString& produced, double seconds) {
        return QStringLiteral("<tr><td style='padding-right:18px'><b>%1</b></td><td style='padding-right:18px'>%2</td>"
                              "<td style='color:#9a9a9a'>%3</td></tr>")
            .arg(stage, produced, seconds >= 0 ? QStringLiteral("%1 s").arg(seconds, 0, 'f', 2) : QString());
    };
    QString html = QStringLiteral("<p style='font-size:13pt; font-weight:600'>%1</p><p style='color:#9a9a9a'>%2</p>")
                       .arg(q(r.image->fileName), q(r.image->path.string()));
    html += QStringLiteral("<table>");
    html += row(tr("PE parsing"),
                tr("%1 sections, %2 import libraries, %3 exports")
                    .arg(r.image->sections.size())
                    .arg(r.image->imports.size())
                    .arg(r.image->exports.size()),
                r.parseSeconds);
    html += row(tr("Functions"),
                tr("%1 functions, %2 instructions").arg(r.functions->functions.size()).arg(r.functions->totalInstructions()),
                r.functionSeconds);
    html += row(tr("Driver model"),
                tr("%1, %2 dispatch entries, %3 KMDF queues")
                    .arg(QString::fromLatin1(core::driver::modelName(r.driver->model.kind)))
                    .arg(r.driver->majorFunctions.size())
                    .arg(r.driver->wdfQueues.size()),
                r.driverSeconds);
    html += row(tr("Attack surface"),
                tr("%1 IOCTLs, %2 device objects, %3 links, %4 kernel APIs")
                    .arg(r.ioctls->ioctls.size())
                    .arg(r.devices->devices.size())
                    .arg(r.devices->symbolicLinks.size())
                    .arg(r.kernelApis->apis.size()),
                r.surfaceSeconds);
    html += row(tr("Data flow"),
                tr("%1 flows from %2 handler(s), %3 sensitive calls checked")
                    .arg(r.dataflow->flows.size())
                    .arg(r.dataflow->entries.size())
                    .arg(r.dataflow->checkedCalls.size()),
                -1);
    html += row(tr("Findings"),
                tr("%1 findings, risk %2/100 (%3)")
                    .arg(r.findings->findings.size())
                    .arg(r.findings->risk.score)
                    .arg(q(r.findings->risk.level)),
                -1);
    html += row(tr("Database"), storedId > 0 ? tr("saved as analysis #%1").arg(storedId) : tr("not saved"), -1);
    html += QStringLiteral("</table>");

    auto notes = [&](const QString& title, const std::vector<std::string>& n) {
        if (n.empty()) {
            return QString();
        }
        return QStringLiteral("<h3>%1</h3>").arg(title) + list(n);
    };
    html += notes(tr("Driver model notes"), r.driver->notes);
    html += notes(tr("IOCTL notes"), r.ioctls->notes);
    html += notes(tr("Device notes"), r.devices->notes);
    html += notes(tr("Data-flow notes"), r.dataflow->notes);
    html += notes(tr("Findings notes"), r.findings->notes);
    m_view->setHtml(html);
}

// =================================================================== Diff ==

DiffWidget::DiffWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    auto* bar = new QHBoxLayout;
    bar->setSpacing(10);
    m_choose = new QPushButton(tr("Compare With File..."), this);
    m_otherIsOlder = new QCheckBox(tr("Chosen file is the older version"), this);
    m_otherIsOlder->setChecked(true);
    m_hideIdentical = new QCheckBox(tr("Hide identical functions"), this);
    m_hideIdentical->setChecked(true);
    bar->addWidget(m_choose);
    bar->addWidget(m_otherIsOlder);
    bar->addWidget(m_hideIdentical);
    bar->addStretch(1);
    layout->addLayout(bar);
    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::RichText);
    m_summary->setWordWrap(true);
    layout->addWidget(m_summary);

    auto* splitter = new QSplitter(Qt::Horizontal, this);
    m_table = new QTableWidget(0, 6, splitter);
    m_table->setHorizontalHeaderLabels({tr("Change"), tr("Old"), tr("New"), tr("Instructions"), tr("Matched by"),
                                        tr("Import calls")});
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(26);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setAlternatingRowColors(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_details = makeBrowser(splitter);
    splitter->addWidget(m_table);
    splitter->addWidget(m_details);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    layout->addWidget(splitter, 1);

    connect(m_choose, &QPushButton::clicked, this, &DiffWidget::chooseFile);
    connect(m_otherIsOlder, &QCheckBox::toggled, this, [this] {
        if (m_other) showDiff(m_other);
    });
    connect(m_hideIdentical, &QCheckBox::toggled, this, [this] {
        if (m_other) showDiff(m_other);
    });
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        const QVariant rva = m_table->item(row, 0)->data(kRvaRole);
        if (rva.isValid() && rva.toULongLong() != 0) {
            emit functionActivated(rva.toULongLong());
        }
    });
    clear();
}

void DiffWidget::clear() {
    ++m_generation;
    m_result.reset();
    m_other.reset();
    m_choose->setEnabled(false);
    m_table->setRowCount(0);
    m_details->clear();
    m_summary->setText(tr("Load a driver, then compare it with another version of it (patch diffing) or any other "
                          "driver."));
}

void DiffWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    ++m_generation;
    m_result = std::move(result);
    m_other.reset();
    m_choose->setEnabled(true);
    m_table->setRowCount(0);
    m_details->clear();
    m_summary->setText(tr("Choose another version of <b>%1</b> to compare with.")
                           .arg(q(m_result->image->fileName)));
}

void DiffWidget::chooseFile() {
    const QString start = QFileInfo(QString::fromStdString(m_result->image->path.string())).absolutePath();
    const QString path = QFileDialog::getOpenFileName(this, tr("Compare With"), start,
                                                      tr("Windows drivers (*.sys);;All files (*)"));
    if (!path.isEmpty()) {
        compareWith(path);
    }
}

void DiffWidget::compareWith(const QString& path) {
    const quint64 generation = ++m_generation;
    m_summary->setText(tr("Analysing %1 ...").arg(path.toHtmlEscaped()));
    m_choose->setEnabled(false);
    QPointer<DiffWidget> self(this);
    const std::filesystem::path fsPath = QDir::toNativeSeparators(path).toStdWString();
    QThreadPool::globalInstance()->start([self, generation, fsPath, path]() {
        std::shared_ptr<const analysis::AnalysisResult> other;
        QString error;
        try {
            other = analysis::runStaticAnalysis(fsPath);
        } catch (const std::exception& ex) {
            error = QString::fromStdString(ex.what());
        }
        QMetaObject::invokeMethod(
            qApp,
            [self, generation, other, error, path]() {
                if (!self || generation != self->m_generation) {
                    return;
                }
                self->m_choose->setEnabled(true);
                if (!other) {
                    self->m_summary->setText(tr("Could not analyse %1: %2").arg(path.toHtmlEscaped(), error.toHtmlEscaped()));
                    return;
                }
                self->showDiff(other);
            },
            Qt::QueuedConnection);
    });
}

void DiffWidget::showDiff(std::shared_ptr<const analysis::AnalysisResult> other) {
    m_other = std::move(other);
    const bool otherOld = m_otherIsOlder->isChecked();
    const auto& oldR = otherOld ? *m_other : *m_result;
    const auto& newR = otherOld ? *m_result : *m_other;
    const auto d = analysis::diffAnalyses(oldR, newR);

    m_summary->setText(
        tr("<b>%1</b> &rarr; <b>%2</b>%3 &nbsp; <span style='color:#f1706b'>%4 changed</span> &middot; "
           "<span style='color:#6cc68a'>%5 added</span> &middot; <span style='color:#e5a54b'>%6 removed</span> "
           "&middot; %7 identical &nbsp; risk %8 &rarr; %9")
            .arg(q(d.oldFile), q(d.newFile))
            .arg(d.sameFile ? tr(" (same file)") : QString())
            .arg(d.changed)
            .arg(d.added)
            .arg(d.removed)
            .arg(d.identical)
            .arg(d.riskOld)
            .arg(d.riskNew));

    const bool hide = m_hideIdentical->isChecked();
    m_table->setRowCount(0);
    for (const auto& f : d.functions) {
        if (hide && f.change == analysis::FunctionChange::Identical) {
            continue;
        }
        const int row = m_table->rowCount();
        m_table->insertRow(row);
        auto* change = new QTableWidgetItem(QString::fromLatin1(analysis::functionChangeName(f.change)) +
                                            (f.touchesRiskyApi ? QStringLiteral(" !") : QString()));
        const QColor color = f.change == analysis::FunctionChange::Changed ? QColor(0xf1, 0x70, 0x6b)
                             : f.change == analysis::FunctionChange::Added ? QColor(0x6c, 0xc6, 0x8a)
                             : f.change == analysis::FunctionChange::Removed ? QColor(0xe5, 0xa5, 0x4b)
                                                                               : QColor(0x9a, 0x9a, 0x9a);
        change->setForeground(QBrush(color));
        if (f.touchesRiskyApi) {
            change->setToolTip(tr("Calls a high- or critical-risk kernel API"));
        }
        // Double-click opens the function in the loaded driver.
        const std::uint64_t mine = otherOld ? f.newRva : f.oldRva;
        change->setData(kRvaRole, static_cast<qulonglong>(mine));
        m_table->setItem(row, 0, change);
        m_table->setItem(row, 1, new QTableWidgetItem(f.oldRva ? QString::fromStdString(f.oldName) + "  " + hexRva(f.oldRva)
                                                               : QStringLiteral("-")));
        m_table->setItem(row, 2, new QTableWidgetItem(f.newRva ? QString::fromStdString(f.newName) + "  " + hexRva(f.newRva)
                                                               : QStringLiteral("-")));
        m_table->setItem(row, 3, new QTableWidgetItem(QStringLiteral("%1 \u2192 %2").arg(f.oldInstructions).arg(f.newInstructions)));
        m_table->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(f.matchedBy)));
        QStringList calls;
        for (const auto& s : f.importsAdded) calls << QStringLiteral("+") + QString::fromStdString(s.substr(s.find('!') + 1));
        for (const auto& s : f.importsRemoved) calls << QStringLiteral("-") + QString::fromStdString(s.substr(s.find('!') + 1));
        m_table->setItem(row, 5, new QTableWidgetItem(calls.join(QStringLiteral(" "))));
    }
    for (int c = 0; c < 5; ++c) {
        m_table->resizeColumnToContents(c);
    }

    auto delta = [](const QString& title, const analysis::NamedDelta& nd) {
        if (nd.added.empty() && nd.removed.empty()) {
            return QString();
        }
        QString html = QStringLiteral("<p><b>%1</b></p><ul>").arg(title);
        for (const auto& s : nd.added) html += QStringLiteral("<li style='color:#6cc68a'>+ ") + q(s) + QStringLiteral("</li>");
        for (const auto& s : nd.removed) html += QStringLiteral("<li style='color:#e5a54b'>- ") + q(s) + QStringLiteral("</li>");
        return html + QStringLiteral("</ul>");
    };
    QString html = delta(tr("Findings"), d.findings) + delta(tr("IOCTLs"), d.ioctls) + delta(tr("Devices and links"), d.devices) +
                   delta(tr("Imports"), d.imports) + delta(tr("Exports"), d.exports) + delta(tr("Sections"), d.sections);
    if (html.isEmpty()) {
        html = tr("<p style='color:#9a9a9a'>No differences in findings, IOCTLs, devices, imports, exports or "
                  "sections.</p>");
    }
    html += tr("<p style='color:#9a9a9a'>Functions are matched by an address-independent fingerprint, then by "
               "name, then by the imports they call and their size. \"!\" marks functions that call a high- or "
               "critical-risk API - the first place to look for a security fix.</p>");
    m_details->setHtml(html);
}

// ================================================================ Drivers ==

namespace {

struct DriverFile {
    QString path;
    QString company;
    QString version;
    QString description;
    qint64 size = 0;
    bool loaded = false;
};

#ifdef _WIN32
QString versionString(const std::vector<BYTE>& data, const wchar_t* key) {
    struct LangCodepage {
        WORD lang;
        WORD codepage;
    }* translations = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations), &len) ||
        len < sizeof(LangCodepage)) {
        return {};
    }
    wchar_t sub[128];
    swprintf_s(sub, L"\\StringFileInfo\\%04x%04x\\%s", translations[0].lang, translations[0].codepage, key);
    wchar_t* value = nullptr;
    UINT valueLen = 0;
    if (VerQueryValueW(data.data(), sub, reinterpret_cast<void**>(&value), &valueLen) && valueLen > 0) {
        return QString::fromWCharArray(value).trimmed();
    }
    return {};
}

void readVersionInfo(DriverFile& f) {
    const std::wstring path = QDir::toNativeSeparators(f.path).toStdWString();
    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) {
        return;
    }
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) {
        return;
    }
    f.company = versionString(data, L"CompanyName");
    f.version = versionString(data, L"FileVersion");
    f.description = versionString(data, L"FileDescription");
}

// Kernel-module paths come as \SystemRoot\..., \??\C:\... or System32\...
QString normaliseModulePath(QString p) {
    const QString root = QString::fromLocal8Bit(qgetenv("SystemRoot"));
    if (p.startsWith(QLatin1String("\\SystemRoot\\"), Qt::CaseInsensitive)) {
        p = root + p.mid(11);
    } else if (p.startsWith(QLatin1String("\\??\\"))) {
        p = p.mid(4);
    } else if (p.startsWith(QLatin1String("System32\\"), Qt::CaseInsensitive)) {
        p = root + QLatin1Char('\\') + p;
    }
    return p;
}

// Running driver services and their image paths, from the Service Control
// Manager. Works without administrator rights, unlike EnumDeviceDrivers,
// whose list recent Windows builds restrict for non-admin processes.
void addActiveDriverServices(QSet<QString>& out) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        return;
    }
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, nullptr, 0, &needed, &count,
                          &resume, nullptr);
    std::vector<BYTE> buffer(needed + 1024);
    resume = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &needed, &count, &resume, nullptr)) {
        const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        const QString root = QString::fromLocal8Bit(qgetenv("SystemRoot"));
        for (DWORD i = 0; i < count; ++i) {
            QString path;
            if (SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG)) {
                DWORD cfgNeeded = 0;
                QueryServiceConfigW(svc, nullptr, 0, &cfgNeeded);
                std::vector<BYTE> cfg(cfgNeeded + 16);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg.data());
                if (QueryServiceConfigW(svc, config, static_cast<DWORD>(cfg.size()), &cfgNeeded) &&
                    config->lpBinaryPathName && *config->lpBinaryPathName) {
                    path = normaliseModulePath(QString::fromWCharArray(config->lpBinaryPathName).trimmed());
                }
                CloseServiceHandle(svc);
            }
            if (path.isEmpty()) {
                // No ImagePath: the default is System32\drivers\<service>.sys.
                path = root + QStringLiteral(R"(\System32\drivers\)") +
                       QString::fromWCharArray(services[i].lpServiceName) + QStringLiteral(".sys");
            }
            if (path.endsWith(QLatin1String(".sys"), Qt::CaseInsensitive)) {
                out.insert(QFileInfo(path).absoluteFilePath().toLower());
            }
        }
    }
    CloseServiceHandle(scm);
}

QSet<QString> loadedDriverPaths() {
    QSet<QString> out;
    addActiveDriverServices(out);
    std::vector<LPVOID> bases(4096);
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed)) {
        return out;
    }
    const std::size_t count = std::min<std::size_t>(needed / sizeof(LPVOID), bases.size());
    for (std::size_t i = 0; i < count; ++i) {
        wchar_t name[MAX_PATH];
        if (GetDeviceDriverFileNameW(bases[i], name, MAX_PATH)) {
            out.insert(QFileInfo(normaliseModulePath(QString::fromWCharArray(name))).absoluteFilePath().toLower());
        }
    }
    return out;
}
#else
void readVersionInfo(DriverFile&) {}
QSet<QString> loadedDriverPaths() {
    return {};
}
#endif

} // namespace

DriversWidget::DriversWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    auto* bar = new QHBoxLayout;
    bar->setSpacing(10);
    m_source = new QComboBox(this);
    m_source->addItem(tr("Loaded right now"));
    m_source->addItem(tr("System32\\drivers"));
    m_source->addItem(tr("Folder..."));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("Filter by name, company or description"));
    m_filter->setClearButtonEnabled(true);
    m_thirdParty = new QCheckBox(tr("Third-party only"), this);
    m_thirdParty->setChecked(true);
    m_thirdParty->setToolTip(tr("Hide drivers whose company is Microsoft"));
    m_rescan = new QPushButton(tr("Rescan"), this);
    bar->addWidget(m_source);
    bar->addWidget(m_filter, 1);
    bar->addWidget(m_thirdParty);
    bar->addWidget(m_rescan);
    layout->addLayout(bar);
    m_status = new QLabel(this);
    m_status->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_status);
    m_table = new QTableWidget(0, 6, this);
    m_table->setHorizontalHeaderLabels({tr("Driver"), tr("Company"), tr("Description"), tr("Version"), tr("Size"),
                                        tr("Analysed")});
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(26);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_table->setMinimumHeight(60);
    layout->addWidget(m_table, 1);

    connect(m_source, &QComboBox::activated, this, [this](int index) {
        if (index == 2) {
            const QString dir = QFileDialog::getExistingDirectory(this, tr("Folder with drivers"), m_folder);
            if (dir.isEmpty()) {
                return;
            }
            m_folder = dir;
            m_source->setItemText(2, tr("Folder: %1").arg(QDir::toNativeSeparators(dir)));
        }
        scan();
    });
    connect(m_rescan, &QPushButton::clicked, this, &DriversWidget::scan);
    connect(m_filter, &QLineEdit::textChanged, this, &DriversWidget::applyFilter);
    connect(m_thirdParty, &QCheckBox::toggled, this, &DriversWidget::applyFilter);
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        emit openDriverRequested(m_table->item(row, 0)->data(kPathRole).toString());
    });
    m_status->setText(tr("Click Rescan to list drivers."));
}

FileVersion fileVersionInfo(const QString& path) {
    DriverFile f;
    f.path = path;
    readVersionInfo(f);
    return {f.company, f.description, f.version};
}

void DriversWidget::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    if (!m_scanned) {
        m_scanned = true; // list the drivers as soon as the tab is first opened
        scan();
    }
}

void DriversWidget::setDatabase(std::shared_ptr<core::database::AnalysisDatabase> db) {
    m_db = std::move(db);
}

void DriversWidget::scan() {
    const quint64 generation = ++m_generation;
    const int source = m_source->currentIndex();
    const QString folder = source == 1 ? QString::fromLocal8Bit(qgetenv("SystemRoot")) + QStringLiteral("\\System32\\drivers")
                           : source == 2 ? m_folder
                                         : QString();
    if (source == 2 && folder.isEmpty()) {
        m_status->setText(tr("Choose a folder."));
        return;
    }
    std::set<std::string> analysedPaths;
    if (m_db) {
        try {
            for (const auto& s : m_db->list(100000)) {
                analysedPaths.insert(QString::fromStdString(s.filePath).toLower().toStdString());
            }
        } catch (const std::exception&) {
        }
    }
    m_status->setText(tr("Scanning..."));
    m_rescan->setEnabled(false);
    QPointer<DriversWidget> self(this);
    QThreadPool::globalInstance()->start([self, generation, source, folder, analysedPaths]() {
        const QSet<QString> loaded = loadedDriverPaths();
        QStringList paths;
        if (source == 0) {
            for (const auto& p : loaded) paths << p;
        } else {
            const QDir dir(folder);
            for (const auto& info : dir.entryInfoList({QStringLiteral("*.sys")}, QDir::Files)) {
                paths << info.absoluteFilePath();
            }
        }
        std::vector<DriverFile> files;
        for (const auto& p : paths) {
            const QFileInfo info(p);
            if (!info.exists()) {
                continue;
            }
            DriverFile f;
            f.path = QDir::toNativeSeparators(info.absoluteFilePath());
            f.size = info.size();
            f.loaded = loaded.contains(info.absoluteFilePath().toLower());
            readVersionInfo(f);
            files.push_back(std::move(f));
        }
        QMetaObject::invokeMethod(
            qApp,
            [self, generation, files, analysedPaths, source]() {
                if (!self || generation != self->m_generation) {
                    return;
                }
                auto* t = self->m_table;
                t->setSortingEnabled(false);
                t->setRowCount(static_cast<int>(files.size()));
                for (int i = 0; i < static_cast<int>(files.size()); ++i) {
                    const auto& f = files[static_cast<std::size_t>(i)];
                    auto* name = new QTableWidgetItem(QFileInfo(f.path).fileName());
                    name->setData(kPathRole, f.path);
                    name->setToolTip(f.path + (f.loaded ? tr("\nloaded now") : QString()));
                    t->setItem(i, 0, name);
                    t->setItem(i, 1, new QTableWidgetItem(f.company));
                    t->setItem(i, 2, new QTableWidgetItem(f.description));
                    t->setItem(i, 3, new QTableWidgetItem(f.version));
                    auto* size = new QTableWidgetItem;
                    size->setData(Qt::DisplayRole, static_cast<qlonglong>((f.size + 1023) / 1024));
                    t->setItem(i, 4, size);
                    const bool analysed =
                        analysedPaths.count(QDir::fromNativeSeparators(f.path).toLower().toStdString()) ||
                        analysedPaths.count(f.path.toLower().toStdString());
                    t->setItem(i, 5, new QTableWidgetItem(analysed ? tr("yes") : QString()));
                }
                t->setSortingEnabled(true);
                t->sortByColumn(0, Qt::AscendingOrder);
                t->resizeColumnToContents(0);
                t->resizeColumnToContents(1);
                t->resizeColumnToContents(3);
                t->resizeColumnToContents(4);
                self->m_rescan->setEnabled(true);
                self->applyFilter();
                (void)source;
            },
            Qt::QueuedConnection);
    });
}

void DriversWidget::applyFilter() {
    const QString text = m_filter->text().trimmed();
    const bool thirdParty = m_thirdParty->isChecked();
    int shown = 0;
    for (int row = 0; row < m_table->rowCount(); ++row) {
        const QString name = m_table->item(row, 0)->text();
        const QString company = m_table->item(row, 1)->text();
        const QString desc = m_table->item(row, 2)->text();
        bool visible = text.isEmpty() || name.contains(text, Qt::CaseInsensitive) ||
                       company.contains(text, Qt::CaseInsensitive) || desc.contains(text, Qt::CaseInsensitive);
        if (thirdParty && company.contains(QLatin1String("Microsoft"), Qt::CaseInsensitive)) {
            visible = false;
        }
        m_table->setRowHidden(row, !visible);
        shown += visible;
    }
    m_status->setText(tr("%1 of %2 drivers shown. Size in KB. Double-click to analyse.")
                          .arg(shown)
                          .arg(m_table->rowCount()));
}

} // namespace dasa::ui
