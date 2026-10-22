#include "app/MainWindow.h"

#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QDockWidget>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QMenuBar>
#include <QMimeData>
#include <QStatusBar>
#include <QTabBar>
#include <QPointer>
#include <QScrollArea>
#include <QStandardPaths>
#include <QThreadPool>
#include <QUrl>
#include <filesystem>
#include <spdlog/spdlog.h>

#include "analysis/report/ReportWriter.h"
#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/database/AnalysisDatabase.h"
#include "ui/dashboard/DashboardWidget.h"
#include "ui/dataflow_view/DataFlowWidget.h"
#include "ui/graph_view/CallGraphWidget.h"
#include "ui/graph_view/ControlFlowWidget.h"
#include "ui/database_view/CompareWidget.h"
#include "ui/database_view/HistoryWidget.h"
#include "ui/driver_view/DevicesWidget.h"
#include "ui/findings_view/EvidenceWidget.h"
#include "ui/findings_view/FindingsWidget.h"
#include "ui/findings_view/SeverityColors.h"
#include "ui/driver_view/DriverModelWidget.h"
#include "ui/function_view/FunctionsWidget.h"
#include "ui/ioctl_view/IoctlWidget.h"
#include "ui/report_view/ExportWidget.h"
#include "ui/security_view/KernelApiWidget.h"

namespace dasa::app {

namespace {

// Dock titles mirror the brief's four nav groups (WORKSPACE / RESEARCH /
// DYNAMIC / DATABASE) plus REPORTS. Views not built yet show a short
// "not built yet" note; the phase that implements a view swaps in its
// widget (ui/dashboard, ui/function_view, ... per the architecture
// proposal).
struct DockSpec {
    const char* title;
    const char* objectName;
};

constexpr DockSpec kWorkspaceDocks[] = {
    {"Dashboard", "dock_dashboard"},
    {"Drivers", "dock_drivers"},
    {"Current Analysis", "dock_current_analysis"},
    {"Functions", "dock_functions"},
    {"IOCTLs", "dock_ioctls"},
    {"Devices", "dock_devices"},
    {"IRP Handlers", "dock_irp_handlers"},
    {"Call Graph", "dock_call_graph"},
    {"Control Flow", "dock_control_flow"},
    {"Data Flow", "dock_data_flow"},
    {"Findings", "dock_findings"},
    {"Evidence", "dock_evidence"},
    {"Diff", "dock_diff"},
};

constexpr DockSpec kResearchDocks[] = {
    {"Search", "dock_search"},
    {"Bookmarks", "dock_bookmarks"},
    {"Notes", "dock_notes"},
    {"Tags", "dock_tags"},
    {"Investigation Workspace", "dock_investigation_workspace"},
};

constexpr DockSpec kDynamicDocks[] = {
    {"VM", "dock_vm"},
    {"Driver Verifier", "dock_driver_verifier"},
    {"WinDbg", "dock_windbg"},
    {"Runtime Events", "dock_runtime_events"},
    {"Crash Analysis", "dock_crash_analysis"},
};

constexpr DockSpec kDatabaseDocks[] = {
    {"Analysis History", "dock_analysis_history"},
    {"Compare Drivers", "dock_compare_drivers"},
    {"Previous Findings", "dock_previous_findings"},
};

constexpr DockSpec kReportDocks[] = {
    {"Security Assessment", "dock_security_assessment"},
    {"Export", "dock_export"},
};

// First local .sys file in a drag payload, or an empty string.
QString firstDriverPath(const QMimeData* mime) {
    if (mime && mime->hasUrls()) {
        for (const QUrl& url : mime->urls()) {
            if (url.isLocalFile() && url.toLocalFile().endsWith(".sys", Qt::CaseInsensitive)) {
                return url.toLocalFile();
            }
        }
    }
    return {};
}

bool containsDriverUrl(const QMimeData* mime) {
    return !firstDriverPath(mime).isEmpty();
}

// Bump when the default dock arrangement changes so previously saved
// layouts are discarded instead of restored over the new default.
constexpr int kLayoutVersion = 6;
constexpr int kRightColumnWidth = 330;
constexpr int kBottomStripHeight = 200;

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      m_settings("DASA Project", "DASA") {
    setObjectName("DASAMainWindow");
    setAcceptDrops(true);
    resize(1600, 980);

    buildMenus();
    buildDockLayout();
    buildStatusBar();
    openDatabase();
    restoreLayout();

    spdlog::info("MainWindow constructed");
}

MainWindow::~MainWindow() = default;

void MainWindow::openDatabase() {
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(dir);
    m_dbPath = QDir(dir).filePath(QStringLiteral("dasa.db"));
    QString error;
    try {
        m_db = std::make_shared<core::database::AnalysisDatabase>(m_dbPath.toStdWString());
        spdlog::info("Analysis database: {}", m_dbPath.toStdString());
    } catch (const std::exception& ex) {
        error = QString::fromStdString(ex.what());
        spdlog::warn("Could not open the analysis database {}: {}", m_dbPath.toStdString(), ex.what());
    }
    m_history->setDatabase(m_db, m_dbPath, error);
    m_compare->setDatabase(m_db);
    m_previousFindings->setDatabase(m_db);
}

void MainWindow::buildMenus() {
    auto* fileMenu = menuBar()->addMenu(tr("&File"));
    QAction* openAction = fileMenu->addAction(tr("&Open Driver..."));
    openAction->setShortcut(QKeySequence::Open);
    connect(openAction, &QAction::triggered, this, [this]() {
        const QString startDir = m_settings.value("lastDriverDir").toString();
        const QString path = QFileDialog::getOpenFileName(
            this, tr("Open Driver"), startDir,
            tr("Windows drivers (*.sys);;All files (*)"));
        if (!path.isEmpty()) {
            loadDriver(path);
        }
    });
    fileMenu->addSeparator();
    QAction* exportHtml = fileMenu->addAction(tr("Export &HTML Report..."));
    exportHtml->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
    QAction* exportJson = fileMenu->addAction(tr("Export &JSON..."));
    exportJson->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_E));
    const auto runExport = [this](bool html) {
        if (!m_export->hasResult()) {
            statusBar()->showMessage(tr("Load a driver first - there is nothing to export yet."), 5000);
            return;
        }
        if (html) {
            m_export->exportHtml();
        } else {
            m_export->exportJson();
        }
    };
    connect(exportHtml, &QAction::triggered, this, [runExport] { runExport(true); });
    connect(exportJson, &QAction::triggered, this, [runExport] { runExport(false); });
    fileMenu->addSeparator();
    QAction* exitAction = fileMenu->addAction(tr("E&xit"));
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);

    auto* viewMenu = menuBar()->addMenu(tr("&View"));
    viewMenu->addAction(tr("Reset Layout"), this, [this]() {
        m_settings.remove("mainWindow/geometry");
        m_settings.remove("mainWindow/state");
        spdlog::info("Layout reset requested (takes effect on restart)");
    });

    auto* helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(tr("&About DASA"), this, [this]() {
        spdlog::info("About dialog requested (not yet implemented)");
    });
}

QDockWidget* MainWindow::makeDock(const QString& title, const QString& objectName) {
    auto* dock = new QDockWidget(title, this);
    dock->setObjectName(objectName);
    dock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable |
                       QDockWidget::DockWidgetClosable);
    // Placeholder until the phase that implements this view replaces it, so
    // an unbuilt view reads as "not built yet" rather than as a blank area.
    auto* placeholder = new QLabel(
        tr("<p style='font-size:11pt; color:#c8c8c8'>%1</p>"
           "<p style='color:#8a8a8a'>Not built yet &mdash; this view arrives in a later phase.</p>")
            .arg(title.toHtmlEscaped()),
        dock);
    placeholder->setAlignment(Qt::AlignCenter);
    placeholder->setWordWrap(true);
    placeholder->setMargin(16);
    dock->setWidget(placeholder);
    return dock;
}

void MainWindow::buildDockLayout() {
    setDockNestingEnabled(true);
    setTabPosition(Qt::AllDockWidgetAreas, QTabWidget::North);

    QDockWidget* firstLeft = nullptr;
    for (const auto& spec : kWorkspaceDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        if (dock->objectName() == QLatin1String("dock_dashboard")) {
            // makeDock() gave it an empty placeholder; setWidget() doesn't
            // delete the old one.
            delete dock->widget();
            // In a scroll area: the Dashboard's content is tall once a driver
            // is loaded, and as a plain dock widget its minimum height pushed
            // the bottom strip and status bar off a 1080p screen.
            auto* scroll = new QScrollArea(dock);
            scroll->setWidgetResizable(true);
            scroll->setFrameShape(QFrame::NoFrame);
            m_dashboard = new ui::DashboardWidget(scroll);
            scroll->setWidget(m_dashboard);
            dock->setWidget(scroll);
            m_kernelApis = new ui::KernelApiWidget(m_dashboard);
            m_dashboard->insertTab(2, m_kernelApis, tr("Kernel APIs"));
        } else if (dock->objectName() == QLatin1String("dock_functions")) {
            delete dock->widget();
            m_functions = new ui::FunctionsWidget(dock);
            dock->setWidget(m_functions);
        } else if (dock->objectName() == QLatin1String("dock_irp_handlers")) {
            delete dock->widget();
            m_driverModel = new ui::DriverModelWidget(dock);
            dock->setWidget(m_driverModel);
        } else if (dock->objectName() == QLatin1String("dock_ioctls")) {
            delete dock->widget();
            m_ioctls = new ui::IoctlWidget(dock);
            dock->setWidget(m_ioctls);
        } else if (dock->objectName() == QLatin1String("dock_devices")) {
            delete dock->widget();
            m_devices = new ui::DevicesWidget(dock);
            dock->setWidget(m_devices);
        } else if (dock->objectName() == QLatin1String("dock_findings")) {
            delete dock->widget();
            m_findings = new ui::FindingsWidget(dock);
            dock->setWidget(m_findings);
        } else if (dock->objectName() == QLatin1String("dock_call_graph")) {
            delete dock->widget();
            m_callGraph = new ui::CallGraphWidget(dock);
            dock->setWidget(m_callGraph);
        } else if (dock->objectName() == QLatin1String("dock_control_flow")) {
            delete dock->widget();
            m_controlFlow = new ui::ControlFlowWidget(dock);
            dock->setWidget(m_controlFlow);
        } else if (dock->objectName() == QLatin1String("dock_data_flow")) {
            delete dock->widget();
            m_dataFlow = new ui::DataFlowWidget(dock);
            dock->setWidget(m_dataFlow);
        } else if (dock->objectName() == QLatin1String("dock_evidence")) {
            delete dock->widget();
            m_evidence = new ui::EvidenceWidget(dock);
            dock->setWidget(m_evidence);
        }
        addDockWidget(Qt::LeftDockWidgetArea, dock);
        if (firstLeft) {
            tabifyDockWidget(firstLeft, dock);
        } else {
            firstLeft = dock;
        }
    }

    // Double-clicking a handler (IRP Handlers) or an IOCTL (IOCTLs) opens
    // the function in Functions.
    auto openFunction = [this](std::uint64_t rva) {
        m_functions->showFunction(rva);
        if (auto* dock = findChild<QDockWidget*>(QStringLiteral("dock_functions"))) {
            dock->raise();
        }
    };
    connect(m_driverModel, &ui::DriverModelWidget::functionActivated, this, openFunction);
    connect(m_ioctls, &ui::IoctlWidget::functionActivated, this, openFunction);
    connect(m_kernelApis, &ui::KernelApiWidget::functionActivated, this, openFunction);
    connect(m_evidence, &ui::EvidenceWidget::functionActivated, this, openFunction);
    connect(m_dataFlow, &ui::DataFlowWidget::functionActivated, this, openFunction);
    connect(m_findings, &ui::FindingsWidget::findingSelected, m_evidence, &ui::EvidenceWidget::showFinding);

    // Control Flow follows the function selected in Functions. Choosing a
    // function in Call Graph or Control Flow selects it in Functions (which
    // moves Control Flow too) without switching tabs.
    connect(m_functions, &ui::FunctionsWidget::functionSelected, m_controlFlow,
            &ui::ControlFlowWidget::showFunction);
    connect(m_callGraph, &ui::CallGraphWidget::functionActivated, m_functions, &ui::FunctionsWidget::showFunction);
    connect(m_controlFlow, &ui::ControlFlowWidget::functionActivated, this, [this](std::uint64_t rva) {
        m_controlFlow->showFunction(rva);
        m_functions->showFunction(rva);
        m_callGraph->focusFunction(rva);
    });
    connect(m_callGraph, &ui::CallGraphWidget::controlFlowRequested, this, [this](std::uint64_t rva) {
        m_controlFlow->showFunction(rva);
        if (auto* dock = findChild<QDockWidget*>(QStringLiteral("dock_control_flow"))) {
            dock->raise();
        }
    });

    QDockWidget* firstRight = nullptr;
    for (const auto& spec : kResearchDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        addDockWidget(Qt::RightDockWidgetArea, dock);
        if (firstRight) {
            tabifyDockWidget(firstRight, dock);
        } else {
            firstRight = dock;
        }
    }

    QDockWidget* firstBottom = nullptr;
    for (const auto& spec : kDynamicDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        addDockWidget(Qt::BottomDockWidgetArea, dock);
        if (firstBottom) {
            tabifyDockWidget(firstBottom, dock);
        } else {
            firstBottom = dock;
        }
    }

    // Swaps a dock's "not built yet" placeholder for its view.
    const auto install = [](QDockWidget* dock, QWidget* view) {
        delete dock->widget();
        view->setParent(dock);
        dock->setWidget(view);
    };

    for (const auto& spec : kDatabaseDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        if (dock->objectName() == QLatin1String("dock_analysis_history")) {
            install(dock, m_history = new ui::HistoryWidget);
        } else if (dock->objectName() == QLatin1String("dock_compare_drivers")) {
            install(dock, m_compare = new ui::CompareWidget);
        } else if (dock->objectName() == QLatin1String("dock_previous_findings")) {
            install(dock, m_previousFindings = new ui::PreviousFindingsWidget);
        }
        addDockWidget(Qt::BottomDockWidgetArea, dock);
        tabifyDockWidget(firstBottom, dock);
    }

    // Reports share the bottom strip, which has room for their tabs; the
    // narrow right column keeps only the research views.
    for (const auto& spec : kReportDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        if (dock->objectName() == QLatin1String("dock_export")) {
            install(dock, m_export = new ui::ExportWidget);
        }
        addDockWidget(Qt::BottomDockWidgetArea, dock);
        tabifyDockWidget(firstBottom, dock);
    }

    connect(m_history, &ui::HistoryWidget::openDriverRequested, this, [this](const QString& path) {
        if (!QFileInfo::exists(path)) {
            statusBar()->showMessage(tr("%1 is no longer at that path.").arg(path), 6000);
            return;
        }
        loadDriver(path);
    });
    connect(m_history, &ui::HistoryWidget::compareRequested, this, [this](qint64 a, qint64 b) {
        m_compare->compare(a, b);
        if (auto* dock = findChild<QDockWidget*>(QStringLiteral("dock_compare_drivers"))) {
            dock->raise();
        }
    });
    connect(m_history, &ui::HistoryWidget::historyChanged, this, [this] { m_compare->refresh(); });
    connect(m_export, &ui::ExportWidget::exported, this, [this](const QString& path) {
        statusBar()->showMessage(tr("Exported %1").arg(QDir::toNativeSeparators(path)), 6000);
    });

    // Tabifying makes the most recently added dock current; open each group
    // on its first tab instead.
    for (QDockWidget* first : {firstLeft, firstRight, firstBottom}) {
        if (first) {
            first->raise();
        }
    }

    // With no central widget the bottom area would otherwise span the full
    // width and swallow most of the window. Give the right column the full
    // height, keep the bottom strip under the workspace only, and size the
    // groups so the workspace is the dominant area.
    setCorner(Qt::TopRightCorner, Qt::RightDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);
    setCorner(Qt::BottomLeftCorner, Qt::BottomDockWidgetArea);
    if (firstLeft && firstRight && firstBottom) {
        resizeDocks({firstLeft, firstRight}, {width() - kRightColumnWidth, kRightColumnWidth},
                    Qt::Horizontal);
        resizeDocks({firstLeft, firstBottom}, {height() - kBottomStripHeight, kBottomStripHeight},
                    Qt::Vertical);
    }
}

void MainWindow::buildStatusBar() {
    m_statusDriverLabel = new QLabel(tr("No driver loaded"), this);
    statusBar()->addWidget(m_statusDriverLabel);
    statusBar()->showMessage(tr("Ready"), 3000);
}

void MainWindow::restoreLayout() {
    // Geometry saved under an older layout can be one where the window
    // overflowed the screen, so only restore it alongside a current layout.
    if (m_settings.value("mainWindow/layoutVersion").toInt() != kLayoutVersion) {
        return;
    }
    if (m_settings.contains("mainWindow/geometry")) {
        restoreGeometry(m_settings.value("mainWindow/geometry").toByteArray());
    }
    // restoreState() rejects a state saved under a different version, so
    // layouts saved before the current default fall back to it.
    if (m_settings.contains("mainWindow/state")) {
        restoreState(m_settings.value("mainWindow/state").toByteArray(), kLayoutVersion);
    }
}

void MainWindow::saveLayout() {
    m_settings.setValue("mainWindow/geometry", saveGeometry());
    m_settings.setValue("mainWindow/state", saveState(kLayoutVersion));
    m_settings.setValue("mainWindow/layoutVersion", kLayoutVersion);
}

bool MainWindow::event(QEvent* event) {
    // QMainWindow creates a tab bar for each tabified dock group (and again
    // whenever the user re-docks) and forces Qt::ElideRight on it, which
    // turns labels into "Dashbo...", "Driv...". Keep full labels and let the
    // tab bar scroll instead.
    if (event->type() == QEvent::ChildPolished) {
        if (auto* tabBar = qobject_cast<QTabBar*>(static_cast<QChildEvent*>(event)->child())) {
            tabBar->setElideMode(Qt::ElideNone);
            tabBar->setUsesScrollButtons(true);
        }
    }
    return QMainWindow::event(event);
}

void MainWindow::closeEvent(QCloseEvent* event) {
    saveLayout();
    QMainWindow::closeEvent(event);
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (containsDriverUrl(event->mimeData())) {
        event->acceptProposedAction();
    }
}

void MainWindow::dragMoveEvent(QDragMoveEvent* event) {
    // Accept explicitly on every move: as the cursor crosses dock tab bars
    // and title bars, a move that isn't accepted turns the cursor into "no
    // drop" and the release is ignored.
    if (containsDriverUrl(event->mimeData())) {
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    const QString path = firstDriverPath(event->mimeData());
    if (!path.isEmpty()) {
        loadDriver(path);
        event->acceptProposedAction();
    }
}

void MainWindow::loadDriver(const QString& path) {
    const QFileInfo info(path);
    if (!info.exists() || !info.isFile()) {
        spdlog::warn("loadDriver: file does not exist: {}", path.toStdString());
        statusBar()->showMessage(tr("File not found: %1").arg(path), 5000);
        return;
    }
    if (info.suffix().compare("sys", Qt::CaseInsensitive) != 0) {
        spdlog::warn("loadDriver: not a .sys file: {}", path.toStdString());
        statusBar()->showMessage(tr("Not a .sys file: %1").arg(path), 5000);
        return;
    }

    spdlog::info("Driver file accepted: {}", path.toStdString());
    m_settings.setValue("lastDriverDir", info.absolutePath());
    const QString nativePath = QDir::toNativeSeparators(info.absoluteFilePath());
    m_statusDriverLabel->setText(tr("Analyzing %1...").arg(info.fileName()));
    setWindowTitle(tr("%1 - Driver Attack Surface Analyzer").arg(info.fileName()));
    m_dashboard->showLoading(nativePath);
    m_functions->clear();
    m_driverModel->clear();
    m_ioctls->clear();
    m_devices->clear();
    m_kernelApis->clear();
    m_findings->clear();
    m_evidence->clear();
    m_callGraph->clear();
    m_dataFlow->clear();
    m_controlFlow->clear();
    m_previousFindings->clear();
    m_export->clear();
    m_dashboard->setRiskSummary(QString());
    if (auto* dock = findChild<QDockWidget*>(QStringLiteral("dock_dashboard"))) {
        dock->show();
        dock->raise();
    }

    // Analyze off the GUI thread and hand the result back with a queued
    // call. The generation counter drops results from a load that was
    // superseded by a newer one while it was still running.
    const quint64 generation = ++m_loadGeneration;
    const std::filesystem::path fsPath = nativePath.toStdWString();
    QPointer<MainWindow> self(this);
    // The worker also saves the analysis, over its own database connection.
    const std::filesystem::path dbPath = m_db ? std::filesystem::path(m_dbPath.toStdWString())
                                              : std::filesystem::path();
    QThreadPool::globalInstance()->start([self, generation, fsPath, nativePath, dbPath]() {
        std::shared_ptr<const analysis::AnalysisResult> result;
        QString error;
        try {
            result = analysis::runStaticAnalysis(fsPath);
        } catch (const std::exception& ex) {
            error = QString::fromStdString(ex.what());
            spdlog::warn("Analysis failed for {}: {}", nativePath.toStdString(), ex.what());
        }
        qint64 storedId = 0;
        QString storeError;
        if (result && !dbPath.empty()) {
            try {
                core::database::AnalysisDatabase db(dbPath);
                storedId = analysis::saveAnalysis(db, *result);
            } catch (const std::exception& ex) {
                storeError = QString::fromStdString(ex.what());
                spdlog::warn("Could not save the analysis of {}: {}", nativePath.toStdString(), ex.what());
            }
        }
        QMetaObject::invokeMethod(
            qApp,
            [self, generation, nativePath, result, error, storedId, storeError]() {
                if (self && generation == self->m_loadGeneration) {
                    self->onAnalysisFinished(nativePath, result, error, storedId, storeError);
                }
            },
            Qt::QueuedConnection);
    });
}

void MainWindow::onAnalysisFinished(const QString& path,
                                    const std::shared_ptr<const analysis::AnalysisResult>& result,
                                    const QString& error, qint64 storedId, const QString& storeError) {
    const QString name = QFileInfo(path).fileName();
    if (!result) {
        m_dashboard->showError(path, error);
        m_statusDriverLabel->setText(tr("Failed to analyze %1").arg(name));
        statusBar()->showMessage(tr("Could not analyze %1: %2").arg(name, error), 8000);
        return;
    }
    const auto& image = *result->image;
    m_dashboard->showImage(image);
    m_functions->setResult(result);
    m_driverModel->setResult(result);
    m_ioctls->setResult(result);
    m_devices->setResult(result);
    m_kernelApis->setResult(result);
    m_evidence->setResult(result);
    m_findings->setResult(result); // selects the first finding, which fills Evidence
    m_export->setResult(result);
    m_callGraph->setResult(result);
    m_dataFlow->setResult(result);
    m_controlFlow->setResult(result);
    m_history->refresh();
    m_compare->refresh();
    m_previousFindings->showFor(storedId, QString::fromStdString(image.hashes.sha256),
                                QString::fromStdString(image.fileName));
    const auto& risk = result->findings->risk;
    m_dashboard->setRiskSummary(
        tr("<span style='font-size:12pt; color:%1'><b>%2/100 &middot; %3 risk</b></span>"
           "&nbsp;&nbsp;<span style='color:#9a9a9a'>%4 findings - see the Findings tab</span>")
            .arg(ui::riskLevelColor(QString::fromStdString(risk.level)).name())
            .arg(risk.score)
            .arg(QString::fromStdString(risk.level))
            .arg(result->findings->findings.size()));
    m_statusDriverLabel->setText(tr("Loaded: %1").arg(name));
    statusBar()->showMessage(tr("%1: risk %6/100 (%7), %2 driver, %3 functions, %4 IOCTLs, %5 device objects")
                                 .arg(name)
                                 .arg(QString::fromLatin1(core::driver::modelName(result->driver->model.kind)))
                                 .arg(result->functions->functions.size())
                                 .arg(result->ioctls->ioctls.size())
                                 .arg(result->devices->devices.size())
                                 .arg(result->findings->risk.score)
                                 .arg(QString::fromStdString(result->findings->risk.level)),
                             8000);
    if (!storeError.isEmpty()) {
        statusBar()->showMessage(tr("%1 analyzed, but it couldn't be saved to the database: %2")
                                     .arg(name, storeError),
                                 10000);
    }
}

} // namespace dasa::app
