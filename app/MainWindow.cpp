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
#include <QThreadPool>
#include <QUrl>
#include <filesystem>
#include <spdlog/spdlog.h>

#include "core/pe/PEParser.h"
#include "ui/dashboard/DashboardWidget.h"

namespace dasa::app {

namespace {

// Dock titles mirror the brief's four nav groups (WORKSPACE / RESEARCH /
// DYNAMIC / DATABASE) plus REPORTS. Each becomes a real, empty QDockWidget
// now; its content widget is built in the phase that implements that view
// (ui/dashboard, ui/driver_view, ... per the architecture proposal) rather
// than as a placeholder label that would need to be torn out later.
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
constexpr int kLayoutVersion = 2;
constexpr int kRightColumnWidth = 380;
constexpr int kBottomStripHeight = 260;

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
    restoreLayout();

    spdlog::info("MainWindow constructed");
}

MainWindow::~MainWindow() = default;

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
    // Empty content widget placeholder - swapped for the real view (e.g.
    // ui/dashboard/DashboardWidget) in the phase that implements it.
    auto* content = new QWidget(dock);
    dock->setWidget(content);
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
            m_dashboard = new ui::DashboardWidget(dock);
            dock->setWidget(m_dashboard);
        }
        addDockWidget(Qt::LeftDockWidgetArea, dock);
        if (firstLeft) {
            tabifyDockWidget(firstLeft, dock);
        } else {
            firstLeft = dock;
        }
    }

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

    for (const auto& spec : kDatabaseDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        addDockWidget(Qt::BottomDockWidgetArea, dock);
        tabifyDockWidget(firstBottom, dock);
    }

    for (const auto& spec : kReportDocks) {
        auto* dock = makeDock(tr(spec.title), QString::fromLatin1(spec.objectName));
        addDockWidget(Qt::RightDockWidgetArea, dock);
        tabifyDockWidget(firstRight, dock);
    }

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
    m_statusDriverLabel->setText(tr("Parsing %1...").arg(info.fileName()));
    setWindowTitle(tr("%1 - Driver Attack Surface Analyzer").arg(info.fileName()));
    m_dashboard->showLoading(nativePath);
    if (auto* dock = findChild<QDockWidget*>(QStringLiteral("dock_dashboard"))) {
        dock->show();
        dock->raise();
    }

    // Parse off the GUI thread and hand the result back with a queued call.
    // The generation counter drops results from a load that was superseded
    // by a newer one while it was still running.
    const quint64 generation = ++m_loadGeneration;
    const std::filesystem::path fsPath = nativePath.toStdWString();
    QPointer<MainWindow> self(this);
    QThreadPool::globalInstance()->start([self, generation, fsPath, nativePath]() {
        std::shared_ptr<core::pe::PEImage> image;
        QString error;
        try {
            image = std::make_shared<core::pe::PEImage>(core::pe::parsePE(fsPath));
        } catch (const std::exception& ex) {
            error = QString::fromStdString(ex.what());
            spdlog::warn("PE parse failed for {}: {}", nativePath.toStdString(), ex.what());
        }
        QMetaObject::invokeMethod(
            qApp,
            [self, generation, nativePath, image, error]() {
                if (self && generation == self->m_loadGeneration) {
                    self->onDriverParsed(nativePath, image, error);
                }
            },
            Qt::QueuedConnection);
    });
}

void MainWindow::onDriverParsed(const QString& path,
                                const std::shared_ptr<core::pe::PEImage>& image,
                                const QString& error) {
    const QString name = QFileInfo(path).fileName();
    if (!image) {
        m_dashboard->showError(path, error);
        m_statusDriverLabel->setText(tr("Failed to parse %1").arg(name));
        statusBar()->showMessage(tr("Could not parse %1: %2").arg(name, error), 8000);
        return;
    }
    m_dashboard->showImage(*image);
    m_statusDriverLabel->setText(tr("Loaded: %1").arg(name));
    statusBar()->showMessage(tr("%1 parsed: %2 sections, %3 imports, %4 exports")
                                 .arg(name)
                                 .arg(image->sections.size())
                                 .arg(image->importedFunctionCount())
                                 .arg(image->exports.size()),
                             8000);
}

} // namespace dasa::app
