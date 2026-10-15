#pragma once

#include <QMainWindow>
#include <QSettings>

#include <memory>

class QDockWidget;
class QLabel;
class QDragEnterEvent;
class QDragMoveEvent;
class QDropEvent;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {
class DashboardWidget;
class DriverModelWidget;
class FunctionsWidget;
}

namespace dasa::app {

/// Top-level application window: the dock layout (one dock per
/// workspace/research/dynamic/database/reports view from the product
/// brief), persisted layout, dark theme, and driver loading via
/// drag-and-drop, File > Open or --driver. Loading a driver runs the static
/// analysis pipeline on a worker thread; the result fills the Dashboard
/// (Phase 2), Functions (Phase 3) and IRP Handlers (Phase 4) docks. Other
/// docks stay empty until the phase that implements their view.
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    /// Called from main() for `--driver <path>`, File > Open and the
    /// drag-and-drop handler. Validates the path, then analyzes it in the
    /// background; the Dashboard shows a loading state until it finishes.
    void loadDriver(const QString& path);

protected:
    bool event(QEvent* event) override;
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dragMoveEvent(QDragMoveEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void buildMenus();
    void buildDockLayout();
    void buildStatusBar();
    QDockWidget* makeDock(const QString& title, const QString& objectName);
    void onAnalysisFinished(const QString& path,
                            const std::shared_ptr<const analysis::AnalysisResult>& result,
                            const QString& error);
    void restoreLayout();
    void saveLayout();

    QSettings m_settings;
    QLabel* m_statusDriverLabel = nullptr;
    ui::DashboardWidget* m_dashboard = nullptr;
    ui::FunctionsWidget* m_functions = nullptr;
    ui::DriverModelWidget* m_driverModel = nullptr;
    quint64 m_loadGeneration = 0;
};

} // namespace dasa::app
