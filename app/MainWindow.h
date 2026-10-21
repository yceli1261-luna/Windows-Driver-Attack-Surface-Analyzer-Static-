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

namespace dasa::core::database {
class AnalysisDatabase;
}

namespace dasa::ui {
class CompareWidget;
class DashboardWidget;
class ExportWidget;
class HistoryWidget;
class PreviousFindingsWidget;
class EvidenceWidget;
class FindingsWidget;
class DevicesWidget;
class DriverModelWidget;
class FunctionsWidget;
class IoctlWidget;
class KernelApiWidget;
}

namespace dasa::app {

/// Top-level application window: the dock layout (one dock per
/// workspace/research/dynamic/database/reports view from the product
/// brief), persisted layout, dark theme, and driver loading via
/// drag-and-drop, File > Open or --driver. Loading a driver runs the static
/// analysis pipeline on a worker thread; the result fills the Dashboard
/// (Phase 2), Functions (Phase 3), IRP Handlers (Phase 4), IOCTLs and
/// Devices (Phase 5), Findings and Evidence (Phase 7) docks and the
/// Dashboard's Kernel APIs tab (Phase 6). Each analysis is also saved to
/// the analysis database (Analysis History, Previous Findings, Compare
/// Drivers) and can be exported (Export) (Phase 8). Other docks stay empty
/// until the phase that implements their view.
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
                            const QString& error, qint64 storedId, const QString& storeError);
    void openDatabase();
    void restoreLayout();
    void saveLayout();

    QSettings m_settings;
    QLabel* m_statusDriverLabel = nullptr;
    ui::DashboardWidget* m_dashboard = nullptr;
    ui::FunctionsWidget* m_functions = nullptr;
    ui::DriverModelWidget* m_driverModel = nullptr;
    ui::IoctlWidget* m_ioctls = nullptr;
    ui::DevicesWidget* m_devices = nullptr;
    ui::KernelApiWidget* m_kernelApis = nullptr;
    ui::FindingsWidget* m_findings = nullptr;
    ui::EvidenceWidget* m_evidence = nullptr;
    ui::HistoryWidget* m_history = nullptr;
    ui::PreviousFindingsWidget* m_previousFindings = nullptr;
    ui::CompareWidget* m_compare = nullptr;
    ui::ExportWidget* m_export = nullptr;
    // GUI-thread connection for the database views; the worker opens its
    // own connection to save each analysis.
    std::shared_ptr<core::database::AnalysisDatabase> m_db;
    QString m_dbPath;
    quint64 m_loadGeneration = 0;
};

} // namespace dasa::app
