#pragma once

#include <QMainWindow>
#include <QSettings>

#include <memory>

class QDockWidget;
class QLabel;
class QDragEnterEvent;
class QDragMoveEvent;
class QDropEvent;

namespace dasa::core::pe {
struct PEImage;
}

namespace dasa::ui {
class DashboardWidget;
}

namespace dasa::app {

/// Top-level application window: the dock layout (one dock per
/// workspace/research/dynamic/database/reports view from the product
/// brief), persisted layout, dark theme, and driver loading via
/// drag-and-drop, File > Open or --driver. Phase 2: loading a driver parses
/// it on a worker thread and shows the PE image on the Dashboard. Other
/// docks stay empty until the phase that implements their view.
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    /// Called from main() for `--driver <path>`, File > Open and the
    /// drag-and-drop handler. Validates the path, then parses it in the
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
    void onDriverParsed(const QString& path, const std::shared_ptr<core::pe::PEImage>& image,
                        const QString& error);
    void restoreLayout();
    void saveLayout();

    QSettings m_settings;
    QLabel* m_statusDriverLabel = nullptr;
    ui::DashboardWidget* m_dashboard = nullptr;
    quint64 m_loadGeneration = 0;
};

} // namespace dasa::app
