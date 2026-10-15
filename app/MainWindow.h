#pragma once

#include <QMainWindow>
#include <QSettings>

class QDockWidget;
class QFileInfo;
class QLabel;
class QDragEnterEvent;
class QDragMoveEvent;
class QDropEvent;

namespace dasa::app {

/// Top-level application window. Phase 1 scope: the dock layout skeleton
/// (empty dock widgets, one per workspace/research/dynamic/database/reports
/// nav group from the product brief), persisted layout, dark theme, and
/// .sys drag-and-drop that logs the dropped path. No analysis is wired in
/// yet - that starts Phase 2, through a background job rather than on this
/// thread.
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    /// Called from main() for `--driver <path>` and from the drag-and-drop
    /// handler. Phase 1: validates the path exists and has a .sys
    /// extension, updates the status bar, and logs it - no parsing yet.
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
    void showDriverSummary(const QFileInfo& info);
    void restoreLayout();
    void saveLayout();

    QSettings m_settings;
    QLabel* m_statusDriverLabel = nullptr;
};

} // namespace dasa::app
