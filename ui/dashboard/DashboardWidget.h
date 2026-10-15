#pragma once

#include <QWidget>

class QLabel;
class QStackedWidget;
class QTabWidget;
class QTableWidget;
class QTreeWidget;

namespace dasa::core::pe {
struct PEImage;
}

namespace dasa::ui {

/// Content of the Dashboard dock. Phase 2: shows the parsed PE image -
/// identity, hashes, signature, headers, sections, imports and exports.
/// Purely presentational: it is handed a finished PEImage and never parses
/// anything itself.
class DashboardWidget : public QWidget {
    Q_OBJECT

public:
    explicit DashboardWidget(QWidget* parent = nullptr);

    void showEmpty();
    void showLoading(const QString& path);
    void showError(const QString& path, const QString& message);
    void showImage(const dasa::core::pe::PEImage& image);
    /// Adds a view built from later analysis stages (e.g. Kernel APIs) to
    /// the tab row next to the PE tables.
    void insertTab(int index, QWidget* widget, const QString& title);

private:
    QWidget* buildMessagePage();
    QWidget* buildImagePage();
    void fillSummary(const dasa::core::pe::PEImage& image);
    void fillHeaders(const dasa::core::pe::PEImage& image);
    void fillSections(const dasa::core::pe::PEImage& image);
    void fillImports(const dasa::core::pe::PEImage& image);
    void fillExports(const dasa::core::pe::PEImage& image);
    void fillSignature(const dasa::core::pe::PEImage& image);

    QStackedWidget* m_stack = nullptr;
    QLabel* m_message = nullptr;

    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QLabel* m_facts = nullptr;
    QLabel* m_hashes = nullptr;
    QTabWidget* m_tabs = nullptr;
    QTableWidget* m_headers = nullptr;
    QTableWidget* m_sections = nullptr;
    QTreeWidget* m_imports = nullptr;
    QTableWidget* m_exports = nullptr;
    QLabel* m_signature = nullptr;
};

} // namespace dasa::ui
