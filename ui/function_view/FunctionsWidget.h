#pragma once

#include <QWidget>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QSortFilterProxyModel;
class QTableView;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

class FunctionTableModel;

/// Content of the Functions dock: the discovered functions (sortable,
/// filterable) and the disassembly of the selected one, with calls
/// annotated by callee or import name.
class FunctionsWidget : public QWidget {
    Q_OBJECT

public:
    explicit FunctionsWidget(QWidget* parent = nullptr);
    ~FunctionsWidget() override;

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);
    /// Selects and shows the function starting at `rva`, if there is one.
    void showFunction(std::uint64_t rva);

signals:
    /// The selected function changed (user selection or showFunction()).
    void functionSelected(std::uint64_t rva);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void onCurrentRowChanged();
    void renderListing(std::size_t functionIndex);

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    std::unordered_map<std::uint64_t, std::string> m_imports;
    // Per listing line: the function a double-click on it opens (0 = none).
    std::vector<std::uint64_t> m_lineTargets;

    FunctionTableModel* m_model = nullptr;
    QSortFilterProxyModel* m_proxy = nullptr;
    QLineEdit* m_filter = nullptr;
    QLabel* m_summary = nullptr;
    QTableView* m_table = nullptr;
    QLabel* m_listingTitle = nullptr;
    QPlainTextEdit* m_listing = nullptr;
};

} // namespace dasa::ui
