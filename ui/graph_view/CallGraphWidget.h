#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

#include "core/callgraph/CallGraph.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;
class QToolButton;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

class GraphView;

/// Call Graph dock: the neighbourhood of one function - its callers and
/// callees to a chosen depth, and the imports they call. Entry points
/// (DriverEntry, IRP handlers, KMDF callbacks) have a green border, risky
/// imports are coloured by risk, call cycles are marked. Double-click a
/// function to centre the graph on it.
class CallGraphWidget : public QWidget {
    Q_OBJECT

public:
    explicit CallGraphWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);
    /// Centres the graph on the function at `rva`.
    void focusFunction(std::uint64_t rva);

signals:
    /// A function was chosen in this view (double-click or Go to).
    void functionActivated(std::uint64_t rva);
    /// "Control Flow" was clicked for the focused function.
    void controlFlowRequested(std::uint64_t rva);

private:
    void rebuild();
    void goBack();

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    core::callgraph::CallGraph m_graph;
    std::size_t m_focus = 0;
    std::vector<std::size_t> m_history;

    QLabel* m_title = nullptr;
    QLabel* m_info = nullptr;
    QSpinBox* m_callees = nullptr;
    QSpinBox* m_callers = nullptr;
    QComboBox* m_imports = nullptr;
    QLineEdit* m_goTo = nullptr;
    QToolButton* m_back = nullptr;
    QToolButton* m_cfg = nullptr;
    GraphView* m_view = nullptr;
};

} // namespace dasa::ui
