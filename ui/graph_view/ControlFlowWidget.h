#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QLineEdit;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

class GraphView;

/// Control Flow dock: one function's basic blocks as a graph. Taken
/// branches are green, fall-throughs red, jumps blue; loops (back edges)
/// are dashed. Double-clicking a block that calls another function of the
/// driver opens that function.
class ControlFlowWidget : public QWidget {
    Q_OBJECT

public:
    explicit ControlFlowWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);
    /// Shows the function starting at (or containing) `rva`.
    void showFunction(std::uint64_t rva);
    std::uint64_t currentFunction() const { return m_current; }

signals:
    /// The user asked to open a function from this view.
    void functionActivated(std::uint64_t rva);

private:
    void goTo();

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    std::uint64_t m_current = 0;
    QLabel* m_title = nullptr;
    QLabel* m_info = nullptr;
    QLineEdit* m_goTo = nullptr;
    GraphView* m_view = nullptr;
};

} // namespace dasa::ui
