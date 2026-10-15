#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QTreeWidget;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Content of the Evidence dock: the evidence chains of the finding selected
/// in Findings, step by step (user-mode name -> handler -> IOCTL -> call
/// path -> dangerous call). Double-click a step to open its function.
class EvidenceWidget : public QWidget {
    Q_OBJECT

public:
    explicit EvidenceWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);
    void showFinding(int index);

signals:
    void functionActivated(std::uint64_t rva);

private:
    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QLabel* m_title = nullptr;
    QTreeWidget* m_tree = nullptr;
};

} // namespace dasa::ui
