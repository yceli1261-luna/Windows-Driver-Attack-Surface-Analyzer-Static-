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

/// Kernel APIs the driver uses, grouped by risk, with the entry points that
/// reach each call site, plus privileged instructions. Hosted as a tab on
/// the Dashboard next to the raw import list.
class KernelApiWidget : public QWidget {
    Q_OBJECT

public:
    explicit KernelApiWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    void functionActivated(std::uint64_t rva);

private:
    QLabel* m_summary = nullptr;
    QTreeWidget* m_tree = nullptr;
    QLabel* m_notes = nullptr;
};

} // namespace dasa::ui
