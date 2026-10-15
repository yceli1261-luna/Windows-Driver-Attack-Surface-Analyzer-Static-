#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QTableWidget;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Content of the IOCTLs dock: every recovered IOCTL code, decoded, with
/// the handler it belongs to, where it is compared and how it was found.
class IoctlWidget : public QWidget {
    Q_OBJECT

public:
    explicit IoctlWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    void functionActivated(std::uint64_t rva);

private:
    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QLabel* m_summary = nullptr;
    QTableWidget* m_table = nullptr;
    QLabel* m_notes = nullptr;
};

} // namespace dasa::ui
