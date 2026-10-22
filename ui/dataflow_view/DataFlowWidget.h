#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QTableWidget;
class QTextBrowser;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Data Flow dock: request data that reaches sensitive operations (one row
/// per flow, most severe first) with the selected flow's sources, IOCTLs
/// and call path; and the sensitive calls whose arguments are constants or
/// weren't traced to the request.
class DataFlowWidget : public QWidget {
    Q_OBJECT

public:
    explicit DataFlowWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    void functionActivated(std::uint64_t rva);

private:
    void showDetail(int row);

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QLabel* m_summary = nullptr;
    QTableWidget* m_table = nullptr;
    QTextBrowser* m_detail = nullptr;
};

} // namespace dasa::ui
