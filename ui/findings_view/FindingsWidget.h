#pragma once

#include <QWidget>

#include <memory>

class QLabel;
class QTableWidget;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Content of the Findings dock: the risk score, the findings (most severe
/// first) and the selected finding's description and recommendation.
class FindingsWidget : public QWidget {
    Q_OBJECT

public:
    explicit FindingsWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    /// Index into FindingsReport::findings, or -1 when nothing is selected.
    void findingSelected(int index);

private:
    void showDetail(int index);

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QLabel* m_score = nullptr;
    QTableWidget* m_table = nullptr;
    QLabel* m_detail = nullptr;
};

} // namespace dasa::ui
