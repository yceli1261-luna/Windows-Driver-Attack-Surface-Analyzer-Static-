#pragma once

#include <QWidget>

#include <memory>

class QLabel;
class QPushButton;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Export dock: saves the current analysis as a self-contained HTML report
/// or as JSON. File > Export uses the same two actions.
class ExportWidget : public QWidget {
    Q_OBJECT

public:
    explicit ExportWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);
    bool hasResult() const { return static_cast<bool>(m_result); }

    void exportHtml();
    void exportJson();

signals:
    void exported(const QString& path);

private:
    void save(const QString& title, const QString& suffix, const QString& filter, bool html);

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QLabel* m_summary = nullptr;
    QLabel* m_status = nullptr;
    QPushButton* m_html = nullptr;
    QPushButton* m_json = nullptr;
};

} // namespace dasa::ui
