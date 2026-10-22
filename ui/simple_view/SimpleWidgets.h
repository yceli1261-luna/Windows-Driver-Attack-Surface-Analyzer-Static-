#pragma once

#include <QSet>
#include <QWidget>

#include <memory>

class QLabel;
class QPushButton;
class QTextBrowser;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Simple mode's first screen. Without a driver: a short welcome with the
/// three steps. With one: a traffic-light verdict and plain answers to
/// "what can it do", "who can use it" and "what should I do", plus the most
/// serious problems.
class OverviewWidget : public QWidget {
    Q_OBJECT

public:
    explicit OverviewWidget(QWidget* parent = nullptr);
    void showWelcome();
    void showLoading(const QString& fileName);
    void showError(const QString& fileName, const QString& error);
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    void driversRequested();
    void openFileRequested();
    void exportRequested();
    void problemsRequested();

private:
    QTextBrowser* m_view = nullptr;
    QPushButton* m_drivers = nullptr;
    QPushButton* m_open = nullptr;
    QPushButton* m_export = nullptr;
};

/// Simple mode's problem list: every finding in plain words, with the
/// technical details (the expert finding and its evidence) one click away.
class ProblemsWidget : public QWidget {
    Q_OBJECT

public:
    explicit ProblemsWidget(QWidget* parent = nullptr);
    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

private:
    void render();

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QSet<int> m_expanded;
    QTextBrowser* m_view = nullptr;
};

/// Help > Glossary: plain explanations of the technical terms in the app.
void showGlossary(QWidget* parent);

} // namespace dasa::ui
