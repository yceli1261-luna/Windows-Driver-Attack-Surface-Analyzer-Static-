#pragma once

#include <QWidget>

#include <memory>

class QComboBox;
class QLabel;
class QTextBrowser;

namespace dasa::core::database {
class AnalysisDatabase;
}

namespace dasa::ui {

/// Compare Drivers dock: pick any two stored analyses (two versions of a
/// driver, or two different drivers) and see the findings, IOCTLs and
/// risky APIs that differ.
class CompareWidget : public QWidget {
    Q_OBJECT

public:
    explicit CompareWidget(QWidget* parent = nullptr);

    void setDatabase(std::shared_ptr<core::database::AnalysisDatabase> db);
    /// Re-reads the list of analyses, keeping the current picks if they still exist.
    void refresh();
    /// Selects the two analyses and shows their comparison.
    void compare(qint64 olderId, qint64 newerId);

private:
    void showComparison();

    std::shared_ptr<core::database::AnalysisDatabase> m_db;
    QComboBox* m_a = nullptr;
    QComboBox* m_b = nullptr;
    QTextBrowser* m_view = nullptr;
};

/// Previous Findings dock: how the current driver's findings differ from
/// an earlier analysis of the same file (same SHA-256) or file name.
class PreviousFindingsWidget : public QWidget {
    Q_OBJECT

public:
    explicit PreviousFindingsWidget(QWidget* parent = nullptr);

    void setDatabase(std::shared_ptr<core::database::AnalysisDatabase> db);
    void clear();
    /// `currentId` is the stored id of the analysis just shown, or 0 if it
    /// couldn't be saved.
    void showFor(qint64 currentId, const QString& sha256, const QString& fileName);

private:
    void showComparison();

    std::shared_ptr<core::database::AnalysisDatabase> m_db;
    qint64 m_currentId = 0;
    QLabel* m_header = nullptr;
    QComboBox* m_earlier = nullptr;
    QTextBrowser* m_view = nullptr;
};

} // namespace dasa::ui
