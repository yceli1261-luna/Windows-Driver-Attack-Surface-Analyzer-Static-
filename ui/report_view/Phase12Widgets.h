#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTextBrowser;

namespace dasa::analysis {
struct AnalysisResult;
}
namespace dasa::core::database {
class AnalysisDatabase;
}

namespace dasa::ui {

/// Security Assessment dock: the plain-language assessment of the loaded
/// driver (analysis/report/Assessment) with links into the code.
class AssessmentWidget : public QWidget {
    Q_OBJECT

public:
    explicit AssessmentWidget(QWidget* parent = nullptr);
    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    void functionActivated(std::uint64_t rva);
    void exportRequested();

private:
    QTextBrowser* m_view = nullptr;
    QPushButton* m_export = nullptr;
};

/// Current Analysis dock: what each analysis stage produced, how long it
/// took, and the limits that applied to this driver.
class CurrentAnalysisWidget : public QWidget {
    Q_OBJECT

public:
    explicit CurrentAnalysisWidget(QWidget* parent = nullptr);
    void clear();
    void showLoading(const QString& path);
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result, qint64 storedId);

private:
    QTextBrowser* m_view = nullptr;
};

/// Diff dock: compares the loaded driver with another version, function by
/// function (patch diffing), plus imports, sections, IOCTLs, devices and
/// findings.
class DiffWidget : public QWidget {
    Q_OBJECT

public:
    explicit DiffWidget(QWidget* parent = nullptr);
    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    void functionActivated(std::uint64_t rva);

private:
    void chooseFile();
    void compareWith(const QString& path);
    void showDiff(std::shared_ptr<const analysis::AnalysisResult> other);

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    std::shared_ptr<const analysis::AnalysisResult> m_other;
    quint64 m_generation = 0;
    QPushButton* m_choose = nullptr;
    QCheckBox* m_otherIsOlder = nullptr;
    QCheckBox* m_hideIdentical = nullptr;
    QLabel* m_summary = nullptr;
    QTableWidget* m_table = nullptr;
    QTextBrowser* m_details = nullptr;
};

/// Drivers dock: drivers loaded right now, installed in System32\drivers or
/// in any folder, with company and version, filterable; third-party only
/// by default. Double-click to analyse.
class DriversWidget : public QWidget {
    Q_OBJECT

public:
    explicit DriversWidget(QWidget* parent = nullptr);
    void setDatabase(std::shared_ptr<core::database::AnalysisDatabase> db);

signals:
    void openDriverRequested(const QString& path);

private:
    void scan();
    void applyFilter();

    std::shared_ptr<core::database::AnalysisDatabase> m_db;
    quint64 m_generation = 0;
    QComboBox* m_source = nullptr;
    QLineEdit* m_filter = nullptr;
    QCheckBox* m_thirdParty = nullptr;
    QPushButton* m_rescan = nullptr;
    QLabel* m_status = nullptr;
    QTableWidget* m_table = nullptr;
    QString m_folder;
};

} // namespace dasa::ui
