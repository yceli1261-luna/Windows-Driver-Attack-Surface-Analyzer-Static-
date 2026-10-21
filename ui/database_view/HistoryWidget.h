#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QPushButton;
class QTableWidget;

namespace dasa::core::database {
class AnalysisDatabase;
}

namespace dasa::ui {

/// Analysis History dock: every stored analysis, newest first, with
/// buttons to reopen the driver, compare two analyses, export a stored
/// report or delete an entry.
class HistoryWidget : public QWidget {
    Q_OBJECT

public:
    explicit HistoryWidget(QWidget* parent = nullptr);

    /// Null when the database couldn't be opened; `error` says why.
    void setDatabase(std::shared_ptr<core::database::AnalysisDatabase> db, const QString& location,
                     const QString& error = {});
    void refresh();

signals:
    void openDriverRequested(const QString& path);
    void compareRequested(qint64 olderId, qint64 newerId);
    void historyChanged();

private:
    qint64 idAt(int row) const;
    void updateButtons();
    void exportSelected();
    void deleteSelected();

    std::shared_ptr<core::database::AnalysisDatabase> m_db;
    QLabel* m_header = nullptr;
    QTableWidget* m_table = nullptr;
    QPushButton* m_open = nullptr;
    QPushButton* m_compare = nullptr;
    QPushButton* m_export = nullptr;
    QPushButton* m_delete = nullptr;
    QString m_location;
};

} // namespace dasa::ui
