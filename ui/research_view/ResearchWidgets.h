#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>
#include <string>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;
class QTimer;

namespace dasa::analysis {
struct AnalysisResult;
}
namespace dasa::core::database {
class AnalysisDatabase;
}

namespace dasa::ui {

using DatabasePtr = std::shared_ptr<core::database::AnalysisDatabase>;
using ResultPtr = std::shared_ptr<const analysis::AnalysisResult>;

/// Search dock: functions, imports, exports, strings, instructions, IOCTLs,
/// devices and findings of the loaded driver, by substring or regex.
class SearchWidget : public QWidget {
    Q_OBJECT

public:
    explicit SearchWidget(QWidget* parent = nullptr);
    void clear();
    void setResult(ResultPtr result);
    void focusQuery();

signals:
    void functionActivated(std::uint64_t rva);
    void bookmarkRequested(std::uint64_t rva, const QString& label);

private:
    void runSearch();

    ResultPtr m_result;
    QLineEdit* m_query = nullptr;
    QCheckBox* m_regex = nullptr;
    QCheckBox* m_case = nullptr;
    QComboBox* m_kind = nullptr;
    QLabel* m_status = nullptr;
    QTableWidget* m_table = nullptr;
    QPushButton* m_bookmark = nullptr;
};

/// Bookmarks dock: saved locations in the loaded driver with a label and a
/// note (edit in place). Stored per file SHA-256.
class BookmarksWidget : public QWidget {
    Q_OBJECT

public:
    explicit BookmarksWidget(QWidget* parent = nullptr);
    void setDatabase(DatabasePtr db);
    void clear();
    void setResult(ResultPtr result);
    void setCurrentFunction(std::uint64_t rva);
    void addBookmark(std::uint64_t rva, const QString& label);

signals:
    void functionActivated(std::uint64_t rva);
    void changed();

private:
    void reload();

    DatabasePtr m_db;
    ResultPtr m_result;
    std::uint64_t m_currentFunction = 0;
    bool m_loading = false;
    QLabel* m_header = nullptr;
    QTableWidget* m_table = nullptr;
    QPushButton* m_add = nullptr;
    QPushButton* m_remove = nullptr;
};

/// Notes dock: free-text notes for the loaded driver, saved automatically.
class NotesWidget : public QWidget {
    Q_OBJECT

public:
    explicit NotesWidget(QWidget* parent = nullptr);
    ~NotesWidget() override;
    void setDatabase(DatabasePtr db);
    void clear();
    void setDriver(const std::string& sha256, const QString& fileName);
    /// Writes pending edits now (called before switching drivers / exit).
    void flush();

signals:
    void changed();

private:
    DatabasePtr m_db;
    std::string m_sha;
    bool m_dirty = false;
    bool m_loading = false;
    QLabel* m_header = nullptr;
    QLabel* m_status = nullptr;
    QPlainTextEdit* m_edit = nullptr;
    QTimer* m_saveTimer = nullptr;
};

/// Tags dock: tags on the loaded driver, every tag in use, and the drivers
/// that carry a selected tag.
class TagsWidget : public QWidget {
    Q_OBJECT

public:
    explicit TagsWidget(QWidget* parent = nullptr);
    void setDatabase(DatabasePtr db);
    void clear();
    void setDriver(const std::string& sha256, const QString& fileName);
    void refresh();

signals:
    void changed();
    void openDriverRequested(const QString& path);

private:
    void showTagged(const QString& tag);

    DatabasePtr m_db;
    std::string m_sha;
    QLabel* m_header = nullptr;
    QListWidget* m_driverTags = nullptr;
    QLineEdit* m_newTag = nullptr;
    QPushButton* m_add = nullptr;
    QPushButton* m_remove = nullptr;
    QListWidget* m_allTags = nullptr;
    QTableWidget* m_tagged = nullptr;
};

/// Investigation Workspace dock: every driver with bookmarks, notes or tags,
/// with its latest analysis - the list of what you are working on.
class WorkspaceWidget : public QWidget {
    Q_OBJECT

public:
    explicit WorkspaceWidget(QWidget* parent = nullptr);
    void setDatabase(DatabasePtr db);
    void refresh();

signals:
    void openDriverRequested(const QString& path);

private:
    DatabasePtr m_db;
    QLabel* m_header = nullptr;
    QTableWidget* m_table = nullptr;
};

} // namespace dasa::ui
