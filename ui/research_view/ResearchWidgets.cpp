#include "ui/research_view/ResearchWidgets.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTimer>
#include <QTimeZone>
#include <QVBoxLayout>

#include <algorithm>

#include "analysis/search/Search.h"
#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/database/AnalysisDatabase.h"
#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace {

constexpr int kRvaRole = Qt::UserRole + 1;
constexpr int kFnRole = Qt::UserRole + 2;
constexpr int kIdRole = Qt::UserRole + 3;
constexpr int kPathRole = Qt::UserRole + 4;

QString hexRva(std::uint64_t v) {
    return QStringLiteral("0x") + QStringLiteral("%1").arg(v, 8, 16, QLatin1Char('0')).toUpper();
}

QVBoxLayout* dockLayout(QWidget* w) {
    auto* layout = new QVBoxLayout(w);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(8);
    return layout;
}

QTableWidget* makeTable(QWidget* parent, const QStringList& headers, int stretchColumn) {
    auto* t = new QTableWidget(0, static_cast<int>(headers.size()), parent);
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->setVisible(false);
    t->verticalHeader()->setDefaultSectionSize(26);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setAlternatingRowColors(true);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    t->horizontalHeader()->setSectionResizeMode(stretchColumn, QHeaderView::Stretch);
    t->setMinimumHeight(60);
    return t;
}

QLabel* makeHeader(QWidget* parent) {
    auto* l = new QLabel(parent);
    l->setTextFormat(Qt::RichText);
    l->setWordWrap(true);
    return l;
}

QString localTime(const std::string& utc) {
    QDateTime t = QDateTime::fromString(QString::fromStdString(utc), QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    if (!t.isValid()) {
        return QString::fromStdString(utc);
    }
    t.setTimeZone(QTimeZone::UTC);
    return t.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

QString functionNameAt(const analysis::AnalysisResult& r, std::uint64_t rva) {
    const auto& fns = r.functions->functions;
    for (const auto& f : fns) {
        if (rva >= f.lowRva && rva < f.highRva) {
            for (const auto& i : f.instructions) {
                if (rva >= i.rva && rva < i.endRva()) {
                    return QString::fromStdString(f.name);
                }
            }
        }
    }
    if (const auto* f = r.functions->find(rva)) {
        return QString::fromStdString(f->name);
    }
    return QString();
}

std::uint64_t functionStartAt(const analysis::AnalysisResult& r, std::uint64_t rva) {
    if (r.functions->find(rva)) {
        return rva;
    }
    for (const auto& f : r.functions->functions) {
        if (rva >= f.lowRva && rva < f.highRva) {
            for (const auto& i : f.instructions) {
                if (rva >= i.rva && rva < i.endRva()) {
                    return f.rva;
                }
            }
        }
    }
    return 0;
}

} // namespace

// ================================================================= Search ==

SearchWidget::SearchWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    m_query = new QLineEdit(this);
    m_query->setPlaceholderText(tr("Search the loaded driver (Enter)"));
    m_query->setClearButtonEnabled(true);
    layout->addWidget(m_query);

    auto* opts = new QHBoxLayout;
    opts->setSpacing(8);
    m_kind = new QComboBox(this);
    m_kind->addItem(tr("Everything"), analysis::kAllSearchKinds);
    using K = analysis::SearchKind;
    for (K k : {K::Function, K::Import, K::Export, K::String, K::Instruction, K::Ioctl, K::Device, K::Finding}) {
        m_kind->addItem(tr(analysis::searchKindName(k)), static_cast<std::uint32_t>(k));
    }
    opts->addWidget(m_kind, 1);
    m_regex = new QCheckBox(tr("Regex"), this);
    m_case = new QCheckBox(tr("Aa"), this);
    m_case->setToolTip(tr("Match case"));
    opts->addWidget(m_regex);
    opts->addWidget(m_case);
    layout->addLayout(opts);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_status);

    m_table = makeTable(this, {tr("Kind"), tr("Match"), tr("Where")}, 1);
    layout->addWidget(m_table, 1);
    m_bookmark = new QPushButton(tr("Bookmark selected"), this);
    m_bookmark->setEnabled(false);
    layout->addWidget(m_bookmark);

    connect(m_query, &QLineEdit::returnPressed, this, &SearchWidget::runSearch);
    connect(m_kind, &QComboBox::currentIndexChanged, this, [this] {
        if (!m_query->text().isEmpty()) runSearch();
    });
    connect(m_regex, &QCheckBox::toggled, this, [this] {
        if (!m_query->text().isEmpty()) runSearch();
    });
    connect(m_case, &QCheckBox::toggled, this, [this] {
        if (!m_query->text().isEmpty()) runSearch();
    });
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        const QVariant fn = m_table->item(row, 0)->data(kFnRole);
        if (fn.isValid()) {
            emit functionActivated(fn.toULongLong());
        }
    });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this] {
        const int row = m_table->currentRow();
        m_bookmark->setEnabled(row >= 0 && m_table->item(row, 0)->data(kRvaRole).isValid());
    });
    connect(m_bookmark, &QPushButton::clicked, this, [this] {
        const int row = m_table->currentRow();
        if (row < 0) {
            return;
        }
        const QVariant rva = m_table->item(row, 0)->data(kRvaRole);
        if (rva.isValid()) {
            emit bookmarkRequested(rva.toULongLong(), m_table->item(row, 1)->text().left(80));
        }
    });
    clear();
}

void SearchWidget::focusQuery() {
    m_query->setFocus();
    m_query->selectAll();
}

void SearchWidget::clear() {
    m_result.reset();
    m_table->setRowCount(0);
    m_status->setText(tr("Load a driver to search it."));
    m_query->setEnabled(false);
}

void SearchWidget::setResult(ResultPtr result) {
    m_result = std::move(result);
    m_query->setEnabled(true);
    m_status->setText(tr("Functions, imports, exports, strings, instructions, IOCTLs, devices and findings. "
                         "Double-click a result to open its function."));
    if (!m_query->text().isEmpty()) {
        runSearch();
    }
}

void SearchWidget::runSearch() {
    if (!m_result) {
        return;
    }
    analysis::SearchOptions opt;
    opt.regex = m_regex->isChecked();
    opt.caseSensitive = m_case->isChecked();
    opt.kinds = m_kind->currentData().toUInt();
    const auto res = analysis::search(*m_result, m_query->text().toStdString(), opt);
    if (!res.error.empty()) {
        m_status->setText(QStringLiteral("<span style='color:#f1706b'>%1</span>")
                              .arg(QString::fromStdString(res.error).toHtmlEscaped()));
        m_table->setRowCount(0);
        return;
    }
    m_status->setText(res.truncated ? tr("First %1 results - refine the search.").arg(res.hits.size())
                                    : tr("%n result(s).", nullptr, static_cast<int>(res.hits.size())));
    m_table->setRowCount(static_cast<int>(res.hits.size()));
    for (int i = 0; i < static_cast<int>(res.hits.size()); ++i) {
        const auto& h = res.hits[static_cast<std::size_t>(i)];
        auto* kind = new QTableWidgetItem(tr(analysis::searchKindName(h.kind)));
        if (h.rva) {
            kind->setData(kRvaRole, static_cast<qulonglong>(*h.rva));
        }
        if (h.function) {
            kind->setData(kFnRole, static_cast<qulonglong>(*h.function));
        }
        m_table->setItem(i, 0, kind);
        auto* match = new QTableWidgetItem(QString::fromStdString(h.text));
        match->setToolTip(match->text());
        m_table->setItem(i, 1, match);
        QString where = QString::fromStdString(h.context);
        if (h.rva) {
            where = hexRva(*h.rva) + QStringLiteral("  ") + where;
        }
        auto* w = new QTableWidgetItem(where);
        w->setToolTip(where);
        m_table->setItem(i, 2, w);
    }
    m_table->resizeColumnToContents(0);
}

// ============================================================== Bookmarks ==

BookmarksWidget::BookmarksWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    m_header = makeHeader(this);
    layout->addWidget(m_header);
    m_table = makeTable(this, {tr("Address"), tr("Label"), tr("Note")}, 2);
    m_table->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed |
                             QAbstractItemView::SelectedClicked);
    layout->addWidget(m_table, 1);
    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(8);
    m_add = new QPushButton(tr("Bookmark function"), this);
    m_add->setToolTip(tr("Bookmark the function selected in Functions / Control Flow"));
    m_remove = new QPushButton(tr("Remove"), this);
    buttons->addWidget(m_add);
    buttons->addWidget(m_remove);
    layout->addLayout(buttons);

    connect(m_add, &QPushButton::clicked, this, [this] {
        if (m_result && m_currentFunction) {
            addBookmark(m_currentFunction, functionNameAt(*m_result, m_currentFunction));
        }
    });
    connect(m_remove, &QPushButton::clicked, this, [this] {
        const int row = m_table->currentRow();
        if (row < 0 || !m_db) {
            return;
        }
        m_db->removeBookmark(m_table->item(row, 0)->data(kIdRole).toLongLong());
        reload();
        emit changed();
    });
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        if (column == 0 && m_result) {
            const auto rva = m_table->item(row, 0)->data(kRvaRole).toULongLong();
            if (const auto fn = functionStartAt(*m_result, rva)) {
                emit functionActivated(fn);
            }
        }
    });
    connect(m_table, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* item) {
        if (m_loading || !m_db || item->column() == 0) {
            return;
        }
        const int row = item->row();
        m_db->updateBookmark(m_table->item(row, 0)->data(kIdRole).toLongLong(),
                             m_table->item(row, 1)->text().toStdString(), m_table->item(row, 2)->text().toStdString());
        emit changed();
    });
    connect(m_table, &QTableWidget::itemSelectionChanged, this,
            [this] { m_remove->setEnabled(m_table->currentRow() >= 0); });
    clear();
}

void BookmarksWidget::setDatabase(DatabasePtr db) {
    m_db = std::move(db);
}

void BookmarksWidget::clear() {
    m_result.reset();
    m_currentFunction = 0;
    m_loading = true;
    m_table->setRowCount(0);
    m_loading = false;
    m_header->setText(tr("Load a driver to keep bookmarks for it."));
    m_add->setEnabled(false);
    m_remove->setEnabled(false);
}

void BookmarksWidget::setResult(ResultPtr result) {
    m_result = std::move(result);
    reload();
}

void BookmarksWidget::setCurrentFunction(std::uint64_t rva) {
    m_currentFunction = rva;
    m_add->setEnabled(m_db && m_result && rva != 0);
    if (m_result && rva) {
        m_add->setText(tr("Bookmark %1").arg(functionNameAt(*m_result, rva)));
    }
}

void BookmarksWidget::addBookmark(std::uint64_t rva, const QString& label) {
    if (!m_db || !m_result) {
        return;
    }
    m_db->addBookmark(m_result->image->hashes.sha256, rva, label.toStdString(), "");
    reload();
    emit changed();
}

void BookmarksWidget::reload() {
    if (!m_result) {
        return;
    }
    if (!m_db) {
        m_header->setText(tr("The analysis database is unavailable, so bookmarks can't be saved."));
        return;
    }
    const auto marks = m_db->bookmarks(m_result->image->hashes.sha256);
    m_header->setText(tr("<b>%1</b> &middot; %n bookmark(s). Double-click a label or note to edit it, the address "
                         "to open it.",
                         nullptr, static_cast<int>(marks.size()))
                          .arg(QString::fromStdString(m_result->image->fileName).toHtmlEscaped()));
    m_loading = true;
    m_table->setRowCount(static_cast<int>(marks.size()));
    for (int i = 0; i < static_cast<int>(marks.size()); ++i) {
        const auto& b = marks[static_cast<std::size_t>(i)];
        auto* addr = new QTableWidgetItem(hexRva(b.rva));
        addr->setData(kIdRole, static_cast<qlonglong>(b.id));
        addr->setData(kRvaRole, static_cast<qulonglong>(b.rva));
        addr->setFlags(addr->flags() & ~Qt::ItemIsEditable);
        const QString fn = functionNameAt(*m_result, b.rva);
        addr->setToolTip(fn.isEmpty() ? tr("not inside a known function") : tr("in %1").arg(fn));
        m_table->setItem(i, 0, addr);
        m_table->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(b.label)));
        m_table->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(b.note)));
    }
    m_loading = false;
    m_table->resizeColumnToContents(0);
    m_remove->setEnabled(m_table->currentRow() >= 0);
    setCurrentFunction(m_currentFunction);
}

// ================================================================== Notes ==

NotesWidget::NotesWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    m_header = makeHeader(this);
    layout->addWidget(m_header);
    m_edit = new QPlainTextEdit(this);
    m_edit->setPlaceholderText(tr("Notes about this driver - hypotheses, what you checked, what's left..."));
    layout->addWidget(m_edit, 1);
    m_status = new QLabel(this);
    m_status->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    layout->addWidget(m_status);

    m_saveTimer = new QTimer(this);
    m_saveTimer->setSingleShot(true);
    m_saveTimer->setInterval(800);
    connect(m_saveTimer, &QTimer::timeout, this, &NotesWidget::flush);
    connect(m_edit, &QPlainTextEdit::textChanged, this, [this] {
        if (m_loading || m_sha.empty()) {
            return;
        }
        m_dirty = true;
        m_status->setText(tr("Editing..."));
        m_saveTimer->start();
    });
    clear();
}

NotesWidget::~NotesWidget() {
    flush();
}

void NotesWidget::setDatabase(DatabasePtr db) {
    m_db = std::move(db);
}

void NotesWidget::flush() {
    m_saveTimer->stop();
    if (!m_dirty || !m_db || m_sha.empty()) {
        return;
    }
    try {
        m_db->setNotes(m_sha, m_edit->toPlainText().toStdString());
        m_dirty = false;
        m_status->setText(tr("Saved %1").arg(QTime::currentTime().toString(QStringLiteral("HH:mm:ss"))));
        emit changed();
    } catch (const std::exception& ex) {
        m_status->setText(tr("Not saved: %1").arg(QString::fromStdString(ex.what())));
    }
}

void NotesWidget::clear() {
    flush();
    m_sha.clear();
    m_loading = true;
    m_edit->clear();
    m_loading = false;
    m_edit->setEnabled(false);
    m_header->setText(tr("Load a driver to write notes about it."));
    m_status->clear();
}

void NotesWidget::setDriver(const std::string& sha256, const QString& fileName) {
    flush();
    m_sha = sha256;
    m_loading = true;
    m_edit->setPlainText(m_db ? QString::fromStdString(m_db->notes(sha256)) : QString());
    m_loading = false;
    m_dirty = false;
    m_edit->setEnabled(m_db != nullptr);
    m_header->setText(m_db ? tr("<b>%1</b> &middot; saved automatically, kept for this exact file (SHA-256).")
                                 .arg(fileName.toHtmlEscaped())
                           : tr("The analysis database is unavailable, so notes can't be saved."));
    m_status->clear();
}

// =================================================================== Tags ==

TagsWidget::TagsWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    m_header = makeHeader(this);
    layout->addWidget(m_header);

    m_driverTags = new QListWidget(this);
    m_driverTags->setMaximumHeight(110);
    layout->addWidget(m_driverTags);
    auto* addRow = new QHBoxLayout;
    addRow->setSpacing(8);
    m_newTag = new QLineEdit(this);
    m_newTag->setPlaceholderText(tr("New tag, e.g. reviewed"));
    m_add = new QPushButton(tr("Add"), this);
    m_remove = new QPushButton(tr("Remove"), this);
    addRow->addWidget(m_newTag, 1);
    addRow->addWidget(m_add);
    addRow->addWidget(m_remove);
    layout->addLayout(addRow);

    auto* all = new QLabel(tr("<b>All tags</b> <span style='color:#9a9a9a'>(click one to list its drivers)</span>"), this);
    all->setTextFormat(Qt::RichText);
    layout->addWidget(all);
    m_allTags = new QListWidget(this);
    m_allTags->setMaximumHeight(130);
    layout->addWidget(m_allTags);
    m_tagged = makeTable(this, {tr("Driver"), tr("Risk")}, 0);
    layout->addWidget(m_tagged, 1);

    auto addTag = [this] {
        if (!m_db || m_sha.empty() || m_newTag->text().trimmed().isEmpty()) {
            return;
        }
        m_db->addTag(m_sha, m_newTag->text().toStdString());
        m_newTag->clear();
        refresh();
        emit changed();
    };
    connect(m_add, &QPushButton::clicked, this, addTag);
    connect(m_newTag, &QLineEdit::returnPressed, this, addTag);
    connect(m_remove, &QPushButton::clicked, this, [this] {
        auto* item = m_driverTags->currentItem();
        if (!item || !m_db || m_sha.empty()) {
            return;
        }
        m_db->removeTag(m_sha, item->text().toStdString());
        refresh();
        emit changed();
    });
    connect(m_allTags, &QListWidget::currentItemChanged, this, [this](QListWidgetItem* item) {
        showTagged(item ? item->data(Qt::UserRole).toString() : QString());
    });
    connect(m_tagged, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        const QString path = m_tagged->item(row, 0)->data(kPathRole).toString();
        if (!path.isEmpty()) {
            emit openDriverRequested(path);
        }
    });
    clear();
}

void TagsWidget::setDatabase(DatabasePtr db) {
    m_db = std::move(db);
    refresh();
}

void TagsWidget::clear() {
    m_sha.clear();
    m_header->setText(tr("Load a driver to tag it."));
    refresh();
}

void TagsWidget::setDriver(const std::string& sha256, const QString& fileName) {
    m_sha = sha256;
    m_header->setText(m_db ? tr("<b>%1</b> &middot; tags are kept for this exact file (SHA-256).")
                                 .arg(fileName.toHtmlEscaped())
                           : tr("The analysis database is unavailable, so tags can't be saved."));
    refresh();
}

void TagsWidget::refresh() {
    m_driverTags->clear();
    const QString selected = m_allTags->currentItem() ? m_allTags->currentItem()->data(Qt::UserRole).toString() : QString();
    m_allTags->clear();
    const bool active = m_db && !m_sha.empty();
    m_newTag->setEnabled(active);
    m_add->setEnabled(active);
    m_remove->setEnabled(active);
    if (!m_db) {
        return;
    }
    if (!m_sha.empty()) {
        for (const auto& t : m_db->tags(m_sha)) {
            m_driverTags->addItem(QString::fromStdString(t));
        }
        if (m_driverTags->count() == 0) {
            auto* none = new QListWidgetItem(tr("(no tags yet)"), m_driverTags);
            none->setFlags(Qt::NoItemFlags);
        }
    }
    for (const auto& t : m_db->allTags()) {
        auto* item = new QListWidgetItem(tr("%1  (%2)").arg(QString::fromStdString(t.tag)).arg(t.drivers), m_allTags);
        item->setData(Qt::UserRole, QString::fromStdString(t.tag));
        if (item->data(Qt::UserRole).toString() == selected) {
            m_allTags->setCurrentItem(item);
        }
    }
    showTagged(m_allTags->currentItem() ? m_allTags->currentItem()->data(Qt::UserRole).toString() : QString());
}

void TagsWidget::showTagged(const QString& tag) {
    m_tagged->setRowCount(0);
    if (!m_db || tag.isEmpty()) {
        return;
    }
    const auto annotated = m_db->annotatedDrivers();
    const auto shas = m_db->driversWithTag(tag.toStdString());
    m_tagged->setRowCount(static_cast<int>(shas.size()));
    for (int i = 0; i < static_cast<int>(shas.size()); ++i) {
        const auto& sha = shas[static_cast<std::size_t>(i)];
        const auto it = std::find_if(annotated.begin(), annotated.end(), [&](const auto& d) { return d.sha256 == sha; });
        const bool known = it != annotated.end() && it->latest.id != 0;
        auto* name = new QTableWidgetItem(known ? QString::fromStdString(it->latest.fileName)
                                                : QString::fromStdString(sha.substr(0, 16)) + QStringLiteral("..."));
        if (known) {
            name->setData(kPathRole, QString::fromStdString(it->latest.filePath));
            name->setToolTip(QString::fromStdString(it->latest.filePath));
        }
        m_tagged->setItem(i, 0, name);
        auto* risk = new QTableWidgetItem(known ? QStringLiteral("%1 %2").arg(it->latest.riskScore).arg(
                                                      QString::fromStdString(it->latest.riskLevel))
                                                : QStringLiteral("-"));
        if (known) {
            risk->setForeground(QBrush(riskLevelColor(QString::fromStdString(it->latest.riskLevel))));
        }
        m_tagged->setItem(i, 1, risk);
    }
    m_tagged->resizeColumnToContents(1);
}

// ============================================================== Workspace ==

WorkspaceWidget::WorkspaceWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = dockLayout(this);
    m_header = makeHeader(this);
    layout->addWidget(m_header);
    m_table = makeTable(this, {tr("Driver"), tr("Risk"), tr("Tags"), tr("Marks"), tr("Notes")}, 0);
    layout->addWidget(m_table, 1);
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        const QString path = m_table->item(row, 0)->data(kPathRole).toString();
        if (!path.isEmpty()) {
            emit openDriverRequested(path);
        }
    });
    refresh();
}

void WorkspaceWidget::setDatabase(DatabasePtr db) {
    m_db = std::move(db);
    refresh();
}

void WorkspaceWidget::refresh() {
    m_table->setRowCount(0);
    if (!m_db) {
        m_header->setText(tr("The analysis database is unavailable."));
        return;
    }
    const auto drivers = m_db->annotatedDrivers();
    m_header->setText(drivers.empty()
                          ? tr("Drivers you bookmark, tag or write notes about are collected here.")
                          : tr("%n driver(s) under investigation. Double-click to open one.", nullptr,
                               static_cast<int>(drivers.size())));
    m_table->setRowCount(static_cast<int>(drivers.size()));
    for (int i = 0; i < static_cast<int>(drivers.size()); ++i) {
        const auto& d = drivers[static_cast<std::size_t>(i)];
        const bool known = d.latest.id != 0;
        auto* name = new QTableWidgetItem(known ? QString::fromStdString(d.latest.fileName)
                                                : QString::fromStdString(d.sha256.substr(0, 16)) + QStringLiteral("..."));
        if (known) {
            name->setData(kPathRole, QString::fromStdString(d.latest.filePath));
            name->setToolTip(tr("%1\nlast analysed %2")
                                 .arg(QString::fromStdString(d.latest.filePath), localTime(d.latest.analyzedAt)));
        }
        m_table->setItem(i, 0, name);
        auto* risk = new QTableWidgetItem(known ? QString::number(d.latest.riskScore) : QStringLiteral("-"));
        if (known) {
            risk->setForeground(QBrush(riskLevelColor(QString::fromStdString(d.latest.riskLevel))));
        }
        m_table->setItem(i, 1, risk);
        QStringList tags;
        for (const auto& t : d.tags) {
            tags << QString::fromStdString(t);
        }
        m_table->setItem(i, 2, new QTableWidgetItem(tags.join(QStringLiteral(", "))));
        m_table->setItem(i, 3, new QTableWidgetItem(QString::number(d.bookmarks)));
        auto* notes = new QTableWidgetItem(d.hasNotes ? localTime(d.notesUpdatedAt) : QString());
        m_table->setItem(i, 4, notes);
    }
    for (int c = 1; c < 5; ++c) {
        m_table->resizeColumnToContents(c);
    }
}

} // namespace dasa::ui
