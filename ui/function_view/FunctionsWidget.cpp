#include "ui/function_view/FunctionsWidget.h"

#include <QAbstractTableModel>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QTextBlock>
#include <QVBoxLayout>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::ui {

namespace fn = dasa::core::functions;
using dasa::core::disasm::Flow;

namespace {

QString hex(std::uint64_t value, int width = 8) {
    return QStringLiteral("0x") +
           QString::number(value, 16).toUpper().rightJustified(width, QLatin1Char('0'));
}

QString label(std::uint64_t rva) {
    return QStringLiteral("loc_") + QString::number(rva, 16).toUpper();
}

enum Column { kAddress, kName, kSize, kBlocks, kInstructions, kCalls, kCallers, kSource, kNotes, kColumnCount };

} // namespace

/// Table model over FunctionSet::functions. DisplayRole is formatted text,
/// UserRole the raw value the proxy sorts on.
class FunctionTableModel : public QAbstractTableModel {
public:
    using QAbstractTableModel::QAbstractTableModel;

    void setFunctions(std::shared_ptr<const fn::FunctionSet> set) {
        beginResetModel();
        m_set = std::move(set);
        endResetModel();
    }

    const fn::Function* functionAt(int row) const {
        if (!m_set || row < 0 || row >= static_cast<int>(m_set->functions.size())) {
            return nullptr;
        }
        return &m_set->functions[static_cast<std::size_t>(row)];
    }

    int rowCount(const QModelIndex& parent = {}) const override {
        return (parent.isValid() || !m_set) ? 0 : static_cast<int>(m_set->functions.size());
    }
    int columnCount(const QModelIndex& parent = {}) const override {
        return parent.isValid() ? 0 : kColumnCount;
    }

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
            return {};
        }
        switch (section) {
        case kAddress: return tr("Address (RVA)");
        case kName: return tr("Name");
        case kSize: return tr("Code bytes");
        case kBlocks: return tr("Blocks");
        case kInstructions: return tr("Instructions");
        case kCalls: return tr("Calls out");
        case kCallers: return tr("Callers");
        case kSource: return tr("Found via");
        case kNotes: return tr("Notes");
        default: return {};
        }
    }

    QVariant data(const QModelIndex& index, int role) const override {
        const fn::Function* f = functionAt(index.row());
        if (f == nullptr) {
            return {};
        }
        if (role == Qt::UserRole) {
            switch (index.column()) {
            case kAddress: return QVariant::fromValue<qulonglong>(f->rva);
            case kSize: return QVariant::fromValue<qulonglong>(f->codeBytes);
            case kBlocks: return static_cast<qulonglong>(f->blocks.size());
            case kInstructions: return static_cast<qulonglong>(f->instructions.size());
            case kCalls: return static_cast<qulonglong>(f->calls.size());
            case kCallers: return static_cast<qulonglong>(f->callers.size());
            default: break;
            }
            return data(index, Qt::DisplayRole);
        }
        if (role == Qt::TextAlignmentRole && index.column() >= kSize && index.column() <= kCallers) {
            return QVariant::fromValue(Qt::AlignRight | Qt::AlignVCenter);
        }
        if (role == Qt::ToolTipRole && index.column() == kNotes) {
            return notes(*f, true);
        }
        if (role != Qt::DisplayRole) {
            return {};
        }
        switch (index.column()) {
        case kAddress: return hex(f->rva);
        case kName: return QString::fromStdString(f->name);
        case kSize: return QString::number(f->codeBytes);
        case kBlocks: return QString::number(f->blocks.size());
        case kInstructions: return QString::number(f->instructions.size());
        case kCalls: return QString::number(f->calls.size());
        case kCallers: return QString::number(f->callers.size());
        case kSource: return QString::fromStdString(fn::describeSources(f->sources));
        case kNotes: return notes(*f, false);
        default: return {};
        }
    }

private:
    static QString notes(const fn::Function& f, bool verbose) {
        QStringList out;
        if (f.hasUnresolvedIndirectJump) {
            out << (verbose ? tr("Contains an indirect jump (e.g. a switch table) whose targets "
                                 "were not followed; the body may be incomplete.")
                            : tr("indirect jump"));
        }
        if (f.truncated) {
            out << (verbose ? tr("Disassembly stopped at undecodable bytes or the size limit.")
                            : tr("truncated"));
        }
        return out.join(verbose ? QStringLiteral("\n") : QStringLiteral(", "));
    }

    std::shared_ptr<const fn::FunctionSet> m_set;
};

FunctionsWidget::FunctionsWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    auto* splitter = new QSplitter(Qt::Horizontal, this);

    auto* left = new QWidget(splitter);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    m_filter = new QLineEdit(left);
    m_filter->setPlaceholderText(tr("Filter by name or address"));
    m_filter->setClearButtonEnabled(true);
    leftLayout->addWidget(m_filter);
    m_summary = new QLabel(left);
    m_summary->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    m_summary->setWordWrap(true);
    leftLayout->addWidget(m_summary);

    m_model = new FunctionTableModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setSortRole(Qt::UserRole);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);

    m_table = new QTableView(left);
    m_table->setModel(m_proxy);
    m_table->setSortingEnabled(true);
    m_table->sortByColumn(kAddress, Qt::AscendingOrder);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(22);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    leftLayout->addWidget(m_table, 1);

    auto* right = new QWidget(splitter);
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    m_listingTitle = new QLabel(right);
    m_listingTitle->setTextFormat(Qt::RichText);
    m_listingTitle->setWordWrap(true);
    rightLayout->addWidget(m_listingTitle);
    m_listing = new QPlainTextEdit(right);
    m_listing->setReadOnly(true);
    m_listing->setLineWrapMode(QPlainTextEdit::NoWrap);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas"), mono.family()});
    m_listing->setFont(mono);
    m_listing->setToolTip(tr("Double-click a call to open the called function"));
    m_listing->viewport()->installEventFilter(this);
    rightLayout->addWidget(m_listing, 1);

    splitter->addWidget(left);
    splitter->addWidget(right);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 5);
    layout->addWidget(splitter);

    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_table->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            &FunctionsWidget::onCurrentRowChanged);

    clear();
}

FunctionsWidget::~FunctionsWidget() = default;

void FunctionsWidget::clear() {
    m_result.reset();
    m_imports.clear();
    m_model->setFunctions(nullptr);
    m_summary->setText(tr("No driver loaded."));
    m_listingTitle->clear();
    m_listing->clear();
}

void FunctionsWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_imports = core::functions::buildImportMap(*m_result->image);
    const auto& set = *m_result->functions;
    m_model->setFunctions(m_result->functions);
    m_table->resizeColumnsToContents();

    std::size_t fromPdata = 0;
    for (const auto& f : set.functions) {
        fromPdata += (f.sources & fn::kExceptionTable) ? 1 : 0;
    }
    m_summary->setText(
        tr("%1 functions, %2 instructions. %3 from .pdata, %4 seeds rejected. "
           "Recursive-descent disassembly: functions reached only through computed pointers "
           "may be missing.")
            .arg(set.functions.size())
            .arg(set.totalInstructions())
            .arg(fromPdata)
            .arg(set.rejectedSeeds.size()));

    if (!set.functions.empty()) {
        const std::uint64_t entry = m_result->image->entryPointRva;
        showFunction(set.find(entry) ? entry : set.functions.front().rva);
    } else {
        m_listingTitle->clear();
        m_listing->setPlainText(tr("No functions found."));
    }
}

void FunctionsWidget::showFunction(std::uint64_t rva) {
    if (!m_result) {
        return;
    }
    const auto& fns = m_result->functions->functions;
    for (std::size_t i = 0; i < fns.size(); ++i) {
        if (fns[i].rva == rva) {
            const QModelIndex proxyIndex = m_proxy->mapFromSource(m_model->index(static_cast<int>(i), 0));
            if (proxyIndex.isValid()) {
                m_table->setCurrentIndex(proxyIndex);
                m_table->scrollTo(proxyIndex);
            } else {
                renderListing(i); // filtered out of the table; still show it
            }
            return;
        }
    }
}

void FunctionsWidget::onCurrentRowChanged() {
    const QModelIndex source = m_proxy->mapToSource(m_table->currentIndex());
    if (source.isValid()) {
        renderListing(static_cast<std::size_t>(source.row()));
    }
}

void FunctionsWidget::renderListing(std::size_t functionIndex) {
    const auto& set = *m_result->functions;
    const fn::Function& f = set.functions[functionIndex];

    auto nameOf = [&](std::uint64_t rva) -> QString {
        if (const fn::Function* callee = set.find(rva)) {
            return QString::fromStdString(callee->name);
        }
        return hex(rva);
    };

    QStringList callers;
    for (std::uint64_t c : f.callers) {
        callers << nameOf(c).toHtmlEscaped();
    }
    m_listingTitle->setText(
        tr("<b>%1</b> &nbsp; RVA %2 &nbsp;&middot;&nbsp; %3 blocks, %4 instructions, %5 bytes"
           "<br><span style='color:#9a9a9a'>Found via: %6. Callers: %7</span>")
            .arg(QString::fromStdString(f.name).toHtmlEscaped(), hex(f.rva))
            .arg(f.blocks.size())
            .arg(f.instructions.size())
            .arg(f.codeBytes)
            .arg(QString::fromStdString(fn::describeSources(f.sources)),
                 callers.isEmpty() ? tr("none found") : callers.join(QStringLiteral(", "))));

    std::unordered_map<std::uint64_t, const fn::CallSite*> callAt;
    for (const auto& c : f.calls) {
        callAt.emplace(c.rva, &c);
    }

    QString text;
    text.reserve(static_cast<qsizetype>(f.instructions.size()) * 72);
    m_lineTargets.clear();
    std::size_t blockIndex = 0;
    for (const auto& insn : f.instructions) {
        if (blockIndex < f.blocks.size() && f.blocks[blockIndex].start == insn.rva) {
            if (blockIndex > 0) {
                text += QLatin1Char('\n');
                m_lineTargets.push_back(0);
            }
            text += (insn.rva == f.rva ? QString::fromStdString(f.name) : label(insn.rva)) +
                    QStringLiteral(":\n");
            m_lineTargets.push_back(0);
            ++blockIndex;
        }
        std::uint64_t target = 0;

        QString bytes;
        // Up to 7 bytes, compact; longer encodings are elided.
        const int shown = std::min<int>(insn.size, 7);
        for (int i = 0; i < shown; ++i) {
            bytes += QStringLiteral("%1").arg(insn.bytes[static_cast<std::size_t>(i)], 2, 16, QLatin1Char('0')).toUpper();
        }
        if (insn.size > 7) {
            bytes += QStringLiteral("..");
        }

        QString line = QStringLiteral("  %1  %2%3")
                           .arg(QString::number(insn.rva, 16).toUpper().rightJustified(8, QLatin1Char('0')),
                                bytes.leftJustified(18),
                                QString::fromStdString(insn.text()));

        QString comment;
        if (auto it = callAt.find(insn.rva); it != callAt.end()) {
            const fn::CallSite& c = *it->second;
            if (!c.importName.empty()) {
                comment = QString::fromStdString(c.importName);
            } else if (c.target) {
                comment = (c.isTailCall ? tr("tail call -> ") : QString()) + nameOf(*c.target);
                target = *c.target;
            } else {
                comment = tr("indirect call");
            }
        } else if ((insn.flow == Flow::Jump || insn.flow == Flow::CondJump) && insn.branchTarget) {
            comment = label(*insn.branchTarget);
        } else if (insn.flow == Flow::Jump && !insn.branchTarget) {
            comment = tr("indirect jump - targets not followed");
        } else if (insn.memoryRef && insn.memoryRefIsAddressOf && set.find(*insn.memoryRef)) {
            comment = QStringLiteral("&") + nameOf(*insn.memoryRef);
            target = *insn.memoryRef;
        } else if (insn.immediateRef && set.find(*insn.immediateRef)) {
            comment = QStringLiteral("&") + nameOf(*insn.immediateRef);
            target = *insn.immediateRef;
        } else if (insn.memoryRef) {
            if (auto imp = m_imports.find(*insn.memoryRef); imp != m_imports.end()) {
                comment = QString::fromStdString(imp->second);
            }
        }
        if (!comment.isEmpty()) {
            line = line.leftJustified(62) + QStringLiteral("  ; ") + comment;
        }
        text += line + QLatin1Char('\n');
        m_lineTargets.push_back(target);
    }
    m_listing->setPlainText(text);
}

bool FunctionsWidget::eventFilter(QObject* watched, QEvent* event) {
    // Double-clicking a line that calls or references a function opens it.
    if (watched == m_listing->viewport() && event->type() == QEvent::MouseButtonDblClick) {
        const auto* mouse = static_cast<QMouseEvent*>(event);
        const int line = m_listing->cursorForPosition(mouse->position().toPoint()).blockNumber();
        if (line >= 0 && line < static_cast<int>(m_lineTargets.size()) &&
            m_lineTargets[static_cast<std::size_t>(line)] != 0) {
            showFunction(m_lineTargets[static_cast<std::size_t>(line)]);
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

} // namespace dasa::ui
