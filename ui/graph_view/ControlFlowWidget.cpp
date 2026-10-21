#include "ui/graph_view/ControlFlowWidget.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>

#include <unordered_map>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/cfg/ControlFlowGraph.h"
#include "ui/graph_view/GraphUtil.h"
#include "ui/graph_view/GraphView.h"

namespace dasa::ui {

namespace fn = core::functions;
namespace cfg = core::cfg;

namespace {

// Bigger functions are listed in Functions but not drawn: the layout and
// the scene get slow and the drawing unreadable.
constexpr std::size_t kMaxBlocks = 700;
constexpr int kMaxLinesPerBlock = 40;

QColor edgeColor(cfg::EdgeKind kind) {
    switch (kind) {
    case cfg::EdgeKind::Taken: return QColor(0x6c, 0xc6, 0x8a);
    case cfg::EdgeKind::FallThrough: return QColor(0xf1, 0x70, 0x6b);
    case cfg::EdgeKind::Unconditional: return QColor(0x7f, 0xb2, 0xe5);
    }
    return QColor(0xb0, 0xb0, 0xb0);
}

} // namespace

ControlFlowWidget::ControlFlowWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 10, 16, 10);
    layout->setSpacing(8);

    auto* bar = new QHBoxLayout;
    bar->setSpacing(8);
    m_title = new QLabel(this);
    m_title->setTextFormat(Qt::RichText);
    m_title->setTextInteractionFlags(Qt::TextSelectableByMouse);
    bar->addWidget(m_title);
    m_info = new QLabel(this);
    m_info->setStyleSheet(QStringLiteral("color:#9a9a9a"));
    m_info->setMinimumWidth(1);
    bar->addWidget(m_info, 1);
    m_goTo = new QLineEdit(this);
    m_goTo->setPlaceholderText(tr("Go to function (name or RVA)"));
    m_goTo->setClearButtonEnabled(true);
    m_goTo->setMaximumWidth(260);
    bar->addWidget(m_goTo);
    m_view = new GraphView(this);
    addZoomButtons(bar, m_view, this);
    layout->addLayout(bar);
    layout->addWidget(m_view, 1);

    auto* legend = new QLabel(
        tr("<span style='color:#6cc68a'>&#9632; taken</span> &nbsp; <span style='color:#f1706b'>&#9632; not taken"
           "</span> &nbsp; <span style='color:#7fb2e5'>&#9632; jump</span> &nbsp; dashed = loop back edge &nbsp; "
           "<span style='color:#9a9a9a'>Wheel zooms, drag pans, double-click a block to open the function it "
           "calls.</span>"),
        this);
    legend->setMinimumWidth(1);
    layout->addWidget(legend);

    connect(m_goTo, &QLineEdit::returnPressed, this, &ControlFlowWidget::goTo);
    connect(m_view, &GraphView::nodeActivated, this, [this](const QVariant& key) {
        const auto target = key.toULongLong();
        if (target != 0) {
            emit functionActivated(target);
        }
    });
    clear();
}

void ControlFlowWidget::clear() {
    m_result.reset();
    m_current = 0;
    m_title->setText(tr("<b>Control Flow</b>"));
    m_info->clear();
    m_view->showMessage(tr("Load a driver, then pick a function in Functions, Call Graph or here."));
}

void ControlFlowWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_current = 0;
    if (const auto start = defaultFunction(*m_result)) {
        showFunction(*start);
    } else {
        m_view->showMessage(tr("No functions were found in this driver."));
    }
}

void ControlFlowWidget::goTo() {
    if (!m_result) {
        return;
    }
    if (const auto rva = findFunction(*m_result, m_goTo->text())) {
        showFunction(*rva);
        emit functionActivated(*rva);
    } else {
        m_info->setText(tr("No function matches \"%1\".").arg(m_goTo->text()));
    }
}

void ControlFlowWidget::showFunction(std::uint64_t rva) {
    if (!m_result) {
        return;
    }
    const auto& set = *m_result->functions;
    const fn::Function* f = functionContaining(set, rva);
    if (!f) {
        return;
    }
    if (f->rva == m_current) {
        return;
    }
    m_current = f->rva;
    m_title->setText(QStringLiteral("<b>%1</b> <span style='color:#9a9a9a'>%2</span>")
                         .arg(QString::fromStdString(f->name).toHtmlEscaped(), hexRva(f->rva)));

    const auto g = cfg::buildControlFlowGraph(*f);
    QStringList notes;
    notes << tr("%1 blocks, %2 edges, %3 instructions")
                 .arg(g.blocks.size())
                 .arg(g.edges.size())
                 .arg(f->instructions.size());
    if (f->hasUnresolvedIndirectJump) {
        notes << tr("has a switch/indirect jump whose targets weren't followed - the graph may be incomplete");
    }
    if (f->truncated) {
        notes << tr("decoding stopped early - the graph is incomplete");
    }
    m_info->setText(notes.join(QStringLiteral(" · ")));

    if (g.blocks.size() > kMaxBlocks) {
        m_view->showMessage(tr("%1 has %2 basic blocks - too many to draw readably (limit %3). Its "
                               "disassembly is in the Functions view.")
                                .arg(QString::fromStdString(f->name))
                                .arg(g.blocks.size())
                                .arg(kMaxBlocks));
        return;
    }

    // Call annotations, keyed by call instruction RVA.
    std::unordered_map<std::uint64_t, const fn::CallSite*> calls;
    for (const auto& c : f->calls) {
        calls[c.rva] = &c;
    }

    std::vector<GraphNodeSpec> nodes;
    nodes.reserve(g.blocks.size());
    for (std::size_t i = 0; i < g.blocks.size(); ++i) {
        const auto& b = *g.blocks[i];
        GraphNodeSpec node;
        node.title = i == g.entry ? QStringLiteral("%1  (entry)").arg(QString::fromStdString(f->name))
                                  : QStringLiteral("loc_") + hex8(b.start);
        std::uint64_t firstCallee = 0;
        const int count = static_cast<int>(b.instructionCount);
        for (int k = 0; k < count; ++k) {
            if (k == kMaxLinesPerBlock && count > kMaxLinesPerBlock + 1) {
                node.lines << tr("... %1 more instructions").arg(count - k);
                break;
            }
            const auto& insn = f->instructions[b.firstInstruction + static_cast<std::uint32_t>(k)];
            QString line = hex8(insn.rva) + QStringLiteral("  ") + QString::fromStdString(insn.text());
            if (const auto it = calls.find(insn.rva); it != calls.end()) {
                const auto* c = it->second;
                if (!c->importName.empty()) {
                    line += QStringLiteral("    ; ") + QString::fromStdString(importShortName(c->importName));
                } else if (c->target) {
                    const auto* callee = set.find(*c->target);
                    line += QStringLiteral("    ; ") +
                            (callee ? QString::fromStdString(callee->name) : hexRva(*c->target));
                    if (callee && firstCallee == 0 && callee->rva != f->rva) {
                        firstCallee = callee->rva;
                    }
                }
            }
            node.lines << line;
        }
        if (g.exits[i] != cfg::BlockExit::None && g.exits[i] != cfg::BlockExit::Return) {
            node.lines << QStringLiteral("-> ") + QString::fromLatin1(cfg::blockExitName(g.exits[i]));
        }
        const bool warn = g.exits[i] == cfg::BlockExit::IndirectJump;
        node.fill = i == g.entry ? QColor(0x23, 0x2e, 0x3a) : QColor(0x26, 0x26, 0x29);
        node.border = warn ? QColor(0xe5, 0xa5, 0x4b) : (i == g.entry ? QColor(0x4a, 0x90, 0xd9) : QColor(0x4a, 0x4a, 0x50));
        node.borderWidth = i == g.entry || warn ? 2.0 : 1.0;
        node.key = static_cast<qulonglong>(firstCallee);
        node.toolTip = firstCallee ? tr("Double-click to open %1").arg(QString::fromStdString(set.find(firstCallee)->name))
                                   : QString();
        nodes.push_back(std::move(node));
    }
    std::vector<GraphEdgeSpec> edges;
    edges.reserve(g.edges.size());
    for (const auto& e : g.edges) {
        GraphEdgeSpec spec;
        spec.from = e.from;
        spec.to = e.to;
        spec.color = edgeColor(e.kind);
        // Drawn dashed when it goes back up (decided by the layout too, but
        // address order is the reader's cue for a loop).
        spec.dashed = g.blocks[e.to]->start <= g.blocks[e.from]->start;
        edges.push_back(spec);
    }
    m_view->setGraph(nodes, edges, g.entry);
    m_view->zoomReset();
    m_view->centerOnNode(g.entry);
}

} // namespace dasa::ui
