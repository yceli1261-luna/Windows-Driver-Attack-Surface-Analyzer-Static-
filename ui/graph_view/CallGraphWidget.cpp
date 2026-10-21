#include "ui/graph_view/CallGraphWidget.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <unordered_map>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "ui/findings_view/SeverityColors.h"
#include "ui/graph_view/GraphUtil.h"
#include "ui/graph_view/GraphView.h"

namespace dasa::ui {

namespace cg = core::callgraph;
namespace sec = core::security;
namespace fnd = core::findings;

namespace {

QColor riskColor(sec::ApiRisk risk) {
    switch (risk) {
    case sec::ApiRisk::Critical: return severityColor(fnd::Severity::Critical);
    case sec::ApiRisk::High: return severityColor(fnd::Severity::High);
    case sec::ApiRisk::Medium: return severityColor(fnd::Severity::Medium);
    default: break;
    }
    return QColor(0x5a, 0x5a, 0x60);
}

QSpinBox* depthBox(QWidget* parent, int value, const QString& tip) {
    auto* box = new QSpinBox(parent);
    box->setRange(0, 8);
    box->setValue(value);
    box->setToolTip(tip);
    return box;
}

} // namespace

CallGraphWidget::CallGraphWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 10, 16, 10);
    layout->setSpacing(8);

    auto* bar = new QHBoxLayout;
    bar->setSpacing(8);
    m_back = new QToolButton(this);
    m_back->setText(QStringLiteral("←"));
    m_back->setToolTip(tr("Back to the previous function"));
    m_back->setMinimumWidth(32);
    bar->addWidget(m_back);
    m_title = new QLabel(this);
    m_title->setTextFormat(Qt::RichText);
    bar->addWidget(m_title);
    bar->addSpacing(8);
    bar->addWidget(new QLabel(tr("Callers"), this));
    m_callers = depthBox(this, 1, tr("How many calls up from the focused function"));
    bar->addWidget(m_callers);
    bar->addWidget(new QLabel(tr("Callees"), this));
    m_callees = depthBox(this, 1, tr("How many calls down from the focused function"));
    bar->addWidget(m_callees);
    bar->addWidget(new QLabel(tr("Imports"), this));
    m_imports = new QComboBox(this);
    m_imports->addItem(tr("of focused function"), static_cast<int>(cg::ImportScope::Focus));
    m_imports->addItem(tr("of all shown"), static_cast<int>(cg::ImportScope::All));
    m_imports->addItem(tr("none"), static_cast<int>(cg::ImportScope::None));
    m_imports->setToolTip(tr("Which kernel APIs to show"));
    bar->addWidget(m_imports);
    bar->addStretch(1);
    m_goTo = new QLineEdit(this);
    m_goTo->setPlaceholderText(tr("Go to function (name or RVA)"));
    m_goTo->setClearButtonEnabled(true);
    m_goTo->setMaximumWidth(240);
    bar->addWidget(m_goTo);
    m_cfg = new QToolButton(this);
    m_cfg->setText(tr("Control Flow"));
    m_cfg->setToolTip(tr("Open the focused function in the Control Flow view"));
    bar->addWidget(m_cfg);
    m_view = new GraphView(this);
    addZoomButtons(bar, m_view, this);
    layout->addLayout(bar);
    layout->addWidget(m_view, 1);

    m_info = new QLabel(this);
    m_info->setTextFormat(Qt::RichText);
    m_info->setMinimumWidth(1);
    layout->addWidget(m_info);

    connect(m_callers, &QSpinBox::valueChanged, this, &CallGraphWidget::rebuild);
    connect(m_callees, &QSpinBox::valueChanged, this, &CallGraphWidget::rebuild);
    connect(m_imports, &QComboBox::currentIndexChanged, this, &CallGraphWidget::rebuild);
    connect(m_back, &QToolButton::clicked, this, &CallGraphWidget::goBack);
    connect(m_cfg, &QToolButton::clicked, this, [this] {
        if (m_result && m_focus < m_graph.nodes.size()) {
            emit controlFlowRequested(m_graph.nodes[m_focus].rva);
        }
    });
    connect(m_goTo, &QLineEdit::returnPressed, this, [this] {
        if (!m_result) {
            return;
        }
        if (const auto rva = findFunction(*m_result, m_goTo->text())) {
            focusFunction(*rva);
            emit functionActivated(*rva);
        } else {
            m_info->setText(tr("No function matches \"%1\".").arg(m_goTo->text().toHtmlEscaped()));
        }
    });
    connect(m_view, &GraphView::nodeActivated, this, [this](const QVariant& key) {
        const auto rva = key.toULongLong();
        focusFunction(rva);
        emit functionActivated(rva);
    });
    clear();
}

void CallGraphWidget::clear() {
    m_result.reset();
    m_graph = {};
    m_focus = 0;
    m_history.clear();
    m_back->setEnabled(false);
    m_cfg->setEnabled(false);
    m_title->setText(tr("<b>Call Graph</b>"));
    m_info->clear();
    m_view->showMessage(tr("Load a driver to see who calls what."));
}

void CallGraphWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_graph = cg::buildCallGraph(*m_result->functions, m_result->kernelApis->entryPointFunctions);
    m_history.clear();
    m_focus = m_graph.nodes.size();
    if (const auto start = defaultFunction(*m_result)) {
        focusFunction(*start);
    } else {
        m_view->showMessage(tr("No functions were found in this driver."));
    }
}

void CallGraphWidget::focusFunction(std::uint64_t rva) {
    if (!m_result) {
        return;
    }
    const auto* f = functionContaining(*m_result->functions, rva);
    const std::size_t node = f ? m_graph.functionNode(f->rva) : m_graph.nodes.size();
    if (node >= m_graph.nodes.size() || node == m_focus) {
        return;
    }
    if (m_focus < m_graph.nodes.size()) {
        m_history.push_back(m_focus);
    }
    m_focus = node;
    rebuild();
}

void CallGraphWidget::goBack() {
    if (m_history.empty()) {
        return;
    }
    m_focus = m_history.back();
    m_history.pop_back();
    rebuild();
    emit functionActivated(m_graph.nodes[m_focus].rva);
}

void CallGraphWidget::rebuild() {
    m_back->setEnabled(!m_history.empty());
    if (!m_result || m_focus >= m_graph.nodes.size()) {
        return;
    }
    m_cfg->setEnabled(true);
    const auto& focus = m_graph.nodes[m_focus];
    m_title->setText(QStringLiteral("<b>%1</b> <span style='color:#9a9a9a'>%2</span>")
                         .arg(QString::fromStdString(focus.name).toHtmlEscaped(), hexRva(focus.rva)));

    std::unordered_map<std::string, sec::ApiRisk> risks;
    for (const auto& a : m_result->kernelApis->apis) {
        risks[a.name] = a.info.risk;
    }

    const auto nb = cg::neighborhood(m_graph, m_focus, m_callees->value(), m_callers->value(),
                                     static_cast<cg::ImportScope>(m_imports->currentData().toInt()));
    std::unordered_map<std::size_t, std::size_t> local; // graph node -> view node
    std::vector<GraphNodeSpec> nodes;
    for (std::size_t v : nb.nodes) {
        const auto& n = m_graph.nodes[v];
        local[v] = nodes.size();
        GraphNodeSpec spec;
        spec.title = QString::fromStdString(n.name);
        if (n.kind == cg::CallGraphNode::Kind::Import) {
            const auto it = risks.find(n.name);
            const sec::ApiRisk risk = it == risks.end() ? sec::ApiRisk::Info : it->second;
            spec.lines << QString::fromStdString(n.library);
            if (risk != sec::ApiRisk::Info) {
                spec.lines.back() += QStringLiteral(" · ") + QString::fromLatin1(sec::riskName(risk)) + tr(" risk");
            }
            spec.fill = QColor(0x20, 0x20, 0x22);
            spec.border = riskColor(risk);
            spec.borderWidth = risk == sec::ApiRisk::Info ? 1.0 : 2.0;
            spec.toolTip = tr("Kernel API (import)");
        } else {
            spec.lines << hexRva(n.rva);
            if (!n.roots.empty()) {
                QStringList roots;
                for (const auto& r : n.roots) {
                    roots << QString::fromStdString(r);
                }
                spec.lines << tr("entry: %1").arg(roots.join(QStringLiteral(", ")));
            }
            if (n.recursive) {
                spec.lines << tr("↻ in a call cycle");
            }
            const bool isFocus = v == m_focus;
            spec.fill = isFocus ? QColor(0x23, 0x2e, 0x3a) : QColor(0x26, 0x26, 0x29);
            spec.border = isFocus ? QColor(0x4a, 0x90, 0xd9)
                                  : (!n.roots.empty() ? QColor(0x6c, 0xc6, 0x8a) : QColor(0x4a, 0x4a, 0x50));
            spec.borderWidth = isFocus || !n.roots.empty() ? 2.0 : 1.0;
            spec.key = static_cast<qulonglong>(n.rva);
            spec.toolTip = tr("Double-click to centre on this function");
        }
        nodes.push_back(std::move(spec));
    }
    std::vector<GraphEdgeSpec> edges;
    for (std::size_t ei : nb.edges) {
        const auto& e = m_graph.edges[ei];
        GraphEdgeSpec spec;
        spec.from = local.at(e.from);
        spec.to = local.at(e.to);
        spec.color = QColor(0x8a, 0x8a, 0x92);
        spec.dashed = e.tailCall;
        if (e.callSites > 1) {
            spec.label = QStringLiteral("×%1").arg(e.callSites);
        }
        edges.push_back(spec);
    }

    // Lay out from the topmost caller so callers appear above the focus.
    std::size_t root = 0;
    for (std::size_t i = 0; i < nb.nodes.size(); ++i) {
        const auto& in = m_graph.in[nb.nodes[i]];
        const bool hasIncluded = std::any_of(in.begin(), in.end(), [&](std::size_t ei) {
            return local.count(m_graph.edges[ei].from) && m_graph.edges[ei].from != nb.nodes[i];
        });
        if (!hasIncluded && m_graph.nodes[nb.nodes[i]].kind == cg::CallGraphNode::Kind::Function) {
            root = i;
            break;
        }
    }
    m_view->setGraph(nodes, edges, root);
    // Small neighbourhoods fit the view; big ones would shrink to an
    // unreadable strip, so they open at 100% on the focused function.
    if (nodes.size() <= 16) {
        m_view->fitAll();
    } else {
        m_view->zoomReset();
        m_view->centerOnNode(local.at(m_focus), false);
    }

    std::size_t functions = 0, imports = 0;
    for (std::size_t v : nb.nodes) {
        (m_graph.nodes[v].kind == cg::CallGraphNode::Kind::Function ? functions : imports)++;
    }
    QString info = tr("%1 functions, %2 imports shown. Green border: entry point &middot; coloured imports: "
                      "risky APIs &middot; dashed: tail call &middot; &times;N: N call sites.")
                       .arg(functions)
                       .arg(imports);
    if (nb.truncated) {
        info += tr(" <span style='color:#e5a54b'>Limited to %1 nodes - lower the depth.</span>").arg(nb.nodes.size());
    }
    info += tr(" <span style='color:#9a9a9a'>Direct calls only: calls through pointers (callbacks, the WDF "
               "function table) aren't edges.</span>");
    m_info->setText(info);
}

} // namespace dasa::ui
