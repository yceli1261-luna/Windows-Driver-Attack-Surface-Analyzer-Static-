#include "ui/graph_view/GraphView.h"

#include <QFontDatabase>
#include <QFontMetricsF>
#include <QGraphicsItem>
#include <QGraphicsScene>
#include <QMouseEvent>
#include <QPainterPath>
#include <QPen>
#include <QResizeEvent>
#include <QScrollBar>
#include <QShowEvent>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>

namespace dasa::ui {

namespace {

constexpr int kKeyRole = 0;
constexpr double kPadX = 10, kPadY = 7, kTitleGap = 4;
constexpr double kMinScale = 0.05, kMaxScale = 4.0;

QFont monoFont() {
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    f.setPointSizeF(9.5);
    return f;
}

QFont titleFont() {
    QFont f = monoFont();
    f.setBold(true);
    return f;
}

void addArrowHead(QGraphicsScene* scene, QPointF tip, QPointF from, const QColor& color) {
    const QLineF line(from, tip);
    if (line.length() < 0.01) {
        return;
    }
    const double angle = std::atan2(tip.y() - from.y(), tip.x() - from.x());
    constexpr double len = 9, spread = 0.42;
    QPolygonF head;
    head << tip << QPointF(tip.x() - len * std::cos(angle - spread), tip.y() - len * std::sin(angle - spread))
         << QPointF(tip.x() - len * std::cos(angle + spread), tip.y() - len * std::sin(angle + spread));
    auto* item = scene->addPolygon(head, QPen(color, 1), QBrush(color));
    item->setZValue(2);
}

} // namespace

GraphView::GraphView(QWidget* parent) : QGraphicsView(parent), m_scene(new QGraphicsScene(this)) {
    setScene(m_scene);
    setRenderHints(QPainter::Antialiasing | QPainter::TextAntialiasing);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setViewportUpdateMode(QGraphicsView::BoundingRectViewportUpdate);
    setBackgroundBrush(QColor(0x1b, 0x1b, 0x1d));
    setFrameShape(QFrame::NoFrame);
}

void GraphView::clearGraph() {
    m_pending = Pending::None;
    m_scene->clear();
    m_nodeRects.clear();
    resetTransform();
}

void GraphView::showMessage(const QString& text) {
    clearGraph();
    auto* item = m_scene->addText(text);
    item->setDefaultTextColor(QColor(0x9a, 0x9a, 0x9a));
    item->setTextWidth(520);
    m_scene->setSceneRect(item->boundingRect().adjusted(-20, -20, 20, 20));
    centerOn(item);
}

void GraphView::setGraph(const std::vector<GraphNodeSpec>& nodes, const std::vector<GraphEdgeSpec>& edges,
                         std::size_t root) {
    clearGraph();
    const QFont body = monoFont(), title = titleFont();
    const QFontMetricsF bodyM(body), titleM(title);

    // Measure every node, then lay out.
    std::vector<core::cfg::LayoutNode> sizes;
    sizes.reserve(nodes.size());
    for (const auto& n : nodes) {
        double w = titleM.horizontalAdvance(n.title);
        for (const auto& line : n.lines) {
            w = std::max(w, bodyM.horizontalAdvance(line));
        }
        double h = titleM.height();
        if (!n.lines.isEmpty()) {
            h += kTitleGap + bodyM.lineSpacing() * n.lines.size();
        }
        sizes.push_back({std::ceil(w + 2 * kPadX), std::ceil(h + 2 * kPadY)});
    }
    std::vector<core::cfg::LayoutEdge> layoutEdges;
    layoutEdges.reserve(edges.size());
    for (const auto& e : edges) {
        layoutEdges.push_back({e.from, e.to});
    }
    const auto layout = core::cfg::layoutLayered(sizes, layoutEdges, root);

    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto& spec = nodes[i];
        const QRectF rect(layout.nodes[i].x, layout.nodes[i].y, sizes[i].width, sizes[i].height);
        m_nodeRects.push_back(rect);
        auto* box = m_scene->addRect(rect, QPen(spec.border, spec.borderWidth), QBrush(spec.fill));
        box->setZValue(1);
        box->setData(kKeyRole, spec.key);
        box->setToolTip(spec.toolTip);
        auto* t = new QGraphicsSimpleTextItem(spec.title, box);
        t->setFont(title);
        t->setBrush(QColor(0xe8, 0xe8, 0xe8));
        t->setPos(rect.x() + kPadX, rect.y() + kPadY);
        if (!spec.lines.isEmpty()) {
            auto* b = new QGraphicsSimpleTextItem(spec.lines.join(QLatin1Char('\n')), box);
            b->setFont(body);
            b->setBrush(QColor(0xc8, 0xc8, 0xc8));
            b->setPos(rect.x() + kPadX, rect.y() + kPadY + titleM.height() + kTitleGap);
        }
    }

    for (std::size_t i = 0; i < edges.size(); ++i) {
        const auto& pts = layout.edges[i].points;
        if (pts.size() < 2) {
            continue;
        }
        QPainterPath path(QPointF(pts[0].x, pts[0].y));
        for (std::size_t k = 1; k < pts.size(); ++k) {
            path.lineTo(pts[k].x, pts[k].y);
        }
        QPen pen(edges[i].color, 1.4);
        if (edges[i].dashed) {
            pen.setStyle(Qt::DashLine);
        }
        auto* item = m_scene->addPath(path, pen);
        item->setZValue(0);
        const QPointF tip(pts.back().x, pts.back().y);
        const QPointF before(pts[pts.size() - 2].x, pts[pts.size() - 2].y);
        addArrowHead(m_scene, tip, before, edges[i].color);
        if (!edges[i].label.isEmpty()) {
            const auto& a = pts[pts.size() / 2 - (pts.size() % 2 == 0 ? 1 : 0)];
            const auto& b = pts[pts.size() / 2];
            auto* label = m_scene->addSimpleText(edges[i].label, body);
            label->setBrush(edges[i].color);
            label->setPos((a.x + b.x) / 2 + 4, (a.y + b.y) / 2 - bodyM.height() / 2);
            label->setZValue(2);
        }
    }
    m_scene->setSceneRect(QRectF(0, 0, layout.width, layout.height).adjusted(-40, -40, 40, 40));
}

void GraphView::scaleBy(double factor) {
    const double current = transform().m11();
    const double target = std::clamp(current * factor, kMinScale, kMaxScale);
    scale(target / current, target / current);
}

void GraphView::zoomIn() {
    scaleBy(1.25);
}

void GraphView::zoomOut() {
    scaleBy(0.8);
}

void GraphView::zoomReset() {
    resetTransform();
}

void GraphView::fitAll() {
    if (m_nodeRects.empty()) {
        return;
    }
    if (!isVisible()) {
        m_pending = Pending::Fit;
        return;
    }
    m_pending = Pending::None;
    fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
    // Never blow small graphs up past 100%.
    if (transform().m11() > 1.0) {
        resetTransform();
        centerOn(m_scene->sceneRect().center());
    }
}

void GraphView::centerOnNode(std::size_t index, bool atTop) {
    if (index >= m_nodeRects.size()) {
        return;
    }
    if (!isVisible()) {
        m_pending = Pending::Center;
        m_pendingNode = index;
        m_pendingAtTop = atTop;
        return;
    }
    m_pending = Pending::None;
    const QRectF r = m_nodeRects[index];
    if (!atTop) {
        centerOn(r.center());
        return;
    }
    centerOn(r.center().x(), r.top() + viewport()->height() / (2.0 * transform().m11()) - 30);
}

void GraphView::runPending() {
    if (m_pending == Pending::Fit) {
        fitAll();
    } else if (m_pending == Pending::Center) {
        centerOnNode(m_pendingNode, m_pendingAtTop);
    }
}

void GraphView::showEvent(QShowEvent* event) {
    QGraphicsView::showEvent(event);
    runPending();
}

void GraphView::resizeEvent(QResizeEvent* event) {
    QGraphicsView::resizeEvent(event);
    runPending();
}

void GraphView::wheelEvent(QWheelEvent* event) {
    const double steps = event->angleDelta().y() / 120.0;
    if (steps != 0) {
        scaleBy(std::pow(1.15, steps));
    }
    event->accept();
}

void GraphView::mouseDoubleClickEvent(QMouseEvent* event) {
    for (QGraphicsItem* item = itemAt(event->pos()); item; item = item->parentItem()) {
        const QVariant key = item->data(kKeyRole);
        if (key.isValid()) {
            emit nodeActivated(key);
            event->accept();
            return;
        }
    }
    QGraphicsView::mouseDoubleClickEvent(event);
}

} // namespace dasa::ui
