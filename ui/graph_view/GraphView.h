#pragma once

#include <QColor>
#include <QGraphicsView>
#include <QStringList>
#include <QVariant>

#include <vector>

#include "core/cfg/GraphLayout.h"

class QGraphicsScene;

namespace dasa::ui {

/// A node to draw: a bold title line, body lines in a monospace font, and
/// colours. `key` comes back in nodeActivated() on double-click.
struct GraphNodeSpec {
    QString title;
    QStringList lines;
    QColor fill;
    QColor border;
    double borderWidth = 1.0;
    QString toolTip;
    QVariant key;
};

struct GraphEdgeSpec {
    std::size_t from = 0;
    std::size_t to = 0;
    QColor color;
    bool dashed = false;
    QString label; // drawn at the middle of the route, e.g. "x3"
};

/// Zoomable, pannable canvas that lays out and draws a graph with
/// core::cfg::layoutLayered(). Wheel zooms around the cursor, dragging
/// pans, double-click on a node emits nodeActivated().
class GraphView : public QGraphicsView {
    Q_OBJECT

public:
    explicit GraphView(QWidget* parent = nullptr);

    /// Replaces the scene contents. `root` is the node laid out at the top.
    void setGraph(const std::vector<GraphNodeSpec>& nodes, const std::vector<GraphEdgeSpec>& edges,
                  std::size_t root = 0);
    /// Shows a centred message instead of a graph.
    void showMessage(const QString& text);
    void clearGraph();

    void zoomIn();
    void zoomOut();
    void zoomReset();
    void fitAll();
    /// Scrolls to the node: its top near the top of the view, or centred.
    void centerOnNode(std::size_t index, bool atTop = true);

signals:
    void nodeActivated(const QVariant& key);

protected:
    void wheelEvent(QWheelEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    void scaleBy(double factor);
    void runPending();

    // fitAll()/centerOnNode() called while the view is hidden (another tab
    // is in front) would use a meaningless viewport size; they run when the
    // view is next shown instead.
    enum class Pending { None, Fit, Center };
    Pending m_pending = Pending::None;
    std::size_t m_pendingNode = 0;
    bool m_pendingAtTop = true;

    QGraphicsScene* m_scene = nullptr;
    std::vector<QRectF> m_nodeRects;
};

} // namespace dasa::ui
