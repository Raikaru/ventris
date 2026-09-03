#include "graph_canvas.h"

#include <QFontDatabase>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>

namespace {

const QColor kBackground("#101419");
const QColor kNodeFill("#202a35");
const QColor kNodeBorder("#79b8ff");
const QColor kNodeHighlight("#e5c07b");
const QColor kNodeText("#d6dee8");
const QColor kEdgeTrue("#98c379");
const QColor kEdgeFalse("#e06c75");
const QColor kEdgeUnconditional("#56606d");
const QColor kEdgeCall("#c678dd");
const QColor kEmptyText("#7e8996");

constexpr int kNodeWidth = 180;
constexpr int kNodeHeight = 60;

QColor edgeColor(const QString &kind) {
    if (kind == QStringLiteral("true")) {
        return kEdgeTrue;
    }
    if (kind == QStringLiteral("false")) {
        return kEdgeFalse;
    }
    if (kind == QStringLiteral("call")) {
        return kEdgeCall;
    }
    return kEdgeUnconditional;
}

}  // namespace

GraphCanvas::GraphCanvas(QWidget *parent) : QWidget(parent) {
    setMinimumSize(420, 260);
    setMouseTracking(false);
}

void GraphCanvas::setGraph(const QVector<Node> &nodes, const QVector<Edge> &edges) {
    nodes_ = nodes;
    edges_ = edges;
    zoom_ = 1.0;
    pan_ = QPointF(0, 0);
    fit_pending_ = true;  // fit once the widget knows its size
    update();
}

void GraphCanvas::setAddress(const QString &address) {
    highlight_address_ = address;
    update();
}

void GraphCanvas::fitToView() {
    if (nodes_.isEmpty()) {
        return;
    }
    QRectF bounds;
    for (const Node &node : nodes_) {
        bounds = bounds.united(QRectF(node.pos, QSizeF(kNodeWidth, kNodeHeight)));
    }
    if (bounds.width() <= 0 || bounds.height() <= 0) {
        return;
    }
    const double zx = width() / (bounds.width() + 40);
    const double zy = height() / (bounds.height() + 40);
    zoom_ = qBound(0.05, qMin(zx, zy), 2.0);
    pan_ = QPointF(-bounds.x() * zoom_ + 20, -bounds.y() * zoom_ + 20);
    update();
}

QSize GraphCanvas::sizeHint() const { return {640, 320}; }

QPointF GraphCanvas::nodeCenter(const Node &node) const {
    return QPointF(node.pos.x() + kNodeWidth / 2.0, node.pos.y() + kNodeHeight / 2.0) * zoom_ +
           pan_;
}

QString GraphCanvas::nodeAt(const QPoint &pos) const {
    for (const Node &node : nodes_) {
        const QPointF top_left = node.pos * zoom_ + pan_;
        if (pos.x() >= top_left.x() && pos.x() <= top_left.x() + kNodeWidth * zoom_ &&
            pos.y() >= top_left.y() && pos.y() <= top_left.y() + kNodeHeight * zoom_) {
            return node.address;
        }
    }
    return {};
}

void GraphCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), kBackground);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    if (nodes_.isEmpty()) {
        painter.setPen(kEmptyText);
        painter.drawText(rect().adjusted(8, 8, -8, -8), Qt::AlignTop | Qt::AlignLeft,
                         QStringLiteral("No function graph loaded"));
        return;
    }
    if (fit_pending_) {
        fit_pending_ = false;
        fitToView();
    }

    // Edges: straight lines colored by kind; call edges dashed.
    for (const Edge &edge : edges_) {
        const Node *from = nullptr;
        const Node *to = nullptr;
        for (const Node &node : nodes_) {
            if (node.address == edge.from && from == nullptr) {
                from = &node;
            }
            if (node.address == edge.to && to == nullptr) {
                to = &node;
            }
        }
        if (from == nullptr) {
            continue;  // call edges may target other functions
        }
        const QPointF start = nodeCenter(*from);
        const QPointF end = to != nullptr
                                ? nodeCenter(*to)
                                : start + QPointF(0, kNodeHeight * zoom_);
        QPen pen(edgeColor(edge.kind), 1.5);
        if (edge.kind == QStringLiteral("call")) {
            pen.setStyle(Qt::DashLine);
        }
        painter.setPen(pen);
        painter.drawLine(start, end);
        // Arrowhead for non-call edges.
        if (to != nullptr) {
            const QPointF dir = end - start;
            const double len = qSqrt(dir.x() * dir.x() + dir.y() * dir.y());
            if (len > 1) {
                const QPointF unit = dir / len;
                const QPointF tip = end;
                const QPointF left = tip - unit * 10 +
                                     QPointF(-unit.y(), unit.x()) * 5;
                const QPointF right = tip - unit * 10 +
                                      QPointF(unit.y(), -unit.x()) * 5;
                painter.setBrush(QBrush(pen.color()));
                painter.drawPolygon({tip, left, right});
                painter.setBrush(Qt::NoBrush);
            }
        }
    }

    // Nodes.
    for (const Node &node : nodes_) {
        const QPointF top_left = node.pos * zoom_ + pan_;
        const QRectF box(top_left, QSizeF(kNodeWidth * zoom_, kNodeHeight * zoom_));
        const bool highlighted = node.address == highlight_address_;
        painter.setBrush(QBrush(kNodeFill));
        painter.setPen(QPen(highlighted ? kNodeHighlight : kNodeBorder, highlighted ? 2 : 1));
        painter.drawRoundedRect(box, 5, 5);
        painter.setPen(kNodeText);
        const QString label = QStringLiteral("bb_%1\n%2 bytes")
                                  .arg(node.address)
                                  .arg(node.size);
        painter.drawText(box.adjusted(6, 4, -6, -4), Qt::AlignCenter, label);
    }
}

void GraphCanvas::wheelEvent(QWheelEvent *event) {
    const double factor = event->angleDelta().y() > 0 ? 1.15 : 1 / 1.15;
    const double new_zoom = qBound(0.05, zoom_ * factor, 3.0);
    // Zoom around the cursor.
    const QPointF cursor = event->position();
    pan_ = cursor - (cursor - pan_) * (new_zoom / zoom_);
    zoom_ = new_zoom;
    update();
    event->accept();
}

void GraphCanvas::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::MiddleButton ||
        (event->button() == Qt::LeftButton && event->modifiers() & Qt::ShiftModifier)) {
        panning_ = true;
        pan_start_ = event->pos();
        event->accept();
        return;
    }
    if (event->button() == Qt::LeftButton) {
        const QString address = nodeAt(event->pos());
        if (!address.isEmpty()) {
            highlight_address_ = address;
            emit addressSelected(address, true);
            update();
            event->accept();
            return;
        }
    }
    QWidget::mousePressEvent(event);
}

void GraphCanvas::mouseMoveEvent(QMouseEvent *event) {
    if (panning_) {
        pan_ += QPointF(event->pos() - pan_start_);
        pan_start_ = event->pos();
        update();
        event->accept();
    }
}

void GraphCanvas::mouseReleaseEvent(QMouseEvent *event) {
    panning_ = false;
    QWidget::mouseReleaseEvent(event);
}

void GraphCanvas::mouseDoubleClickEvent(QMouseEvent *event) {
    const QString address = nodeAt(event->pos());
    if (!address.isEmpty()) {
        emit addressSelected(address, true);
    }
    event->accept();
}

void GraphCanvas::resizeEvent(QResizeEvent *event) {
    if (!nodes_.isEmpty() && fit_pending_) {
        fit_pending_ = false;
        fitToView();
    }
    QWidget::resizeEvent(event);
}
