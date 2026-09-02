#include "graph_canvas.h"

#include "json_util.h"

#include <QPainter>

#include <cmath>

GraphCanvas::GraphCanvas(QWidget *parent) : QWidget(parent) {
    setMinimumSize(420, 260);
}

void GraphCanvas::setGraph(const QJsonObject &graph) {
    nodes_ = graph.value("nodes").toArray();
    edges_ = graph.value("edges").toArray();
    update();
}

void GraphCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), QColor("#101419"));
    painter.setRenderHint(QPainter::Antialiasing);
    const int columns = qMax(1, qCeil(std::sqrt(static_cast<double>(nodes_.size()))));
    const int cell_width = qMax(150, width() / columns);
    const int cell_height = 64;
    auto node_index = [this](const QJsonValue &address) {
        const QString target = addressText(address);
        for (int index = 0; index < nodes_.size(); ++index) {
            if (addressText(nodes_.at(index).toObject().value("address")) == target) {
                return index;
            }
        }
        return -1;
    };
    auto center = [columns, cell_width, cell_height](int index) {
        const int row = index / columns;
        const int column = index % columns;
        return QPoint(column * cell_width + cell_width / 2, row * cell_height + 32);
    };
    painter.setPen(QColor("#56606d"));
    for (const QJsonValue &value : edges_) {
        const QJsonObject edge = value.toObject();
        const int from = node_index(edge.value("from"));
        const int to = node_index(edge.value("to"));
        if (from >= 0 && to >= 0) {
            painter.drawLine(center(from), center(to));
        }
    }
    for (int index = 0; index < nodes_.size(); ++index) {
        const QJsonObject node = nodes_.at(index).toObject();
        const QPoint point = center(index);
        const QRect box(point.x() - cell_width / 2 + 6, point.y() - 22, cell_width - 12, 44);
        painter.setBrush(QColor("#202a35"));
        painter.setPen(QColor("#79b8ff"));
        painter.drawRoundedRect(box, 5, 5);
        painter.setPen(QColor("#d6dee8"));
        painter.drawText(box.adjusted(6, 5, -6, -5), Qt::AlignCenter,
                         node.value("name").toString() + QStringLiteral("\n") +
                             addressText(node.value("address")));
    }
}
