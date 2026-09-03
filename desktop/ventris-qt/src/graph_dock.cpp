#include "graph_dock.h"

#include "core_bridge.h"
#include "graph_canvas.h"
#include "json_util.h"

#include <QJsonArray>
#include <QJsonObject>

GraphDock::GraphDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Function graph"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("functionGraphDock"));
    canvas_ = new GraphCanvas(this);
    connect(canvas_, &GraphCanvas::addressSelected, this,
            [this](const QString &address, bool record) {
                emit addressSelected(address, record);
            });
    setWidget(canvas_);
}

void GraphDock::loadGraph(const QString &binary, const QString &address) {
    if (binary.isEmpty() || address.isEmpty()) {
        return;
    }
    const QString job_name = QStringLiteral("function graph %1").arg(address);
    emit jobStarted(job_name);
    bridge_->request(QJsonObject{{"method", "function_bb_graph"},
                                 {"binary", binary},
                                 {"address", address}},
                     [this, job_name](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(job_name, false, error);
                             return;
                         }
                         const QJsonObject result = response.value("result").toObject();
                         GraphCanvas::Node node;
                         GraphCanvas::Edge edge;
                         QVector<GraphCanvas::Node> nodes;
                         QVector<GraphCanvas::Edge> edges;
                         for (const QJsonValue &value : result.value("nodes").toArray()) {
                             const QJsonObject row = value.toObject();
                             node.address = row.value("address").toString();
                             node.size = row.value("size").toVariant().toULongLong();
                             node.pos = QPointF(row.value("x").toVariant().toDouble(),
                                                row.value("y").toVariant().toDouble());
                             nodes.append(node);
                         }
                         for (const QJsonValue &value : result.value("edges").toArray()) {
                             const QJsonObject row = value.toObject();
                             edge.from = row.value("from").toString();
                             edge.to = row.value("to").toString();
                             edge.kind = row.value("kind").toString();
                             edges.append(edge);
                         }
                         canvas_->setGraph(nodes, edges);
                         emit jobFinished(job_name, true, QStringLiteral("graph loaded"));
                     });
}
