#pragma once

#include <QHash>
#include <QPointF>
#include <QVector>
#include <QWidget>

/// Paint-based function-graph view over the function_bb_graph request
/// (Phase 2.1): layered layout computed in core, typed edges, pan/zoom/
/// fit, node clicks navigate. Blocks render address + size; the Listing
/// tokenizer arrives with per-block console text.
class GraphCanvas final : public QWidget {
    Q_OBJECT

public:
    explicit GraphCanvas(QWidget *parent = nullptr);

    struct Node {
        QString address;
        quint64 size = 0;
        QPointF pos;  // layout coordinates (core units)
    };
    struct Edge {
        QString from;
        QString to;
        QString kind;
    };

    /// Replaces the graph; resets zoom and fits to view.
    void setGraph(const QVector<Node> &nodes, const QVector<Edge> &edges);
    /// Highlights the node containing `address` (reverse sync).
    void setAddress(const QString &address);
    void fitToView();
    QSize sizeHint() const override;

signals:
    void addressSelected(const QString &address, bool record);

protected:
    void paintEvent(QPaintEvent *) override;
    void wheelEvent(QWheelEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void mouseDoubleClickEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    QPointF nodeCenter(const Node &node) const;
    QString nodeAt(const QPoint &pos) const;
    struct ResolvedEdge {
        int from_index = -1;
        int to_index = -1;
        QString kind;
    };

    QVector<Node> nodes_;
    QVector<Edge> edges_;
    QVector<ResolvedEdge> resolved_edges_;
    QHash<QString, int> node_lookup_;
    double zoom_ = 1.0;
    QPointF pan_;
    bool panning_ = false;
    QPoint pan_start_;
    QString highlight_address_;
    bool fit_pending_ = false;
};
