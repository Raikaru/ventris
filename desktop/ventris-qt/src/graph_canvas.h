#pragma once

#include <QJsonArray>
#include <QWidget>

/// Placeholder function-graph view: lays nodes out on a grid and draws
/// edges as straight lines. Replaced by the layered (Sugiyama) layout in
/// Phase 2; the API shape (setGraph over the function_graph request) stays.
class GraphCanvas final : public QWidget {
public:
    explicit GraphCanvas(QWidget *parent = nullptr);

    void setGraph(const QJsonObject &graph);

protected:
    void paintEvent(QPaintEvent *) override;

private:
    QJsonArray nodes_;
    QJsonArray edges_;
};
