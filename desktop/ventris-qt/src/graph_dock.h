#pragma once

#include <QDockWidget>

class CoreBridge;
class GraphCanvas;

class GraphDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit GraphDock(CoreBridge *bridge, QWidget *parent = nullptr);

    GraphCanvas *canvas() const { return canvas_; }

    void loadGraph(const QString &binary, const QString &address);

signals:
    void addressSelected(const QString &address, bool record);
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);

private:
    CoreBridge *bridge_;
    GraphCanvas *canvas_ = nullptr;
};
