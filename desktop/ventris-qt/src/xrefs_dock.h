#pragma once

#include <QDockWidget>

class CoreBridge;
class QTableWidget;
class QTabWidget;

class XrefsDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit XrefsDock(CoreBridge *bridge, QWidget *parent = nullptr);

    void loadXrefs(const QString &program, const QString &address);

signals:
    void addressDoubleClicked(const QString &address);
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);

private:
    CoreBridge *bridge_;
    QTableWidget *xrefs_to_ = nullptr;
    QTableWidget *xrefs_from_ = nullptr;
};
