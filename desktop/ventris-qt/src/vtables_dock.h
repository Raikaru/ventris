#pragma once

#include <QDockWidget>

class CoreBridge;
class QTableWidget;

class VtablesDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit VtablesDock(CoreBridge *bridge, QWidget *parent = nullptr);

    void recoverVtables(const QString &binary);

signals:
    void addressDoubleClicked(const QString &address);
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);

private:
    CoreBridge *bridge_;
    QTableWidget *vtables_ = nullptr;
};
