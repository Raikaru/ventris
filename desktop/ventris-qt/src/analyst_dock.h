#pragma once

#include <QDockWidget>

class CoreBridge;
class QTableWidget;

class AnalystDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit AnalystDock(CoreBridge *bridge, QWidget *parent = nullptr);

    void loadAnalystData(const QString &program);
    void setBookmark(const QString &program, const QString &address,
                     const QString &label, const QString &comment);
    void setPatch(const QString &program, const QString &address,
                  const QString &original_hex, const QString &patched_hex);

signals:
    void addressDoubleClicked(const QString &address);
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);

private:
    CoreBridge *bridge_;
    QTableWidget *bookmarks_ = nullptr;
    QTableWidget *patches_ = nullptr;
};
