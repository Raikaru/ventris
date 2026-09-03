#pragma once

#include <QDockWidget>
#include <QSet>

class CoreBridge;
class QLabel;
class QListWidget;

class JobsDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit JobsDock(CoreBridge *bridge, QWidget *parent = nullptr);

    int beginJob(const QString &label);
    void finishJob(int index, bool ok, const QString &detail);
    void refreshJobs();
    void cancelJob();

signals:
    void statusRequested(const QString &message, bool error);

private:
    CoreBridge *bridge_;
    QLabel *jobs_summary_ = nullptr;
    QListWidget *jobs_ = nullptr;
    QSet<int> cancelled_jobs_;
};
