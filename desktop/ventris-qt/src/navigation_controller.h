#pragma once

#include <QObject>
#include <QString>
#include <QStringList>

/// Single owner of navigation state: current program, current address, and
/// the back/forward history stack. Every dock subscribes to addressChanged;
/// no dock talks to another dock directly.
class NavigationController final : public QObject {
    Q_OBJECT

public:
    explicit NavigationController(QObject *parent = nullptr);

    void setProgram(const QString &program);
    QString program() const;

    /// Jumps to an address. When record is false (back/forward traversal)
    /// the history stack is left untouched; recording truncates the
    /// forward branch and appends, collapsing consecutive duplicates.
    void goTo(const QString &address, bool record = true);

    QString address() const;
    bool canGoBack() const;
    bool canGoForward() const;

signals:
    void programChanged(const QString &program);
    void addressChanged(const QString &address);
    void historyChanged(bool canBack, bool canForward);

public slots:
    void back();
    void forward();

private:
    QString program_;
    QString address_;
    QStringList history_;
    int history_index_ = -1;
};
