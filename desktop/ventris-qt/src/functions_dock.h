#pragma once

#include <QDockWidget>

class CoreBridge;
class FunctionTableModel;
class QLineEdit;
class QTableView;
class QTimer;

class FunctionsDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit FunctionsDock(CoreBridge *bridge, QWidget *parent = nullptr);

    FunctionTableModel *model() const { return model_; }
    QTableView *tableView() const { return table_view_; }
    QLineEdit *filterEdit() const { return filter_edit_; }
    QTimer *filterTimer() const { return filter_timer_; }

    void setProgram(const QString &program);
    void setFilter(const QString &filter);

signals:
    void addressSelected(const QString &address, bool record);

private:
    QLineEdit *filter_edit_ = nullptr;
    QTimer *filter_timer_ = nullptr;
    QTableView *table_view_ = nullptr;
    FunctionTableModel *model_ = nullptr;
};
