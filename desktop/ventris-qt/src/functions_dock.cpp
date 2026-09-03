#include "functions_dock.h"

#include "core_bridge.h"
#include "function_table_model.h"

#include <QHeaderView>
#include <QLineEdit>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>

FunctionsDock::FunctionsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Functions"), parent) {
    setObjectName(QStringLiteral("functionsDock"));

    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 0, 0);

    filter_edit_ = new QLineEdit(panel);
    filter_edit_->setObjectName(QStringLiteral("functionFilterEdit"));
    filter_edit_->setPlaceholderText(
        QStringLiteral("Filter (substring, or re: for regex)"));

    filter_timer_ = new QTimer(filter_edit_);
    filter_timer_->setSingleShot(true);
    filter_timer_->setInterval(250);

    connect(filter_edit_, &QLineEdit::textChanged, filter_timer_,
            qOverload<>(&QTimer::start));
    connect(filter_timer_, &QTimer::timeout, this, [this]() {
        model_->setFilter(filter_edit_->text());
    });

    layout->addWidget(filter_edit_);

    table_view_ = new QTableView(panel);
    table_view_->setObjectName(QStringLiteral("functionsView"));
    model_ = new FunctionTableModel(bridge, table_view_);
    table_view_->setModel(model_);

    table_view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_view_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_view_->horizontalHeader()->setStretchLastSection(true);
    table_view_->verticalHeader()->setVisible(false);
    table_view_->setAlternatingRowColors(true);
    table_view_->setSortingEnabled(true);

    connect(table_view_, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
        const QString addr = model_->data(model_->index(index.row(), 0)).toString();
        if (!addr.isEmpty()) {
            emit addressSelected(addr, true);
        }
    });

    layout->addWidget(table_view_, 1);
    setWidget(panel);
}

void FunctionsDock::setProgram(const QString &program) {
    model_->setProgram(program);
}

void FunctionsDock::setFilter(const QString &filter) {
    filter_edit_->setText(filter);
    model_->setFilter(filter);
}
