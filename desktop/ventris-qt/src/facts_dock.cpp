#include "facts_dock.h"

#include "core_bridge.h"
#include "json_util.h"
#include "strings_table_model.h"

#include <QHeaderView>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>

FactsDock::FactsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Symbols / strings / search"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("factsDock"));

    auto *facts_tabs = new QTabWidget(this);

    symbols_ = new QTableWidget(0, 4, facts_tabs);
    symbols_->setHorizontalHeaderLabels(
        {QStringLiteral("Address"), QStringLiteral("Name"), QStringLiteral("Source"),
         QStringLiteral("External")});
    symbols_->horizontalHeader()->setStretchLastSection(true);
    symbols_->verticalHeader()->setVisible(false);
    symbols_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(symbols_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
        if (auto *first = symbols_->item(item->row(), 0)) {
            emit addressDoubleClicked(first->text());
        }
    });

    strings_model_ = new StringsTableModel(bridge_, facts_tabs);
    strings_ = new QTableView(facts_tabs);
    strings_->setObjectName(QStringLiteral("stringsView"));
    strings_->setModel(strings_model_);
    strings_->setSelectionBehavior(QAbstractItemView::SelectRows);
    strings_->setSelectionMode(QAbstractItemView::SingleSelection);
    strings_->horizontalHeader()->setStretchLastSection(true);
    strings_->verticalHeader()->setVisible(false);

    connect(strings_, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
        const QString address =
            strings_model_->data(strings_model_->index(index.row(), 0)).toString();
        emit addressDoubleClicked(address);
    });
    connect(strings_, &QTableView::clicked, this, [this](const QModelIndex &index) {
        const QString address =
            strings_model_->data(strings_model_->index(index.row(), 0)).toString();
        emit addressSelected(address, false);
    });
    connect(strings_model_, &StringsTableModel::requestError, this,
            [this](const QString &message) { emit statusRequested(message, true); });

    search_results_ = new QTableWidget(0, 4, facts_tabs);
    search_results_->setHorizontalHeaderLabels(
        {QStringLiteral("Address"), QStringLiteral("Kind"), QStringLiteral("Name"),
         QStringLiteral("Context")});
    search_results_->horizontalHeader()->setStretchLastSection(true);
    search_results_->verticalHeader()->setVisible(false);
    search_results_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(search_results_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
        if (auto *first = search_results_->item(item->row(), 0)) {
            emit addressDoubleClicked(first->text());
        }
    });

    facts_tabs->addTab(symbols_, QStringLiteral("Symbols"));
    facts_tabs->addTab(strings_, QStringLiteral("Strings"));
    facts_tabs->addTab(search_results_, QStringLiteral("Search"));
    setWidget(facts_tabs);
}

void FactsDock::loadFacts(const QString &program, const QString &search_term) {
    if (program.isEmpty()) {
        return;
    }
    strings_model_->setProgram(program);

    bridge_->request(QJsonObject{{"method", "symbols_page"},
                                 {"program", program},
                                 {"offset", 0},
                                 {"limit", 256}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit statusRequested(error, true);
                             return;
                         }
                         const QJsonArray rows =
                             response.value("result").toObject().value("rows").toArray();
                         symbols_->setRowCount(0);
                         for (const QJsonValue &value : rows) {
                             const QJsonObject row = value.toObject();
                             const int index = symbols_->rowCount();
                             symbols_->insertRow(index);
                             symbols_->setItem(index, 0,
                                               new QTableWidgetItem(addressText(row.value("address"))));
                             symbols_->setItem(index, 1,
                                               new QTableWidgetItem(row.value("name").toString()));
                             symbols_->setItem(index, 2,
                                               new QTableWidgetItem(row.value("source").toString()));
                             symbols_->setItem(index, 3,
                                               new QTableWidgetItem(
                                                   row.value("external").toBool() ? "yes" : "no"));
                         }
                     });

    if (!search_term.trimmed().isEmpty()) {
        bridge_->request(QJsonObject{{"method", "search"},
                                     {"program", program},
                                     {"term", search_term},
                                     {"limit", 256}},
                         [this](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 emit statusRequested(error, true);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             search_results_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = search_results_->rowCount();
                                 search_results_->insertRow(index);
                                 search_results_->setItem(index, 0,
                                                   new QTableWidgetItem(addressText(row.value("address"))));
                                 search_results_->setItem(index, 1,
                                                   new QTableWidgetItem(row.value("kind").toString()));
                                 search_results_->setItem(index, 2,
                                                   new QTableWidgetItem(row.value("name").toString()));
                                 search_results_->setItem(index, 3,
                                                   new QTableWidgetItem(row.value("context").toString()));
                             }
                         });
    }
}
