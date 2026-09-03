#include "xrefs_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QHeaderView>
#include <QTabWidget>
#include <QTableWidget>

XrefsDock::XrefsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Xrefs"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("xrefsDock"));

    auto *tabs = new QTabWidget(this);
    auto make_xrefs_table = [this](QTabWidget *parent_widget, const QString &object_name) {
        auto *table = new QTableWidget(0, 4, parent_widget);
        table->setObjectName(object_name);
        table->setHorizontalHeaderLabels({QStringLiteral("Address"),
                                          QStringLiteral("Function"),
                                          QStringLiteral("Kind"),
                                          QStringLiteral("Target")});
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->setVisible(false);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(table, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
            const QString addr = item->text().split(QLatin1Char(' ')).first();
            if (!addr.isEmpty()) {
                emit addressDoubleClicked(addr);
            }
        });
        return table;
    };
    xrefs_to_ = make_xrefs_table(tabs, QStringLiteral("xrefsToView"));
    xrefs_from_ = make_xrefs_table(tabs, QStringLiteral("xrefsFromView"));
    tabs->addTab(xrefs_to_, QStringLiteral("To"));
    tabs->addTab(xrefs_from_, QStringLiteral("From"));
    setWidget(tabs);
}

void XrefsDock::loadXrefs(const QString &program, const QString &address) {
    if (program.isEmpty() || address.isEmpty()) {
        return;
    }
    auto fill = [this, program, address](QTableWidget *table, bool incoming) {
        const QString job_name = QStringLiteral("xrefs %1 %2")
                                     .arg(incoming ? QStringLiteral("to")
                                                   : QStringLiteral("from"))
                                     .arg(address);
        emit jobStarted(job_name);
        bridge_->request(QJsonObject{{"method", "xrefs_page"},
                                     {"program", program},
                                     {"address", address},
                                     {"incoming", incoming},
                                     {"offset", 0},
                                     {"limit", 256}},
                         [this, job_name, table](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 emit jobFinished(job_name, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result")
                                                         .toObject()
                                                         .value("rows")
                                                         .toArray();
                             table->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = table->rowCount();
                                 table->insertRow(index);
                                 const QString from = addressText(row.value("from"));
                                 const QString to = addressText(row.value("to"));
                                 const QString function = row.value("function").toString();
                                 table->setItem(index, 0, new QTableWidgetItem(from));
                                 table->setItem(index, 1,
                                                new QTableWidgetItem(function.isEmpty()
                                                                         ? QStringLiteral("—")
                                                                         : function));
                                 table->setItem(index, 2,
                                                new QTableWidgetItem(
                                                    row.value("kind").toString()));
                                 table->setItem(index, 3, new QTableWidgetItem(to));
                             }
                             emit jobFinished(job_name, true,
                                              QStringLiteral("%1 xrefs").arg(rows.size()));
                         });
    };
    fill(xrefs_to_, true);
    fill(xrefs_from_, false);
}
