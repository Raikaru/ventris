#include "vtables_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QTableWidget>

VtablesDock::VtablesDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Vtables"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("vtablesDock"));

    vtables_ = new QTableWidget(0, 3, this);
    vtables_->setObjectName(QStringLiteral("vtablesView"));
    vtables_->setHorizontalHeaderLabels(
        {QStringLiteral("Address"), QStringLiteral("Entries"), QStringLiteral("Targets")});
    vtables_->horizontalHeader()->setStretchLastSection(true);
    vtables_->verticalHeader()->setVisible(false);
    vtables_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect(vtables_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
        if (auto *first = vtables_->item(item->row(), 0)) {
            emit addressDoubleClicked(first->text());
        }
    });

    setWidget(vtables_);
}

void VtablesDock::recoverVtables(const QString &binary) {
    if (binary.isEmpty()) {
        return;
    }
    emit jobStarted(QStringLiteral("vtable recovery"));
    bridge_->request(
        QJsonObject{{"method", "recover_vtables"},
                    {"binary", binary},
                    {"limit", 512}},
        [this](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("vtable recovery"), false, error);
                return;
            }
            vtables_->setRowCount(0);
            const QJsonArray rows = response.value("result").toArray();
            for (const QJsonValue &value : rows) {
                const QJsonObject row = value.toObject();
                const int index = vtables_->rowCount();
                vtables_->insertRow(index);
                const QStringList targets =
                    row.value("targets").toVariant().toStringList();
                vtables_->setItem(index, 0,
                                  new QTableWidgetItem(QStringLiteral("0x") +
                                                       row.value("address").toString()));
                vtables_->setItem(index, 1,
                                  new QTableWidgetItem(QString::number(targets.size())));
                vtables_->setItem(index, 2,
                                  new QTableWidgetItem(targets.join(QStringLiteral(", "))));
            }
            emit jobFinished(QStringLiteral("vtable recovery"), true,
                             QStringLiteral("%1 vtables recovered").arg(rows.size()));
        });
}
