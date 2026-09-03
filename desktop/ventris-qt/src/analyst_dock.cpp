#include "analyst_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QHeaderView>
#include <QTabWidget>
#include <QTableWidget>

AnalystDock::AnalystDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Analyst data"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("analystDataDock"));

    auto *tabs = new QTabWidget(this);

    bookmarks_ = new QTableWidget(0, 3, tabs);
    bookmarks_->setHorizontalHeaderLabels(
        {QStringLiteral("Address"), QStringLiteral("Label"), QStringLiteral("Comment")});
    bookmarks_->horizontalHeader()->setStretchLastSection(true);
    bookmarks_->verticalHeader()->setVisible(false);
    bookmarks_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(bookmarks_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
        if (auto *addr_item = bookmarks_->item(item->row(), 0)) {
            emit addressDoubleClicked(addr_item->text());
        }
    });

    patches_ = new QTableWidget(0, 4, tabs);
    patches_->setHorizontalHeaderLabels(
        {QStringLiteral("Address"), QStringLiteral("Original"), QStringLiteral("Patched"),
         QStringLiteral("Enabled")});
    patches_->horizontalHeader()->setStretchLastSection(true);
    patches_->verticalHeader()->setVisible(false);
    patches_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(patches_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
        if (auto *addr_item = patches_->item(item->row(), 0)) {
            emit addressDoubleClicked(addr_item->text());
        }
    });

    tabs->addTab(bookmarks_, QStringLiteral("Bookmarks"));
    tabs->addTab(patches_, QStringLiteral("Patches"));
    setWidget(tabs);
}

void AnalystDock::loadAnalystData(const QString &program) {
    if (program.isEmpty()) {
        return;
    }
    emit jobStarted(QStringLiteral("bookmarks"));
    bridge_->request(QJsonObject{{"method", "bookmarks"},
                                 {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("bookmarks"), false, error);
                             return;
                         }
                         const QJsonArray rows = response.value("result").toArray();
                         bookmarks_->setRowCount(0);
                         for (const QJsonValue &value : rows) {
                             const QJsonObject row = value.toObject();
                             const int index = bookmarks_->rowCount();
                             bookmarks_->insertRow(index);
                             bookmarks_->setItem(index, 0,
                                                  new QTableWidgetItem(addressText(row.value("address"))));
                             bookmarks_->setItem(index, 1,
                                                  new QTableWidgetItem(row.value("label").toString()));
                             bookmarks_->setItem(index, 2,
                                                  new QTableWidgetItem(row.value("comment").toString()));
                         }
                         emit jobFinished(QStringLiteral("bookmarks"), true,
                                          QStringLiteral("%1 bookmarks").arg(rows.size()));
                     });

    emit jobStarted(QStringLiteral("patches"));
    bridge_->request(QJsonObject{{"method", "patches"},
                                 {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("patches"), false, error);
                             return;
                         }
                         const QJsonArray rows = response.value("result").toArray();
                         patches_->setRowCount(0);
                         for (const QJsonValue &value : rows) {
                             const QJsonObject row = value.toObject();
                             const int index = patches_->rowCount();
                             patches_->insertRow(index);
                             patches_->setItem(index, 0,
                                               new QTableWidgetItem(addressText(row.value("address"))));
                             patches_->setItem(index, 1,
                                               new QTableWidgetItem(
                                                   bytesText(row.value("original").toArray())));
                             patches_->setItem(index, 2,
                                               new QTableWidgetItem(
                                                   bytesText(row.value("patched").toArray())));
                             patches_->setItem(index, 3,
                                               new QTableWidgetItem(
                                                   row.value("enabled").toBool() ? "yes" : "no"));
                         }
                         emit jobFinished(QStringLiteral("patches"), true,
                                          QStringLiteral("%1 patches").arg(rows.size()));
                     });
}

void AnalystDock::setBookmark(const QString &program, const QString &address,
                              const QString &label, const QString &comment) {
    if (program.isEmpty() || address.isEmpty()) {
        return;
    }
    emit jobStarted(QStringLiteral("set bookmark"));
    bridge_->request(
        QJsonObject{{"method", "set_bookmark"},
                    {"program", program},
                    {"bookmark",
                     QJsonObject{{"address", address},
                                 {"label", label},
                                 {"comment", comment}}}},
        [this, program](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("set bookmark"), false, error);
                return;
            }
            loadAnalystData(program);
            emit jobFinished(QStringLiteral("set bookmark"), true,
                             QStringLiteral("bookmark committed"));
        });
}

void AnalystDock::setPatch(const QString &program, const QString &address,
                           const QString &original_hex, const QString &patched_hex) {
    if (program.isEmpty() || address.isEmpty()) {
        return;
    }
    emit jobStarted(QStringLiteral("set patch"));
    bridge_->request(
        QJsonObject{{"method", "set_patch"},
                    {"program", program},
                    {"address", address},
                    {"original", bytesFromText(original_hex)},
                    {"patched", bytesFromText(patched_hex)},
                    {"enabled", true}},
        [this, program](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("set patch"), false, error);
                return;
            }
            loadAnalystData(program);
            emit jobFinished(QStringLiteral("set patch"), true,
                             QStringLiteral("patch committed"));
        });
}
