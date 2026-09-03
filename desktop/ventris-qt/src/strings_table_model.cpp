#include "strings_table_model.h"

#include "core_bridge.h"
#include "json_util.h"

StringsTableModel::StringsTableModel(CoreBridge *bridge, QObject *parent)
    : QAbstractTableModel(parent), bridge_(bridge) {}

int StringsTableModel::rowCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0 : rows_.size();
}

int StringsTableModel::columnCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0 : 3;
}

QVariant StringsTableModel::headerData(int section, Qt::Orientation orientation,
                                       int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
        return {};
    }
    static const QStringList labels = {QStringLiteral("Address"),
                                       QStringLiteral("Kind"),
                                       QStringLiteral("Value")};
    return labels.value(section);
}

QVariant StringsTableModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size() || role != Qt::DisplayRole) {
        return {};
    }
    const Row &row = rows_.at(index.row());
    switch (index.column()) {
    case 0:
        return row.address;
    case 1:
        return row.kind;
    case 2:
        return row.value;
    default:
        return {};
    }
}

bool StringsTableModel::canFetchMore(const QModelIndex &parent) const {
    return !parent.isValid() && !loading_ && rows_.size() < total_;
}

void StringsTableModel::fetchMore(const QModelIndex &parent) {
    if (!parent.isValid() && canFetchMore(parent)) {
        requestPage(false);
    }
}

void StringsTableModel::setProgram(const QString &program) {
    program_ = program;
    refresh();
}

QString StringsTableModel::program() const { return program_; }

void StringsTableModel::refresh() {
    beginResetModel();
    rows_.clear();
    total_ = 0;
    endResetModel();
    requestPage(true);
}

void StringsTableModel::requestPage(bool reset) {
    if (loading_ || program_.isEmpty()) {
        return;
    }
    loading_ = true;
    const quint64 generation = ++generation_;
    QJsonObject request{{"method", "strings_page"},
                        {"program", program_},
                        {"offset", reset ? 0 : rows_.size()},
                        {"limit", page_size_}};
    bridge_->request(request, [this, generation, reset](const QJsonObject &response) {
        if (generation != generation_) {
            return;
        }
        loading_ = false;
        QString error;
        if (!successful(response, &error)) {
            emit requestError(error);
            return;
        }
        const QJsonObject result = response.value("result").toObject();
        const QJsonArray incoming = result.value("rows").toArray();
        if (reset) {
            beginResetModel();
            rows_.clear();
            for (const QJsonValue &value : incoming) {
                const QJsonObject row = value.toObject();
                rows_.append(Row{addressText(row.value("address")),
                                 row.value("kind").toString(),
                                 row.value("value").toString()});
            }
            endResetModel();
        } else if (!incoming.isEmpty()) {
            const int first = rows_.size();
            beginInsertRows(QModelIndex(), first, first + incoming.size() - 1);
            for (const QJsonValue &value : incoming) {
                const QJsonObject row = value.toObject();
                rows_.append(Row{addressText(row.value("address")),
                                 row.value("kind").toString(),
                                 row.value("value").toString()});
            }
            endInsertRows();
        }
        total_ = result.value("total").toVariant().toLongLong();
    });
}
