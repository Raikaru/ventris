#include "function_table_model.h"

#include "core_bridge.h"
#include "json_util.h"

FunctionTableModel::FunctionTableModel(CoreBridge *bridge, QObject *parent)
    : QAbstractTableModel(parent), bridge_(bridge) {}

int FunctionTableModel::rowCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0 : rows_.size();
}

int FunctionTableModel::columnCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0 : 4;
}

QVariant FunctionTableModel::headerData(int section, Qt::Orientation orientation,
                                        int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
        return {};
    }
    static const QStringList labels = {QStringLiteral("Address"), QStringLiteral("Name"),
                                       QStringLiteral("Size"), QStringLiteral("Signature")};
    return labels.value(section);
}

QVariant FunctionTableModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size() || role != Qt::DisplayRole) {
        return {};
    }
    const FunctionRowView &view = rows_.at(index.row());
    switch (index.column()) {
    case 0:
        return view.address;
    case 1:
        return view.name;
    case 2:
        return view.size;
    case 3:
        return view.signature;
    default:
        return {};
    }
}

bool FunctionTableModel::canFetchMore(const QModelIndex &parent) const {
    return !parent.isValid() && !loading_ && rows_.size() < total_;
}

void FunctionTableModel::fetchMore(const QModelIndex &parent) {
    if (!parent.isValid() && canFetchMore(parent)) {
        requestPage(false);
    }
}

void FunctionTableModel::setProgram(const QString &program) {
    program_ = program;
    refresh();
}

QString FunctionTableModel::program() const { return program_; }
qint64 FunctionTableModel::total() const { return total_; }
qint64 FunctionTableModel::revision() const { return revision_; }

void FunctionTableModel::refresh() {
    beginResetModel();
    rows_.clear();
    total_ = 0;
    revision_ = 0;
    endResetModel();
    requestPage(true);
}

void FunctionTableModel::requestPage(bool reset) {
    if (loading_ || program_.isEmpty()) {
        return;
    }
    loading_ = true;
    const quint64 generation = ++generation_;
    QJsonObject request{{"method", "functions_page"},
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
            for (const QJsonValue &row : incoming) {
                rows_.append(FunctionRowView::fromJson(row.toObject()));
            }
            endResetModel();
        } else if (!incoming.isEmpty()) {
            const int first = rows_.size();
            beginInsertRows(QModelIndex(), first, first + incoming.size() - 1);
            for (const QJsonValue &row : incoming) {
                rows_.append(FunctionRowView::fromJson(row.toObject()));
            }
            endInsertRows();
        }
        total_ = result.value("total").toVariant().toLongLong();
        revision_ = result.value("revision").toVariant().toLongLong();
        emit refreshed();
    });
}
