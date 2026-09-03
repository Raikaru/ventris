#pragma once

#include <QAbstractTableModel>
#include <QVector>

#include "views.h"

class CoreBridge;

/// Paged model over the strings_page core request (Phase 2.3). Rows are
/// fetched in windows as the view scrolls; the full string list is never
/// materialized.
class StringsTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit StringsTableModel(CoreBridge *bridge, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    bool canFetchMore(const QModelIndex &parent) const override;
    void fetchMore(const QModelIndex &parent) override;

    void setProgram(const QString &program);
    QString program() const;
    void refresh();

signals:
    void requestError(const QString &message);

private:
    void requestPage(bool reset);

    CoreBridge *bridge_;
    QString program_;
    struct Row {
        QString address;
        QString kind;
        QString value;
    };
    QVector<Row> rows_;
    qint64 total_ = 0;
    bool loading_ = false;
    quint64 generation_ = 0;
    static constexpr qint64 page_size_ = 256;
};
