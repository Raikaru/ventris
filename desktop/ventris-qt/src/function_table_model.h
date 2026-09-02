#pragma once

#include <QAbstractTableModel>
#include <QJsonArray>

#include <QCoreApplication>

class CoreBridge;

/// Paged model over the functions_page core request. Rows are fetched in
/// windows of page_size_ as the view scrolls; the full function list is
/// never materialized.
class FunctionTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit FunctionTableModel(CoreBridge *bridge, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    bool canFetchMore(const QModelIndex &parent) const override;
    void fetchMore(const QModelIndex &parent) override;

    void setProgram(const QString &program);
    QString program() const;
    qint64 total() const;
    qint64 revision() const;
    void refresh();

signals:
    void requestError(const QString &message);
    void refreshed();

private:
    void requestPage(bool reset);

    CoreBridge *bridge_;
    QString program_;
    QJsonArray rows_;
    qint64 total_ = 0;
    qint64 revision_ = 0;
    bool loading_ = false;
    quint64 generation_ = 0;
    static constexpr qint64 page_size_ = 256;
};
