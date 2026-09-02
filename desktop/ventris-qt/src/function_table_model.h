#pragma once

#include <QAbstractTableModel>

#include "views.h"
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

    /// Server-side name filter: case-insensitive substring, or regex when
    /// the text carries a `re:` prefix. Empty text clears the filter.
    void setFilter(const QString &filter);
    QString filter() const;

    /// Header-driven sort; column 3 (signature) is not sortable.
    void sort(int column, Qt::SortOrder order) override;

    /// Column 1 (name) is editable in place; the actual rename command is
    /// issued by the window via renameRequested so the undo journal and
    /// job list stay in one place.
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    bool setData(const QModelIndex &index, const QVariant &value,
                 int role = Qt::EditRole) override;

signals:
    void requestError(const QString &message);
    void refreshed();
    void renameRequested(const QString &address, const QString &name);

private:
    void requestPage(bool reset);

    CoreBridge *bridge_;
    QString program_;
    QString filter_;
    int sort_column_ = 0;
    Qt::SortOrder sort_order_ = Qt::AscendingOrder;
    qint64 total_ = 0;
    qint64 revision_ = 0;
    QVector<FunctionRowView> rows_;
    bool loading_ = false;
    quint64 generation_ = 0;
    static constexpr qint64 page_size_ = 256;
};
