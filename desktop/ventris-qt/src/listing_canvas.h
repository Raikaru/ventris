#pragma once

#include <QJsonArray>
#include <QWidget>

/// Paint-based listing view. Rows come from the core "listing" request;
/// scrolling is row-based. Selection, stable row ids, and scrollbar
/// integration arrive with the listing-window work in Phase 1.
class ListingCanvas final : public QWidget {
    Q_OBJECT

public:
    explicit ListingCanvas(QWidget *parent = nullptr);

    void setRows(const QJsonArray &rows);

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent *) override;
    void wheelEvent(QWheelEvent *event) override;

private:
    QJsonArray rows_;
    int top_row_ = 0;
};
