#include "listing_canvas.h"

#include "json_util.h"

#include <QFontDatabase>
#include <QPainter>
#include <QWheelEvent>

ListingCanvas::ListingCanvas(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(180);
    setFocusPolicy(Qt::StrongFocus);
}

void ListingCanvas::setRows(const QJsonArray &rows) {
    rows_ = rows;
    top_row_ = 0;
    update();
}

QSize ListingCanvas::sizeHint() const { return {640, 260}; }

void ListingCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), QColor("#101419"));
    painter.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const QFontMetrics metrics = painter.fontMetrics();
    const int line_height = metrics.lineSpacing();
    int y = metrics.ascent() + 8;
    const int visible = qMax(0, (height() - 8) / line_height);
    for (int i = 0; i < visible && top_row_ + i < rows_.size(); ++i) {
        const QJsonObject row = rows_.at(top_row_ + i).toObject();
        painter.setPen(QColor("#79b8ff"));
        const QString address = addressText(row.value("address"));
        painter.drawText(8, y, address.leftJustified(14, QLatin1Char(' ')));
        painter.setPen(QColor("#d6dee8"));
        painter.drawText(126, y, row.value("text").toString());
        y += line_height;
    }
    if (rows_.isEmpty()) {
        painter.setPen(QColor("#7e8996"));
        painter.drawText(8, y, QStringLiteral("No listing loaded"));
    }
}

void ListingCanvas::wheelEvent(QWheelEvent *event) {
    const int delta = event->angleDelta().y();
    const int step = delta > 0 ? -3 : 3;
    top_row_ = qBound(0, top_row_ + step, qMax(0, rows_.size() - 1));
    update();
    event->accept();
}
