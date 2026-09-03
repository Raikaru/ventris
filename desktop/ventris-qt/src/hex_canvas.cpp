#include "hex_canvas.h"

#include "theme.h"

#include <QFontDatabase>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>

namespace {

constexpr int kMargin = 8;
constexpr int kBytesPerRow = 16;

}  // namespace

HexCanvas::HexCanvas(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(140);
    setFocusPolicy(Qt::StrongFocus);
    setFocus();
}

void HexCanvas::setWindow(quint64 base_offset, const QByteArray &bytes) {
    base_offset_ = base_offset;
    bytes_ = bytes;
    cursor_ = qBound(0, cursor_, qMax(0, bytes_.size() / kBytesPerRow - 1));
    update();
}

void HexCanvas::setAddress(const QString &address) {
    bool ok = false;
    const quint64 target = address.toULongLong(&ok, 16);
    if (!ok) {
        return;
    }
    const quint64 last = base_offset_ + static_cast<quint64>(bytes_.size());
    if (target >= base_offset_ && target < last) {
        cursor_ = static_cast<int>((target - base_offset_) / kBytesPerRow);
        update();
        return;
    }
    // Outside the window: ask for a window around the address (aligned).
    emit windowNeeded(target);
}

void HexCanvas::setRegions(const QVector<MemoryRegionView> &regions) {
    regions_ = regions;
    region_low_ = 0;
    region_high_ = 0;
    for (const MemoryRegionView &region : regions) {
        const quint64 end = region.start_offset + region.size;
        if (region_low_ == 0 || region.start_offset < region_low_) {
            region_low_ = region.start_offset;
        }
        if (end > region_high_) {
            region_high_ = end;
        }
    }
    update();
}

QSize HexCanvas::sizeHint() const { return {640, 220}; }

int HexCanvas::rowHeight() const {
    QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    return metrics.lineSpacing();
}

int HexCanvas::visibleRows() const {
    return qMax(0, (height() - 2 * kMargin) / rowHeight());
}

int HexCanvas::cursorRow() const { return cursor_; }

QString HexCanvas::addressAtRow(int row) const {
    const quint64 offset = base_offset_ + static_cast<quint64>(row) * kBytesPerRow;
    return QStringLiteral("0x%1").arg(offset, 0, 16);
}

/// Pointer detection: the little-endian qword at (row, column) is a
/// pointer when it lands inside any mapped region.
QString HexCanvas::pointerAt(int row, int byte_column) const {
    const int base = row * kBytesPerRow + byte_column;
    if (byte_column + 8 > kBytesPerRow || base + 8 > bytes_.size()) {
        return {};
    }
    quint64 value = 0;
    for (int i = 7; i >= 0; --i) {
        value = (value << 8) | static_cast<quint8>(bytes_.at(base + i));
    }
    if (value < region_low_ || value >= region_high_) {
        return {};
    }
    for (const MemoryRegionView &region : regions_) {
        if (value >= region.start_offset && value < region.start_offset + region.size) {
            return QStringLiteral("0x%1").arg(value, 0, 16);
        }
    }
    return {};
}

void HexCanvas::moveCursor(int delta, bool record) {
    const int rows = qMax(1, bytes_.size() / kBytesPerRow);
    const int target = qBound(0, cursor_ + delta, rows - 1);
    if (target == cursor_) {
        return;
    }
    cursor_ = target;
    ensureWindowAround(cursor_);
    emit addressSelected(addressAtRow(cursor_), record);
    update();
}

void HexCanvas::ensureWindowAround(int row) {
    const int rows = qMax(1, bytes_.size() / kBytesPerRow);
    const int visible = visibleRows();
    if (row < visible || row > rows - visible) {
        emit windowNeeded(base_offset_ + static_cast<quint64>(row) * kBytesPerRow);
    }
}

void HexCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), Theme::current().background);
    painter.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const QFontMetrics metrics = painter.fontMetrics();
    const int line = qMax(1, metrics.lineSpacing());
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    const int visible = visibleRows();
    const int rows = bytes_.size() / kBytesPerRow;

    if (bytes_.isEmpty()) {
        painter.setPen(Theme::current().empty_text);
        painter.drawText(kMargin, kMargin + metrics.ascent(),
                         QStringLiteral("No bytes loaded"));
        return;
    }

    for (int r = 0; r < visible; ++r) {
        const int row = cursor_ - visible / 2 + r;
        if (row < 0 || row >= rows) {
            continue;
        }
        const int y = kMargin + r * line + metrics.ascent();
        if (row == cursor_) {
            painter.fillRect(QRect(0, y - metrics.ascent(), width(), line), Theme::current().cursor_line);
        }
        int x = kMargin;
        painter.setPen(Theme::current().offset_column);
        const quint64 offset = base_offset_ + static_cast<quint64>(row) * kBytesPerRow;
        painter.drawText(x, y, QStringLiteral("0x%1").arg(offset, 8, 16, QLatin1Char('0')));
        x += 12 * char_w;
        // Hex columns; pointer qwords render in the pointer color.
        for (int c = 0; c < kBytesPerRow; ++c) {
            const int index = row * kBytesPerRow + c;
            if (index >= bytes_.size()) {
                break;
            }
            const bool pointer = (c % 8 == 0) && !pointerAt(row, c).isEmpty();
            painter.setPen(pointer ? Theme::current().pointer : Theme::current().hex_text);
            painter.drawText(x, y,
                             QStringLiteral("%1").arg(static_cast<quint8>(bytes_.at(index)),
                                                      2, 16, QLatin1Char('0')));
            x += 3 * char_w;
            if (c == 7) {
                x += char_w;  // gap between qwords
            }
        }
        x += char_w;
        painter.setPen(Theme::current().ascii_text);
        QString ascii;
        for (int c = 0; c < kBytesPerRow; ++c) {
            const int index = row * kBytesPerRow + c;
            if (index >= bytes_.size()) {
                break;
            }
            const char ch = bytes_.at(index);
            ascii += (ch >= 0x20 && ch < 0x7f) ? QChar(ch) : QChar(QLatin1Char('.'));
        }
        painter.drawText(x, y, ascii);
    }
}

void HexCanvas::wheelEvent(QWheelEvent *event) {
    const int delta = event->angleDelta().y();
    moveCursor(delta > 0 ? -3 : 3, false);
    event->accept();
}

void HexCanvas::keyPressEvent(QKeyEvent *event) {
    switch (event->key()) {
    case Qt::Key_Up:
        moveCursor(-1, true);
        break;
    case Qt::Key_Down:
        moveCursor(1, true);
        break;
    case Qt::Key_PageUp:
        moveCursor(-visibleRows(), true);
        break;
    case Qt::Key_PageDown:
        moveCursor(visibleRows(), true);
        break;
    default:
        QWidget::keyPressEvent(event);
        return;
    }
    event->accept();
}

void HexCanvas::mousePressEvent(QMouseEvent *event) {
    QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const int line = qMax(1, metrics.lineSpacing());
    const int r = cursor_ - visibleRows() / 2 + (event->position().y() - kMargin) / line;
    const int rows = bytes_.size() / kBytesPerRow;
    if (r < 0 || r >= rows) {
        return;
    }
    cursor_ = r;
    // Pointer clicks jump; plain clicks select the row address.
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    const int hex_x = kMargin + 12 * char_w;
    const int col = static_cast<int>(event->position().x() - hex_x) / (3 * char_w);
    if (col >= 0 && col < kBytesPerRow) {
        const QString pointer = pointerAt(r, col);
        if (!pointer.isEmpty()) {
            emit addressSelected(pointer, true);
            update();
            event->accept();
            return;
        }
    }
    emit addressSelected(addressAtRow(r), true);
    update();
    event->accept();
}
