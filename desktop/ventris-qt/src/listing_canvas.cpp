#include "listing_canvas.h"

#include <QContextMenuEvent>
#include "theme.h"

#include <QFontDatabase>
#include <QKeyEvent>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>

namespace {

constexpr int kMargin = 8;
constexpr int kAddressWidth = 14;   // characters
constexpr int kBytesWidth = 32;     // characters, 16 bytes

/// Returns the hex token of `text` spanning character column `column`,
/// or empty when the click is not on an address-like token.
QString hexTokenAtColumn(const QString &text, int column) {
    if (column < 0 || column >= text.size()) {
        return {};
    }
    auto isHexChar = [](QChar c) {
        return c.isDigit() || (c >= QLatin1Char('a') && c <= QLatin1Char('f')) ||
               (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
    };
    int begin = column;
    while (begin > 0 && isHexChar(text[begin - 1])) {
        --begin;
    }
    int end = column;
    while (end < text.size() && isHexChar(text[end])) {
        ++end;
    }
    const QString token = text.mid(begin, end - begin);
    bool ok = false;
    token.toULongLong(&ok, 16);
    return ok ? token : QString();
}

bool isSelectableRow(const ListingRowView &row) {
    return row.kind == QStringLiteral("instruction") ||
           row.kind == QStringLiteral("data") ||
           row.kind == QStringLiteral("label");
}

}  // namespace

ListingCanvas::ListingCanvas(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(180);
    setFocusPolicy(Qt::StrongFocus);
    setFocus();
}

void ListingCanvas::setWindow(const QVector<ListingRowView> &rows) {
    rows_ = rows;
    update();
}

void ListingCanvas::setAddress(const QString &address) {
    if (address.isEmpty()) {
        return;
    }
    // Structural rows share the address of their first instruction. Prefer
    // the instruction so navigation never lands on a non-code marker.
    for (int pass = 0; pass < 2; ++pass) {
        for (int i = 0; i < rows_.size(); ++i) {
            const ListingRowView &row = rows_.at(i);
            if (row.address == address &&
                (pass == 1 || row.kind == QStringLiteral("instruction"))) {
                cursor_ = i;
                update();
                return;
            }
        }
    }
    // Not in this window: ask for a window anchored at the address. The
    // owner refetches and calls setWindow + setAddress; when the address
    // is genuinely unmapped the next setAddress stops here (cursor -1).
    const QString window_start = rows_.isEmpty() ? QString() : rows_.first().address;
    cursor_ = -1;
    if (address != window_start) {
        emit windowNeeded(address);
    } else {
        update();
    }
}

QString ListingCanvas::currentAddress() const {
    return cursorIndex() >= 0 ? addressAt(cursorIndex()) : QString();
}

void ListingCanvas::setBytesVisible(bool on) {
    bytes_visible_ = on;
    update();
}

bool ListingCanvas::bytesVisible() const { return bytes_visible_; }

QSize ListingCanvas::sizeHint() const { return {640, 260}; }

int ListingCanvas::rowHeight() const {
    QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    return metrics.lineSpacing();
}

int ListingCanvas::visibleRows() const {
    return qMax(0, (height() - 2 * kMargin) / rowHeight());
}

int ListingCanvas::cursorIndex() const { return cursor_; }

QString ListingCanvas::addressAt(int row) const {
    return row >= 0 && row < rows_.size() ? rows_.at(row).address : QString();
}

void ListingCanvas::moveCursor(int delta, bool record) {
    if (rows_.isEmpty() || delta == 0) {
        return;
    }
    const int direction = delta < 0 ? -1 : 1;
    int remaining = delta < 0 ? -delta : delta;
    int target = cursor_;
    if (target < 0) {
        target = direction > 0 ? -1 : rows_.size();
    }
    while (remaining-- > 0) {
        do {
            target += direction;
        } while (target >= 0 && target < rows_.size() &&
                 !isSelectableRow(rows_.at(target)));
    }
    if (target < 0 || target >= rows_.size()) {
        return;
    }
    if (target == cursor_) {
        return;
    }
    cursor_ = target;
    ensureWindowAround(cursor_);
    emit addressSelected(addressAt(cursor_), record);
    update();
}

void ListingCanvas::ensureWindowAround(int index) {
    const int visible = visibleRows();
    // Refetch when the cursor enters one visible-page of either edge.
    if (index < visible || index > rows_.size() - visible) {
        if (!rows_.isEmpty()) {
            emit windowNeeded(addressAt(index));
        }
    }
}

void ListingCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), Theme::current().background);
    painter.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const QFontMetrics metrics = painter.fontMetrics();
    const int line = rowHeight();
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    const int first = qMax(0, cursorIndex() - qMax(0, (visibleRows() - 1) / 2));
    int y = kMargin + metrics.ascent();
    for (int i = first; i < rows_.size() && i < first + visibleRows(); ++i, y += line) {
        const ListingRowView &row = rows_.at(i);
        if (i == cursorIndex()) {
            painter.fillRect(QRect(0, y - metrics.ascent(), width(), line), Theme::current().cursor_line);
        }
        if (row.kind == QStringLiteral("function_header")) {
            painter.setPen(Theme::current().function_name);
            painter.drawText(kMargin, y,
                             QStringLiteral("Function %1 @ %2").arg(row.text, row.address));
            continue;
        }
        if (row.kind == QStringLiteral("bb_separator")) {
            painter.setPen(Theme::current().empty_text);
            painter.drawText(kMargin, y,
                             QStringLiteral("---- basic block %1 ----").arg(row.address));
            continue;
        }
        int x = kMargin;
        painter.setPen(Theme::current().address_column);
        painter.drawText(x, y, row.address.leftJustified(kAddressWidth, QLatin1Char(' ')));
        x += kAddressWidth * char_w + 8;
        if (bytes_visible_) {
            painter.setPen(Theme::current().bytes_column);
            painter.drawText(x, y, row.bytes.leftJustified(kBytesWidth, QLatin1Char(' ')));
            x += (kBytesWidth + 2) * char_w;
        }
        // Syntax coloring: mnemonic vs operands, jump targets highlighted.
        if (row.kind == QStringLiteral("label")) {
            painter.setPen(Theme::current().jump_target);
            painter.drawText(x, y, row.text + QLatin1Char(':'));
            continue;
        }
        if (row.kind == QStringLiteral("data")) {
            painter.setPen(Theme::current().bytes_column);
            painter.drawText(x, y, row.text);
            continue;
        }
        const QString text = row.text;
        const int mnemonic_end = text.indexOf(QLatin1Char(' '));
        painter.setPen(Theme::current().mnemonic);
        painter.drawText(x, y, mnemonic_end < 0 ? text : text.left(mnemonic_end));
        if (mnemonic_end >= 0) {
            const QString operands = text.mid(mnemonic_end);
            int ox = x + (mnemonic_end + 1) * char_w;
            int token_begin = 0;
            for (int c = 0; c <= operands.size(); ++c) {
                const bool token_end = c == operands.size() || operands[c].isSpace();
                if (!token_end) {
                    continue;
                }
                const QString token = operands.mid(token_begin, c - token_begin);
                bool is_hex = false;
                token.toULongLong(&is_hex, 16);
                painter.setPen(token.startsWith(QStringLiteral("0x")) && is_hex
                                   ? Theme::current().jump_target
                                   : Theme::current().operands);
                painter.drawText(ox, y, token);
                ox += (token.size() + 1) * char_w;
                token_begin = c + 1;
            }
        }
    }
    if (rows_.isEmpty()) {
        painter.setPen(Theme::current().empty_text);
        painter.drawText(kMargin, y, QStringLiteral("No listing loaded"));
    }
}

void ListingCanvas::wheelEvent(QWheelEvent *event) {
    const int delta = event->angleDelta().y();
    moveCursor(delta > 0 ? -3 : 3, false);
    event->accept();
}

void ListingCanvas::keyPressEvent(QKeyEvent *event) {
    const int page = qMax(1, visibleRows() - 1);
    switch (event->key()) {
    case Qt::Key_Up:
        moveCursor(-1, true);
        break;
    case Qt::Key_Down:
        moveCursor(1, true);
        break;
    case Qt::Key_PageUp:
        moveCursor(-page, true);
        break;
    case Qt::Key_PageDown:
        moveCursor(page, true);
        break;
    case Qt::Key_Home:
        moveCursor(-rows_.size(), true);
        break;
    case Qt::Key_End:
        moveCursor(rows_.size(), true);
        break;
    case Qt::Key_Escape:
        emit backRequested();
        break;
    case Qt::Key_BracketLeft:
        if (event->modifiers() & Qt::ControlModifier) {
            emit backRequested();
        }
        break;
    case Qt::Key_BracketRight:
        if (event->modifiers() & Qt::ControlModifier) {
            emit forwardRequested();
        }
        break;
    default:
        QWidget::keyPressEvent(event);
        return;
    }
    event->accept();
}

void ListingCanvas::mousePressEvent(QMouseEvent *event) {
    const int line = rowHeight();
    const int first = qMax(0, cursorIndex() - qMax(0, (visibleRows() - 1) / 2));
    const int row = first + (event->position().y() - kMargin) / line;
    if (row < 0 || row >= rows_.size()) {
        return;
    }
    cursor_ = row;
    const ListingRowView &view = rows_.at(row);
    // Operand clicks jump; plain row clicks select.
    const QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    int text_x = kMargin + kAddressWidth * char_w + 8;
    if (bytes_visible_) {
        text_x += (kBytesWidth + 2) * char_w;
    }
    const QString token =
        hexTokenAtColumn(view.text, (event->position().x() - text_x) / char_w);
    if (!token.isEmpty()) {
        emit addressSelected(token, true);
    } else {
        emit addressSelected(view.address, true);
    }
    update();
    event->accept();
}

void ListingCanvas::mouseDoubleClickEvent(QMouseEvent *event) {
    // Double-click follows the row address (single click already selects).
    const int line = rowHeight();
    const int first = qMax(0, cursorIndex() - qMax(0, (visibleRows() - 1) / 2));
    const int row = first + (event->position().y() - kMargin) / line;
    if (row >= 0 && row < rows_.size()) {
        emit addressSelected(rows_.at(row).address, true);
    }
    event->accept();
}

void ListingCanvas::contextMenuEvent(QContextMenuEvent *event) {
    const int line = rowHeight();
    const int first = qMax(0, cursorIndex() - qMax(0, (visibleRows() - 1) / 2));
    const int row = first + (event->pos().y() - kMargin) / line;
    if (row < 0 || row >= rows_.size()) {
        return;
    }
    cursor_ = row;
    update();
    emit contextMenuRequested(event->globalPos(), addressAt(row));
}
