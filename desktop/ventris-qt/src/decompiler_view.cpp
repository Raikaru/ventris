#include "decompiler_view.h"

#include <QFontDatabase>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>

namespace {

constexpr int kMargin = 8;
const QColor kBackground("#101419");
const QColor kDefaultText("#d6dee8");
const QColor kVariable("#e5c07b");
const QColor kFunctionName("#61afef");
const QColor kOperator("#56b6c2");
const QColor kKeyword("#c678dd");
const QColor kHighlight("#3a4a5a");
const QColor kCursorLine("#2a3542");
const QColor kEmptyText("#7e8996");

QColor colorForKind(const QString &kind) {
    if (kind == QStringLiteral("Variable")) {
        return kVariable;
    }
    if (kind == QStringLiteral("FuncName")) {
        return kFunctionName;
    }
    if (kind == QStringLiteral("Operator") || kind == QStringLiteral("Syntax")) {
        return kOperator;
    }
    if (kind == QStringLiteral("Keyword") || kind == QStringLiteral("Type")) {
        return kKeyword;
    }
    return kDefaultText;
}

}  // namespace

DecompilerView::DecompilerView(QWidget *parent) : QWidget(parent) {
    setObjectName(QStringLiteral("decompilerView"));
    setFocusPolicy(Qt::StrongFocus);
    setFocus();
}

void DecompilerView::setTokens(const QVector<TokenView> &tokens) {
    lines_.clear();
    Line current;
    for (const TokenView &token : tokens) {
        if (token.isBreak()) {
            if (!current.tokens.isEmpty()) {
                lines_.append(current);
            }
            current = Line{};
            current.indent = token.indent;
            continue;
        }
        current.tokens.append(token);
    }
    if (!current.tokens.isEmpty()) {
        lines_.append(current);
    }
    cursor_line_ = lines_.isEmpty() ? -1 : 0;
    scroll_line_ = 0;
    highlight_address_.clear();
    highlight_symbol_.clear();
    pending_message_.clear();
    update();
}

void DecompilerView::setAddress(const QString &address) {
    highlight_address_ = address;
    update();
}

void DecompilerView::setPending(const QString &message) {
    pending_message_ = message;
    update();
}

QString DecompilerView::currentAddress() const {
    if (cursor_line_ < 0 || cursor_line_ >= lines_.size()) {
        return {};
    }
    for (const TokenView &token : lines_.at(cursor_line_).tokens) {
        if (!token.address.isEmpty()) {
            return token.address;
        }
    }
    return {};
}

QSize DecompilerView::sizeHint() const { return {640, 260}; }

int DecompilerView::lineAt(int y) const {
    QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    return scroll_line_ + (y - kMargin) / qMax(1, metrics.lineSpacing());
}

void DecompilerView::moveCursor(int delta) {
    if (lines_.isEmpty()) {
        return;
    }
    const int target = qBound(0, cursor_line_ + delta, lines_.size() - 1);
    if (target == cursor_line_) {
        return;
    }
    cursor_line_ = target;
    QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const int visible = qMax(1, (height() - 2 * kMargin) / metrics.lineSpacing());
    if (cursor_line_ < scroll_line_) {
        scroll_line_ = cursor_line_;
    } else if (cursor_line_ >= scroll_line_ + visible) {
        scroll_line_ = cursor_line_ - visible + 1;
    }
    const QString address = currentAddress();
    if (!address.isEmpty()) {
        emit addressSelected(address, false);
    }
    update();
}

const TokenView *DecompilerView::tokenAt(const QPoint &pos,
                                                         int *line_index) const {
    const int line = lineAt(pos.y());
    if (line < 0 || line >= lines_.size()) {
        return nullptr;
    }
    QFontMetrics metrics(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    int x = kMargin + static_cast<int>(lines_.at(line).indent) * char_w;
    for (const TokenView &token : lines_.at(line).tokens) {
        const int width = token.text.size() * char_w;
        if (pos.x() >= x && pos.x() < x + width) {
            if (line_index != nullptr) {
                *line_index = line;
            }
            return &token;
        }
        x += width;
    }
    return nullptr;
}

void DecompilerView::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), kBackground);
    painter.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    const QFontMetrics metrics = painter.fontMetrics();
    const int line_height = qMax(1, metrics.lineSpacing());
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    const int visible = qMax(1, (height() - 2 * kMargin) / line_height);

    if (lines_.isEmpty()) {
        painter.setPen(kEmptyText);
        painter.drawText(kMargin, kMargin + metrics.ascent(),
                         pending_message_.isEmpty()
                             ? QStringLiteral("No decompilation loaded")
                             : pending_message_);
        return;
    }

    for (int i = scroll_line_; i < lines_.size() && i < scroll_line_ + visible; ++i) {
        const Line &line = lines_.at(i);
        const int y = kMargin + (i - scroll_line_) * line_height + metrics.ascent();
        bool line_highlighted = false;
        if (i == cursor_line_) {
            painter.fillRect(QRect(0, y - metrics.ascent(), width(), line_height),
                             kCursorLine);
        }
        int x = kMargin + static_cast<int>(line.indent) * char_w;
        for (const TokenView &token : line.tokens) {
            if (!highlight_address_.isEmpty() && token.address == highlight_address_) {
                painter.fillRect(QRect(x, y - metrics.ascent(),
                                       qMax(1, token.text.size() * char_w), line_height),
                                 kHighlight);
                line_highlighted = true;
            }
            painter.setPen(colorForKind(token.kind));
            painter.drawText(x, y, token.text);
            x += token.text.size() * char_w;
        }
        if (!line_highlighted && !highlight_symbol_.isEmpty()) {
            // Occurrence highlighting: lines holding the selected symbol.
            for (const TokenView &token : line.tokens) {
                if (token.kind == QStringLiteral("Variable") &&
                    token.text == highlight_symbol_) {
                    painter.fillRect(QRect(0, y - metrics.ascent(), width(), line_height),
                                     kHighlight);
                    break;
                }
            }
        }
    }
}

void DecompilerView::keyPressEvent(QKeyEvent *event) {
    switch (event->key()) {
    case Qt::Key_Up:
        moveCursor(-1);
        break;
    case Qt::Key_Down:
        moveCursor(1);
        break;
    case Qt::Key_PageUp:
        moveCursor(-10);
        break;
    case Qt::Key_PageDown:
        moveCursor(10);
        break;
    default:
        QWidget::keyPressEvent(event);
        return;
    }
    event->accept();
}

void DecompilerView::mousePressEvent(QMouseEvent *event) {
    int line_index = -1;
    const TokenView *token = tokenAt(event->pos(), &line_index);
    if (token == nullptr) {
        return;
    }
    cursor_line_ = line_index;
    if (!token->address.isEmpty()) {
        highlight_address_ = token->address;
        highlight_symbol_.clear();
        emit addressSelected(token->address, true);
    } else if (token->kind == QStringLiteral("Variable")) {
        // Occurrence highlight for variables (no address of their own).
        highlight_symbol_ = token->text;
        highlight_address_.clear();
    }
    update();
    event->accept();
}

void DecompilerView::mouseDoubleClickEvent(QMouseEvent *event) {
    int line_index = -1;
    const TokenView *token = tokenAt(event->pos(), &line_index);
    if (token == nullptr) {
        return;
    }
    // Function-name tokens rename through the command journal. Variable
    // rename needs worker-side support and is never emitted here.
    if (token->kind == QStringLiteral("FuncName") && !token->address.isEmpty()) {
        emit renameRequested(token->address, token->text);
    }
    event->accept();
}

void DecompilerView::wheelEvent(QWheelEvent *event) {
    const int delta = event->angleDelta().y();
    scroll_line_ = qBound(0, scroll_line_ + (delta > 0 ? -3 : 3),
                          qMax(0, lines_.size() - 1));
    update();
    event->accept();
}
