#pragma once

#include <QColor>
#include <QPoint>
#include <QVector>
#include <QWidget>

#include "views.h"

class QKeyEvent;
class QMouseEvent;

/// Paint-based decompiler view over the WORKER-004 token stream. Tokens
/// are laid out into lines (Break tokens end a line and indent the next);
/// every token is hit-testable. Navigation and rename requests flow to
/// the window owner through signals.
class DecompilerView final : public QWidget {
    Q_OBJECT

public:
    explicit DecompilerView(QWidget *parent = nullptr);

    /// Lays out a decompiler document.
    void setTokens(const QVector<TokenView> &tokens);
    /// Shown while a decompile request is in flight.
    void setPending(const QString &message);
    /// Reverse sync: highlights every line holding a token at `address`.
    void setAddress(const QString &address);
    QString currentAddress() const;
    QSize sizeHint() const override;

signals:
    void addressSelected(const QString &address, bool record);
    /// Double-click on a function-name token; the owner runs the rename
    /// command (variable rename is engine-gated and never emitted).
    void renameRequested(const QString &address, const QString &current_name);

protected:
    void paintEvent(QPaintEvent *) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseDoubleClickEvent(QMouseEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;

private:
    struct Line {
        QVector<TokenView> tokens;
        quint64 indent = 0;
    };
    int lineAt(int y) const;
    void moveCursor(int delta);
    const TokenView *tokenAt(const QPoint &pos, int *line_index) const;

    QVector<Line> lines_;
    int cursor_line_ = -1;
    int scroll_line_ = 0;
    QString highlight_address_;
    QString highlight_symbol_;
    QString pending_message_;
};
