#pragma once

#include <QPlainTextEdit>

#include "views.h"

/// Decompiler output surface. Phase 0 keeps the QPlainTextEdit backing;
/// Phase 1.3 replaces the internals with a paint-based token renderer
/// (per-token hit testing) without changing the widget's role in the dock.
class DecompilerView final : public QPlainTextEdit {
    Q_OBJECT

public:
    explicit DecompilerView(QWidget *parent = nullptr);

    /// Renders the token stream as text and retains the typed tokens for
    /// Phase 1.3 hit testing. Parsing happened once, in the caller.
    void setTokens(const QVector<TokenView> &tokens);

private:
    QVector<TokenView> tokens_;
};
