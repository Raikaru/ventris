#include "decompiler_view.h"

DecompilerView::DecompilerView(QWidget *parent) : QPlainTextEdit(parent) {
    setObjectName(QStringLiteral("decompilerView"));
    setReadOnly(true);
    setPlaceholderText(QStringLiteral("Structured decompiler document"));
}

void DecompilerView::setTokens(const QVector<TokenView> &tokens) {
    tokens_ = tokens;
    QString text;
    text.reserve(tokens.size() * 8);
    for (const TokenView &token : tokens) {
        text += token.text;
    }
    setPlainText(text);
}
