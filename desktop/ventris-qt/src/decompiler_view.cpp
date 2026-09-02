#include "decompiler_view.h"

DecompilerView::DecompilerView(QWidget *parent) : QPlainTextEdit(parent) {
    setObjectName(QStringLiteral("decompilerView"));
    setReadOnly(true);
    setPlaceholderText(QStringLiteral("Structured decompiler document"));
}
