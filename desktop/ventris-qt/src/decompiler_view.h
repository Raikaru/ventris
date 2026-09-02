#pragma once

#include <QPlainTextEdit>

/// Decompiler output surface. Phase 0 keeps the QPlainTextEdit backing;
/// Phase 1.3 replaces the internals with a paint-based token renderer
/// (per-token hit testing) without changing the widget's role in the dock.
class DecompilerView final : public QPlainTextEdit {
    Q_OBJECT

public:
    explicit DecompilerView(QWidget *parent = nullptr);
};
