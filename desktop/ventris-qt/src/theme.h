#pragma once

#include <QColor>
#include <QSettings>
#include <QString>

/// The single color source for every paint site (Phase 3). Three palettes:
/// dark (default), light, and high-contrast. The selection persists in
/// QSettings("Ventris"/"theme"); widgets read `Theme::current()` at paint
/// time so a theme switch is one repaint.
struct Theme {
    // Shared surfaces.
    QColor background;
    QColor cursor_line;
    QColor highlight;
    QColor empty_text;
    QColor status_ok;
    QColor status_error;
    QColor job_running;
    QColor job_cancelled;
    // Listing.
    QColor address_column;
    QColor bytes_column;
    QColor mnemonic;
    QColor operands;
    QColor jump_target;
    // Decompiler tokens.
    QColor variable;
    QColor function_name;
    QColor operator_;
    QColor keyword;
    // Graph.
    QColor node_fill;
    QColor node_border;
    QColor node_highlight;
    QColor node_text;
    QColor edge_true;
    QColor edge_false;
    QColor edge_unconditional;
    QColor edge_call;
    // Hex.
    QColor offset_column;
    QColor hex_text;
    QColor ascii_text;
    QColor pointer;

    static const Theme &current() {
        static const Theme theme = make(settingsName());
        return theme;
    }

    static QString settingsName() {
        QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
        return settings.value(QStringLiteral("theme"), QStringLiteral("dark")).toString();
    }

    static void setName(const QString &name) {
        QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
        settings.setValue(QStringLiteral("theme"), name);
    }

    static Theme make(const QString &name);
};
