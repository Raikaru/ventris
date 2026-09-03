#pragma once

#include "json_util.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <QVector>

/// Typed views over the JSON envelopes the Rust bridge returns. Widgets
/// consume these structs; no QJsonObject indexing happens inside
/// paintEvent or data(). Field names mirror the lre-model wire contracts
/// (FunctionRow via functions_page, ListingRow via CORE-007, DecompToken
/// via WORKER-004).

/// One functions_page row: address, name, size, signature.
struct FunctionRowView {
    QString address;
    QString name;
    qint64 size = 0;
    QString signature;

    static FunctionRowView fromJson(const QJsonObject &row) {
        FunctionRowView view;
        view.address = addressText(row.value("entry"));
        view.name = row.value("name").toString();
        view.size = row.value("size").toVariant().toLongLong();
        view.signature = row.value("signature").toString();
        return view;
    }
};

/// One listing row (CORE-007): stable id (= instruction address offset),
/// structural kind, display address, rendered mnemonic + operands, and raw
/// instruction bytes.
struct ListingRowView {
    quint64 stable_id = 0;
    QString address;
    QString kind = QStringLiteral("instruction");
    QString text;
    QString bytes;

    static ListingRowView fromJson(const QJsonObject &row) {
        ListingRowView view;
        view.stable_id = row.value("stable_id").toVariant().toULongLong();
        view.address = addressText(row.value("address"));
        view.kind = row.value("kind").toString();
        if (view.kind.isEmpty()) {
            view.kind = QStringLiteral("instruction");
        }
        view.text = row.value("text").toString();
        view.bytes = row.value("bytes").toString();
        return view;
    }
};

/// One memory region row (section table): name, range, permissions.
struct MemoryRegionView {
    QString name;
    QString start;
    quint64 start_offset = 0;
    quint64 size = 0;
    QString permissions;

    static MemoryRegionView fromJson(const QJsonObject &row) {
        MemoryRegionView view;
        view.name = row.value("name").toString();
        view.start = addressText(row.value("start"));
        view.start_offset = row.value("start").toObject().value("offset")
                                .toVariant().toULongLong();
        view.size = row.value("size").toVariant().toULongLong();
        view.permissions = row.value("permissions").toString();
        return view;
    }
};

/// One decompiler token (WORKER-004): text, token kind, and the entity
/// address when the packed document carried one. Break tokens end a line
/// and carry the next line's indent.
struct TokenView {
    QString text;
    QString kind;
    QString address;
    quint64 indent = 0;

    bool isBreak() const { return kind == QStringLiteral("Break"); }

    static TokenView fromJson(const QJsonObject &token) {
        TokenView view;
        view.text = token.value("text").toString();
        view.kind = token.value("kind").toString();
        const QJsonValue address = token.value("address");
        view.address = address.isNull() || address.isUndefined()
                           ? QString()
                           : addressText(address);
        view.indent = token.value("indent").toVariant().toULongLong();
        return view;
    }
};
