#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>

/// Shared JSON helpers for the desktop frontend. These convert between the
/// wire envelope produced by the Rust bridge and the display strings the
/// widgets need. The typed views (views.h) are the preferred consumer
/// surface; these remain for widgets that still parse envelopes directly.
inline QString addressText(const QJsonValue &value) {
    if (value.isString()) {
        return value.toString();
    }
    if (value.isObject()) {
        const QJsonObject object = value.toObject();
        const qlonglong offset = object.value("offset").toVariant().toLongLong();
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(offset), 0, 16);
    }
    return QStringLiteral("?");
}

inline QJsonArray bytesFromText(QString text) {
    text.remove(' ');
    text.remove(':');
    if (text.startsWith(QStringLiteral("0x"))) {
        text.remove(0, 2);
    }
    QJsonArray bytes;
    if (text.isEmpty() || text.size() % 2 != 0) {
        return bytes;
    }
    for (int offset = 0; offset < text.size(); offset += 2) {
        bool ok = false;
        const int byte = text.mid(offset, 2).toInt(&ok, 16);
        if (!ok || byte < 0 || byte > 255) {
            return {};
        }
        bytes.append(byte);
    }
    return bytes;
}

inline QString bytesText(const QJsonArray &bytes) {
    QString text;
    for (const QJsonValue &value : bytes) {
        text += QStringLiteral("%1").arg(value.toInt(), 2, 16, QLatin1Char('0'));
    }
    return text.toUpper();
}

inline QJsonValue optionalInteger(const QString &text) {
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return QJsonValue(QJsonValue::Null);
    }
    bool ok = false;
    const qlonglong value = trimmed.toLongLong(&ok, 0);
    return ok ? QJsonValue(value) : QJsonValue(QJsonValue::Null);
}

inline bool successful(const QJsonObject &response, QString *error = nullptr) {
    if (response.value("ok").toBool(false)) {
        return true;
    }
    if (error != nullptr) {
        *error = response.value("error").toString(QStringLiteral("request failed"));
    }
    return false;
}
