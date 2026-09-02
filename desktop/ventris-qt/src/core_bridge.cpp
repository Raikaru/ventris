#include "core_bridge.h"

#include <QFutureWatcher>
#include <QJsonDocument>
#include <QtConcurrent/QtConcurrentRun>

CoreBridge::CoreBridge(const QString &project, QObject *parent)
    : QObject(parent) {
    try {
        const QByteArray utf8 = project.toUtf8();
        core_.emplace(ventris::core_open(
            rust::Str(utf8.constData(), static_cast<std::size_t>(utf8.size()))));
    } catch (const std::exception &error) {
        startup_error_ = QString::fromUtf8(error.what());
    }
    pool_.setMaxThreadCount(2);
}

CoreBridge::~CoreBridge() { shutdown(); }

void CoreBridge::shutdown() {
    const bool was_shutdown = shutting_down_.exchange(true);
    if (was_shutdown) {
        return;
    }
    pool_.clear();
    pool_.waitForDone();
}

QString CoreBridge::startupError() const { return startup_error_; }

void CoreBridge::request(const QJsonObject &request, ResponseCallback callback) {
    if (shutting_down_.load()) {
        callback(QJsonObject{{"ok", false}, {"error", "bridge is shutting down"}});
        return;
    }
    if (!core_.has_value()) {
        callback(QJsonObject{{"ok", false}, {"error", startup_error_}});
        return;
    }
    const QByteArray encoded = QJsonDocument(request).toJson(QJsonDocument::Compact);
    QFuture<QString> future = QtConcurrent::run(&pool_, [this, encoded]() {
        rust::String response = ventris::core_request(
            **core_, rust::Str(encoded.constData(), static_cast<std::size_t>(encoded.size())));
        return QString::fromUtf8(response.data(), static_cast<int>(response.size()));
    });
    auto *watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this,
            [watcher, callback = std::move(callback)]() mutable {
                const QString response = watcher->result();
                const QJsonDocument document =
                    QJsonDocument::fromJson(response.toUtf8());
                if (document.isObject()) {
                    callback(document.object());
                } else {
                    callback(QJsonObject{{"ok", false},
                                         {"error", "Rust bridge returned invalid JSON"}});
                }
                watcher->deleteLater();
            });
    watcher->setFuture(future);
}
