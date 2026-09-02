#pragma once

#include <QJsonObject>
#include <QObject>
#include <QThreadPool>

#include <lre-qt-bridge/src/lib.rs.h>

#include <atomic>
#include <functional>
#include <optional>

using ResponseCallback = std::function<void(const QJsonObject &)>;

class CoreBridge final : public QObject {
    Q_OBJECT

public:
    explicit CoreBridge(const QString &project, QObject *parent = nullptr);
    ~CoreBridge() override;

    /// Stop accepting work, discard queued jobs, and wait for running Core
    /// calls to return before the Rust handle is dropped. Native decompiler
    /// calls remain isolated child processes; the Core call cannot leave one
    /// orphaned after this barrier.
    void shutdown();

    QString startupError() const;
    void request(const QJsonObject &request, ResponseCallback callback);

private:
    std::optional<rust::Box<ventris::CoreHandle>> core_;
    QString startup_error_;
    std::atomic_bool shutting_down_{false};
    QThreadPool pool_;
};
