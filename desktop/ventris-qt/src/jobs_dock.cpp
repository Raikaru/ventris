#include "jobs_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

JobsDock::JobsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Analysis jobs"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("analysisJobsDock"));

    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 0, 0);

    jobs_summary_ = new QLabel(QStringLiteral("Worker pool: no decompile jobs"), panel);
    jobs_summary_->setObjectName(QStringLiteral("workerPoolStatus"));
    jobs_summary_->setWordWrap(true);
    layout->addWidget(jobs_summary_);

    jobs_ = new QListWidget(panel);
    jobs_->setObjectName(QStringLiteral("analysisJobs"));
    layout->addWidget(jobs_, 1);

    auto *cancel_btn = new QPushButton(QStringLiteral("Cancel selected"), panel);
    connect(cancel_btn, &QPushButton::clicked, this, &JobsDock::cancelJob);
    layout->addWidget(cancel_btn);

    setWidget(panel);
}

int JobsDock::beginJob(const QString &label) {
    auto *item = new QListWidgetItem(QStringLiteral("▶ ") + label, jobs_);
    item->setForeground(QColor("#e5c07b"));
    jobs_->scrollToBottom();
    return jobs_->count() - 1;
}

void JobsDock::finishJob(int index, bool ok, const QString &detail) {
    if (auto *item = jobs_->item(index)) {
        if (cancelled_jobs_.contains(index)) {
            item->setText(QStringLiteral("✗ cancelled — ") + detail);
            item->setForeground(QColor("#7e8996"));
        } else if (ok) {
            item->setText(QStringLiteral("✓ ") + detail);
            item->setForeground(QColor("#98c379"));
        } else {
            item->setText(QStringLiteral("✗ ") + detail);
            item->setForeground(QColor("#e06c75"));
        }
    }
    emit statusRequested(detail, !ok);
    refreshJobs();
}

void JobsDock::refreshJobs() {
    if (jobs_summary_ == nullptr) {
        return;
    }
    bridge_->request(
        QJsonObject{{"method", "jobs_page"}, {"offset", 0}, {"limit", 64}},
        [this](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                jobs_summary_->setText(QStringLiteral("Worker pool unavailable: %1").arg(error));
                jobs_summary_->setStyleSheet(QStringLiteral("color:#e06c75"));
                return;
            }
            const QJsonObject result = response.value("result").toObject();
            const QJsonObject pool = result.value("pool").toObject();
            const qint64 cap_bytes = pool.value("memory_cap_bytes").toInteger();
            const QString cap = cap_bytes == 0
                                    ? QStringLiteral("unlimited")
                                    : QStringLiteral("%1 MiB").arg(cap_bytes / (1024 * 1024));
            QString summary =
                QStringLiteral("Worker pool: %1 idle, %2 busy, %3 restarts, cap %4 (%5 hits)")
                    .arg(pool.value("idle_workers").toInteger())
                    .arg(pool.value("busy_workers").toInteger())
                    .arg(pool.value("restarts").toInteger())
                    .arg(cap)
                    .arg(pool.value("memory_cap_hits").toInteger());
            const QJsonArray rows = result.value("rows").toArray();
            for (int i = rows.size() - 1; i >= 0; --i) {
                const QJsonObject row = rows.at(i).toObject();
                if (row.value("state").toString() == QStringLiteral("failed")) {
                    summary += QStringLiteral("\nLast failure: %1 — %2")
                                   .arg(row.value("operation").toString(),
                                        row.value("detail").toString());
                    break;
                }
            }
            jobs_summary_->setText(summary);
            jobs_summary_->setStyleSheet(QString());
        });
}

void JobsDock::cancelJob() {
    const int row = jobs_->currentRow();
    if (row < 0) {
        return;
    }
    if (auto *item = jobs_->item(row)) {
        if (item->text().startsWith(QStringLiteral("▶ "))) {
            cancelled_jobs_.insert(row);
            finishJob(row, false, QStringLiteral("cancelled by user"));
        }
    }
}
