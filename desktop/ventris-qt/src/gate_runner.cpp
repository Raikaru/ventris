#include "gate_runner.h"

#include "core_bridge.h"
#include "decompiler_dock.h"
#include "decompiler_view.h"
#include "functions_dock.h"
#include "graph_canvas.h"
#include "graph_dock.h"
#include "json_util.h"
#include "listing_canvas.h"
#include "main_window.h"
#include "navigation_controller.h"

#include <QApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTableView>
#include <QTextStream>
#include <QTimer>

GateRunner::GateRunner(MainWindow *window, CoreBridge *bridge, QObject *parent)
    : QObject(parent), window_(window), bridge_(bridge) {}

void GateRunner::run() {
    if (active_) {
        return;
    }
    active_ = true;
    stage_ = Stage::Inactive;
    window_->functionsDock()->filterTimer()->setInterval(0);
    metrics_ = QJsonObject();
    address_.clear();

    const QString b = window_->binary();
    const QString p = window_->program();
    if (b.isEmpty() || p.isEmpty()) {
        finish(false, QStringLiteral("gate requires --binary and --name"));
        return;
    }

    bridge_->request(
        QJsonObject{{"method", "import_native"}, {"binary", b}, {"name", p}},
        [this, p](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            window_->navigation()->setProgram(p);
            stage_ = Stage::LoadingList;
            timer_.start();
            window_->functionsDock()->setProgram(p);
        });
}

void GateRunner::modelRefreshed() {
    if (!active_) {
        return;
    }
    const Stage current_stage = stage_;
    if (current_stage != Stage::LoadingList && current_stage != Stage::Filtering &&
        current_stage != Stage::ClearingFilter) {
        return;
    }
    QTimer::singleShot(0, this, [this, current_stage]() {
        if (!active_ || stage_ != current_stage) {
            return;
        }
        if (window_->functionsDock()->tableView() != nullptr) {
            window_->functionsDock()->tableView()->viewport()->repaint();
        }
        const double elapsed_ms = static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0;
        if (current_stage == Stage::LoadingList) {
            metrics_.insert(QStringLiteral("ui.list.load_ms"), elapsed_ms);
            stage_ = Stage::Filtering;
            timer_.restart();
            window_->functionsDock()->filterTimer()->stop();
            window_->functionsDock()->setFilter(QStringLiteral("FUN_"));
        } else if (current_stage == Stage::Filtering) {
            metrics_.insert(QStringLiteral("ui.list.filter_ms"), elapsed_ms);
            stage_ = Stage::ClearingFilter;
            window_->functionsDock()->filterTimer()->stop();
            window_->functionsDock()->setFilter(QString());
        } else {
            startLargestFunction();
        }
    });
}

void GateRunner::startLargestFunction() {
    stage_ = Stage::Inactive;
    bridge_->request(
        QJsonObject{{"method", "functions_page"},
                    {"program", window_->program()},
                    {"offset", 0},
                    {"limit", 1},
                    {"sort", "size:desc"}},
        [this](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            const QJsonArray rows = res.value("result").toObject().value("rows").toArray();
            if (rows.isEmpty()) {
                finish(false, QStringLiteral("gate found no functions"));
                return;
            }
            address_ = addressText(rows.first().toObject().value("entry"));
            if (address_.isEmpty() || address_ == QStringLiteral("?")) {
                finish(false, QStringLiteral("gate found invalid address"));
                return;
            }
            startDecompile(address_);
        });
}

void GateRunner::startDecompile(const QString &addr) {
    bridge_->request(
        QJsonObject{{"method", "decompile_doc"},
                    {"binary", window_->binary()},
                    {"program", window_->program()},
                    {"address", addr}},
        [this](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            QVector<TokenView> tokens;
            for (const QJsonValue &v : res.value("result").toObject().value("tokens").toArray()) {
                tokens.append(TokenView::fromJson(v.toObject()));
            }
            bridge_->request(
                QJsonObject{{"method", "listing"},
                            {"binary", window_->binary()},
                            {"start", address_},
                            {"count", 128}},
                [this, tokens = std::move(tokens)](const QJsonObject &l_res) mutable {
                    QVector<ListingRowView> views;
                    if (successful(l_res)) {
                        for (const QJsonValue &row : l_res.value("result").toObject().value("rows").toArray()) {
                            views.append(ListingRowView::fromJson(row.toObject()));
                        }
                    }
                    window_->listingCanvas()->setWindow(views);
                    window_->decompilerDock()->view()->setTokens(tokens);
                    timer_.start();
                    window_->decompilerDock()->view()->setAddress(address_);
                    window_->listingCanvas()->setAddress(address_);
                    window_->decompilerDock()->view()->repaint();
                    window_->listingCanvas()->repaint();
                    metrics_.insert(QStringLiteral("ui.sync_ms"),
                                    static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0);
                    startGraph();
                });
        });
}

void GateRunner::startGraph() {
    timer_.start();
    bridge_->request(
        QJsonObject{{"method", "function_bb_graph"},
                    {"binary", window_->binary()},
                    {"address", address_}},
        [this](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            metrics_.insert(QStringLiteral("ui.graph.layout_ms"),
                            static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0);
            const QJsonObject result = res.value("result").toObject();
            QVector<GraphCanvas::Node> nodes;
            QVector<GraphCanvas::Edge> edges;
            for (const QJsonValue &v : result.value("nodes").toArray()) {
                const QJsonObject row = v.toObject();
                GraphCanvas::Node n;
                n.address = row.value("address").toString();
                n.size = row.value("size").toVariant().toULongLong();
                n.pos = QPointF(row.value("x").toVariant().toDouble(),
                                row.value("y").toVariant().toDouble());
                nodes.append(n);
            }
            for (const QJsonValue &v : result.value("edges").toArray()) {
                const QJsonObject row = v.toObject();
                GraphCanvas::Edge e;
                e.from = row.value("from").toString();
                e.to = row.value("to").toString();
                e.kind = row.value("kind").toString();
                edges.append(e);
            }
            timer_.start();
            window_->graphDock()->canvas()->setGraph(nodes, edges);
            window_->graphDock()->canvas()->setAddress(address_);
            window_->graphDock()->canvas()->repaint();
            metrics_.insert(QStringLiteral("ui.graph.paint_ms"),
                            static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0);
            const bool install_ok = qEnvironmentVariableIsSet("VENTRIS_UI_INSTALL_OK");
            metrics_.insert(QStringLiteral("ui.install.ok"), install_ok);
            finish(true);
        });
}

void GateRunner::finish(bool ok, const QString &detail) {
    if (!active_) {
        return;
    }
    active_ = false;
    stage_ = Stage::Inactive;
    const QJsonObject output{{"metrics", metrics_}};
    QTextStream out(stdout);
    out << QJsonDocument(output).toJson(QJsonDocument::Compact) << Qt::endl;
    if (!ok) {
        QTextStream err(stderr);
        err << "ui gate failed: " << detail << Qt::endl;
    }
    QApplication::exit(ok ? 0 : 1);
}
