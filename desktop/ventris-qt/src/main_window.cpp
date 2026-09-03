#include "main_window.h"

#include "analyst_dock.h"
#include "core_bridge.h"
#include "decompiler_dock.h"
#include "decompiler_view.h"
#include "facts_dock.h"
#include "function_table_model.h"
#include "functions_dock.h"
#include "gate_runner.h"
#include "graph_canvas.h"
#include "graph_dock.h"
#include "jobs_dock.h"
#include "json_util.h"
#include "listing_canvas.h"
#include "memory_dock.h"
#include "navigation_controller.h"
#include "theme.h"
#include "types_dock.h"
#include "views.h"
#include "vtables_dock.h"
#include "xrefs_dock.h"

#include <QAction>
#include <QApplication>
#include <QDialog>
#include <QFileDialog>
#include <QGridLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMenuBar>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QVBoxLayout>

MainWindow::MainWindow(const QString &project, const QString &program,
                        const QString &binary, const QString &address,
                        QWidget *parent)
    : QMainWindow(parent), bridge_(new CoreBridge(project, this)),
      program_(program), binary_(binary), address_(address) {
    navigation_ = new NavigationController(this);
    gate_runner_ = new GateRunner(this, bridge_, this);
    setWindowTitle(QStringLiteral("Ventris"));
    resize(1280, 820);

    auto *central = new QWidget(this);
    auto *root = new QVBoxLayout(central);
    auto *controls = new QGridLayout();

    controls->addWidget(new QLabel(QStringLiteral("Project"), central), 0, 0);
    controls->addWidget(project_edit_ = new QLineEdit(project, central), 0, 1);
    controls->addWidget(new QLabel(QStringLiteral("Program"), central), 0, 2);
    controls->addWidget(program_edit_ = new QLineEdit(program, central), 0, 3);
    controls->addWidget(new QLabel(QStringLiteral("Binary"), central), 1, 0);
    controls->addWidget(binary_edit_ = new QLineEdit(binary, central), 1, 1, 1, 3);
    controls->addWidget(new QLabel(QStringLiteral("Address"), central), 2, 0);
    controls->addWidget(address_edit_ = new QLineEdit(address, central), 2, 1);

    auto add_btn = [this, controls](const QString &lbl, int r, int c, auto slot) {
        auto *btn = new QPushButton(lbl, this);
        controls->addWidget(btn, r, c);
        connect(btn, &QPushButton::clicked, this, slot);
        return btn;
    };
    add_btn(QStringLiteral("Import native"), 2, 2, &MainWindow::importNative);
    add_btn(QStringLiteral("Open"), 2, 3, &MainWindow::openProgram);
    add_btn(QStringLiteral("<"), 3, 0, [this]() { navigation_->back(); });
    add_btn(QStringLiteral(">"), 3, 1, [this]() { navigation_->forward(); });
    add_btn(QStringLiteral("Refresh"), 3, 2, &MainWindow::loadProgramPanels);
    add_btn(QStringLiteral("Decompile"), 3, 3, &MainWindow::decompile);
    controls->addWidget(new QLabel(QStringLiteral("Rename"), central), 4, 0);
    controls->addWidget(name_edit_ = new QLineEdit(central), 4, 1);
    add_btn(QStringLiteral("Apply rename"), 4, 2, &MainWindow::renameFunction);
    add_btn(QStringLiteral("Undo"), 4, 3, &MainWindow::undoCommand);
    controls->addWidget(new QLabel(QStringLiteral("Comment"), central), 5, 0);
    controls->addWidget(comment_edit_ = new QLineEdit(central), 5, 1);
    controls->addWidget(comment_kind_edit_ = new QLineEdit(QStringLiteral("eol"), central), 5, 2);
    add_btn(QStringLiteral("Apply comment"), 5, 3, &MainWindow::applyComment);

    auto *btn_listing = new QPushButton(QStringLiteral("Listing"), central);
    connect(btn_listing, &QPushButton::clicked, this, &MainWindow::loadListing);
    auto *btn_xref = new QPushButton(QStringLiteral("Xrefs"), central);
    connect(btn_xref, &QPushButton::clicked, this, [this]() { xrefs_dock_->loadXrefs(program_edit_->text(), address_edit_->text()); });

    listing_canvas_ = new ListingCanvas(central);
    root->addLayout(controls);
    root->addWidget(listing_canvas_, 1);
    setCentralWidget(central);

    auto add_dock = [this](Qt::DockWidgetArea a, QDockWidget *d) { addDockWidget(a, d); return d; };
    functions_dock_ = static_cast<FunctionsDock*>(add_dock(Qt::LeftDockWidgetArea, new FunctionsDock(bridge_, this)));
    analyst_dock_ = static_cast<AnalystDock*>(add_dock(Qt::LeftDockWidgetArea, new AnalystDock(bridge_, this)));
    types_dock_ = static_cast<TypesDock*>(add_dock(Qt::LeftDockWidgetArea, new TypesDock(bridge_, this)));
    decompiler_dock_ = static_cast<DecompilerDock*>(add_dock(Qt::BottomDockWidgetArea, new DecompilerDock(this)));
    graph_dock_ = static_cast<GraphDock*>(add_dock(Qt::BottomDockWidgetArea, new GraphDock(bridge_, this)));
    jobs_dock_ = static_cast<JobsDock*>(add_dock(Qt::BottomDockWidgetArea, new JobsDock(bridge_, this)));
    facts_dock_ = static_cast<FactsDock*>(add_dock(Qt::RightDockWidgetArea, new FactsDock(bridge_, this)));
    memory_dock_ = static_cast<MemoryDock*>(add_dock(Qt::RightDockWidgetArea, new MemoryDock(bridge_, this)));
    xrefs_dock_ = static_cast<XrefsDock*>(add_dock(Qt::RightDockWidgetArea, new XrefsDock(bridge_, this)));
    vtables_dock_ = static_cast<VtablesDock*>(add_dock(Qt::RightDockWidgetArea, new VtablesDock(bridge_, this)));

    status_ = new QLabel(this);
    statusBar()->addWidget(status_, 1);

    auto *menu_bar = menuBar();
    auto *file_menu = menu_bar->addMenu(QStringLiteral("&File"));
    file_menu->addAction(QStringLiteral("&Open project…"), this, [this]() {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Open SQLite project"), project_edit_->text());
        if (!dir.isEmpty()) { project_edit_->setText(dir); }
    });
    recent_menu_ = file_menu->addMenu(QStringLiteral("Open &recent"));
    file_menu->addSeparator();
    file_menu->addAction(QStringLiteral("&Quit"), qApp, &QApplication::quit, QKeySequence::Quit);

    auto *view_menu = menu_bar->addMenu(QStringLiteral("&View"));
    const QList<QDockWidget*> all_docks = {functions_dock_, decompiler_dock_, facts_dock_, memory_dock_, graph_dock_, analyst_dock_, types_dock_, xrefs_dock_, jobs_dock_, vtables_dock_};
    for (auto *dock : all_docks) {
        view_menu->addAction(dock->toggleViewAction());
    }

    auto *search_menu = menu_bar->addMenu(QStringLiteral("&Search"));
    search_menu->addAction(QStringLiteral("&Command palette"), this, &MainWindow::showCommandPalette, QKeySequence(QStringLiteral("Ctrl+Shift+P")));
    search_menu->addAction(QStringLiteral("&Byte-pattern search…"), this, &MainWindow::showSignatureSearch);
    search_menu->addAction(QStringLiteral("Recover &vtables"), this, [this]() { vtables_dock_->recoverVtables(binary_edit_->text()); });

    connect(functions_dock_, &FunctionsDock::addressSelected, navigation_, &NavigationController::goTo);
    connect(functions_dock_->model(), &FunctionTableModel::refreshed, gate_runner_, &GateRunner::modelRefreshed);
    connect(decompiler_dock_->view(), &DecompilerView::addressSelected, navigation_, &NavigationController::goTo);
    connect(decompiler_dock_->view(), &DecompilerView::renameRequested, this, &MainWindow::renameFunctionAt);
    connect(listing_canvas_, &ListingCanvas::addressSelected, navigation_, &NavigationController::goTo);
    connect(listing_canvas_, &QWidget::customContextMenuRequested, this, [this](const QPoint &p) { listingContextMenu(p, listing_canvas_->currentAddress()); });
    connect(graph_dock_, &GraphDock::addressSelected, navigation_, &NavigationController::goTo);
    connect(facts_dock_, &FactsDock::addressSelected, this, [this](const QString &a, bool) { address_edit_->setText(a); xrefs_dock_->loadXrefs(program_edit_->text(), a); });
    connect(facts_dock_, &FactsDock::addressDoubleClicked, this, [this](const QString &a) { navigation_->goTo(a, true); });
    connect(memory_dock_, &MemoryDock::addressSelected, navigation_, &NavigationController::goTo);
    connect(analyst_dock_, &AnalystDock::addressDoubleClicked, this, [this](const QString &a) { navigation_->goTo(a, true); });
    connect(vtables_dock_, &VtablesDock::addressDoubleClicked, this, [this](const QString &a) { navigation_->goTo(a, true); });
    connect(xrefs_dock_, &XrefsDock::addressDoubleClicked, this, [this](const QString &a) { navigation_->goTo(a, true); });
    connect(types_dock_, &TypesDock::prototypeSaved, this, [this](const QString &addr) {
        decompile_cache_.remove(program_edit_->text() + QLatin1Char('|') + addr);
        decompile();
    });

    auto hook = [this](auto *d) {
        connect(d, &std::remove_pointer_t<decltype(d)>::jobStarted, jobs_dock_, [this](const QString &n) { jobs_dock_->beginJob(n); });
        connect(d, &std::remove_pointer_t<decltype(d)>::jobFinished, jobs_dock_, [this](const QString &, bool ok, const QString &det) { jobs_dock_->finishJob(jobs_dock_->findChildren<QListWidget*>().first()->count() - 1, ok, det); });
    };
    hook(memory_dock_); hook(graph_dock_); hook(analyst_dock_); hook(types_dock_); hook(xrefs_dock_); hook(vtables_dock_);
    connect(jobs_dock_, &JobsDock::statusRequested, this, &MainWindow::setStatus);

    connect(navigation_, &NavigationController::addressChanged, this, [this](const QString &address) {
        address_edit_->setText(address);
        decompile();
        loadListing();
        xrefs_dock_->loadXrefs(program_edit_->text(), address);
        types_dock_->setPrototypeAddress(address);
        saveWorkspace();
    });

    if (!bridge_->startupError().isEmpty()) {
        setStatus(bridge_->startupError(), true);
    } else if (!program_.isEmpty()) {
        functions_dock_->setProgram(program_);
        navigation_->setProgram(program_);
        if (!qEnvironmentVariableIsSet("VENTRIS_UI_GATE")) { loadProgramPanels(); }
    }
    checkOnboardingGate();
    restoreWorkspace();
}

MainWindow::~MainWindow() {
    saveWorkspace();
    bridge_->shutdown();
}

QString MainWindow::program() const { return program_edit_->text(); }
QString MainWindow::binary() const { return binary_edit_->text(); }
void MainWindow::runGate() { gate_runner_->run(); }

void MainWindow::setStatus(const QString &message, bool error) {
    if (status_ != nullptr) {
        status_->setText(message);
        status_->setStyleSheet(error ? QStringLiteral("color:#e06c75") : QString());
    }
}

void MainWindow::loadProgramPanels() {
    const QString p = program_edit_->text(), b = binary_edit_->text(), a = address_edit_->text();
    facts_dock_->loadFacts(p, search_edit_->text());
    memory_dock_->loadMemory(p, b, a);
    graph_dock_->loadGraph(b, a);
    analyst_dock_->loadAnalystData(p);
    types_dock_->loadTypes(p);
}

void MainWindow::importNative() {
    const QString binary = binary_edit_->text(), p = program_edit_->text();
    const int job = jobs_dock_->beginJob(QStringLiteral("native import"));
    bridge_->request(QJsonObject{{"method", "import_native"}, {"binary", binary}, {"name", p}},
                     [this, job, p](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         jobs_dock_->finishJob(job, true, QStringLiteral("imported %1").arg(p));
                         functions_dock_->setProgram(p);
                         navigation_->setProgram(p);
                         loadProgramPanels();
                     });
}

void MainWindow::openProgram() {
    const QString p = program_edit_->text();
    const int job = jobs_dock_->beginJob(QStringLiteral("open program"));
    bridge_->request(QJsonObject{{"method", "open"}, {"program", p}},
                     [this, job, p](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         jobs_dock_->finishJob(job, true, QStringLiteral("opened %1").arg(p));
                         functions_dock_->setProgram(p);
                         navigation_->setProgram(p);
                         loadProgramPanels();
                     });
}

void MainWindow::decompile() {
    const QString address = address_edit_->text();
    const QString key = program_edit_->text() + QLatin1Char('|') + address;
    if (decompile_cache_.contains(key)) {
        const auto cached = decompile_cache_.value(key);
        decompiler_dock_->view()->setTokens(cached.second);
        decompiler_dock_->view()->setAddress(address);
        return;
    }
    const int job = jobs_dock_->beginJob(QStringLiteral("decompile %1").arg(address));
    decompiler_dock_->view()->setPending(QStringLiteral("Decompiling…"));
    const quint64 gen = ++decompile_generation_;
    bridge_->request(QJsonObject{{"method", "decompile_doc"}, {"binary", binary_edit_->text()}, {"program", program_edit_->text()}, {"address", address}},
                     [this, job, key, gen, address](const QJsonObject &res) {
                         if (gen != decompile_generation_) { return; }
                         QString err;
                         if (!successful(res, &err)) {
                             decompiler_dock_->view()->setPending(QStringLiteral("Decompilation failed: %1").arg(err));
                             jobs_dock_->finishJob(job, false, err);
                             return;
                         }
                         const QJsonObject result = res.value("result").toObject();
                         QVector<TokenView> tokens;
                         for (const QJsonValue &v : result.value("tokens").toArray()) {
                             tokens.append(TokenView::fromJson(v.toObject()));
                         }
                         const qint64 rev = result.value("revision").toVariant().toLongLong();
                         decompile_cache_.insert(key, qMakePair(rev, tokens));
                         decompiler_dock_->view()->setTokens(tokens);
                         decompiler_dock_->view()->setAddress(address);
                         jobs_dock_->finishJob(job, true, QStringLiteral("%1 tokens, revision %2").arg(tokens.size()).arg(rev));
                     });
}

void MainWindow::loadListing() { loadListingAt(address_edit_->text()); }

void MainWindow::loadListingAt(const QString &address) {
    if (address.isEmpty() || binary_edit_->text().isEmpty()) { return; }
    const int job = jobs_dock_->beginJob(QStringLiteral("listing %1").arg(address));
    bridge_->request(QJsonObject{{"method", "listing"}, {"binary", binary_edit_->text()}, {"start", address}, {"count", 128}},
                     [this, job, address](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         QVector<ListingRowView> views;
                         for (const QJsonValue &v : res.value("result").toObject().value("rows").toArray()) {
                             views.append(ListingRowView::fromJson(v.toObject()));
                         }
                         listing_canvas_->setWindow(views);
                         listing_canvas_->setAddress(address);
                         jobs_dock_->finishJob(job, true, QStringLiteral("listing loaded"));
                     });
}

void MainWindow::listingContextMenu(const QPoint &pos, const QString &addr) {
    QMenu menu(this);
    menu.addAction(QStringLiteral("Rename function"), this, [this, addr]() { renameFunctionAt(addr, QString()); });
    menu.addAction(QStringLiteral("Show xrefs"), this, [this, addr]() { xrefs_dock_->loadXrefs(program_edit_->text(), addr); });
    menu.addAction(QStringLiteral("Decompile here"), this, [this, addr]() { navigation_->goTo(addr, true); });
    menu.exec(pos);
}

void MainWindow::renameFunctionAt(const QString &address, const QString &name) {
    QString new_name = name;
    if (new_name.isEmpty()) {
        bool ok = false;
        new_name = QInputDialog::getText(this, QStringLiteral("Rename function"), QStringLiteral("New name:"), QLineEdit::Normal, QString(), &ok);
        if (!ok || new_name.trimmed().isEmpty()) { return; }
    }
    const int job = jobs_dock_->beginJob(QStringLiteral("rename %1").arg(address));
    bridge_->request(QJsonObject{{"method", "rename"}, {"program", program_edit_->text()}, {"address", address}, {"name", new_name}},
                     [this, job, address, new_name](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         decompile_cache_.remove(program_edit_->text() + QLatin1Char('|') + address);
                         functions_dock_->model()->refresh();
                         decompile();
                         jobs_dock_->finishJob(job, true, QStringLiteral("renamed to %1").arg(new_name));
                     });
}

void MainWindow::renameFunction() { renameFunctionAt(address_edit_->text(), name_edit_->text().trimmed()); }

void MainWindow::applyComment() {
    const QString addr = address_edit_->text();
    const int job = jobs_dock_->beginJob(QStringLiteral("comment %1").arg(addr));
    bridge_->request(QJsonObject{{"method", "comment"}, {"program", program_edit_->text()}, {"address", addr}, {"kind", comment_kind_edit_->text()}, {"text", comment_edit_->text()}},
                     [this, job, addr](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         loadListingAt(addr);
                         jobs_dock_->finishJob(job, true, QStringLiteral("comment applied"));
                     });
}

void MainWindow::undoCommand() {
    const int job = jobs_dock_->beginJob(QStringLiteral("undo"));
    bridge_->request(QJsonObject{{"method", "undo"}, {"program", program_edit_->text()}},
                     [this, job](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         functions_dock_->model()->refresh();
                         decompile();
                         loadListing();
                         jobs_dock_->finishJob(job, true, res.value("result").toObject().value("message").toString());
                     });
}

void MainWindow::showCommandPalette() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Command palette"));
    auto *l = new QVBoxLayout(&dialog);
    auto *filter = new QLineEdit(&dialog);
    auto *list = new QListWidget(&dialog);
    l->addWidget(filter);
    l->addWidget(list);
    connect(list, &QListWidget::itemActivated, &dialog, &QDialog::accept);
    dialog.exec();
}

void MainWindow::showSignatureSearch() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Byte-pattern signature search"));
    auto *l = new QVBoxLayout(&dialog);
    auto *pattern_edit = new QLineEdit(&dialog);
    auto *list = new QListWidget(&dialog);
    l->addWidget(pattern_edit);
    l->addWidget(list);
    dialog.exec();
}

void MainWindow::checkOnboardingGate() {
    if (qEnvironmentVariableIsSet("VENTRIS_UI_GATE")) { return; }
}

void MainWindow::restoreWorkspace() {
    QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
    const QString scope = program_edit_->text().isEmpty() ? QString() : program_edit_->text() + QLatin1Char('/');
    const QByteArray geo = settings.value(scope + QStringLiteral("geometry")).toByteArray();
    if (!geo.isEmpty()) { restoreGeometry(geo); }
    const QByteArray state = settings.value(scope + QStringLiteral("windowState")).toByteArray();
    if (!state.isEmpty()) { restoreState(state); }
}

void MainWindow::saveWorkspace() {
    QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
    const QString scope = program_edit_->text().isEmpty() ? QString() : program_edit_->text() + QLatin1Char('/');
    settings.setValue(scope + QStringLiteral("geometry"), saveGeometry());
    settings.setValue(scope + QStringLiteral("windowState"), saveState());
}
