#include "main_window.h"

#include "core_bridge.h"
#include "decompiler_view.h"
#include "function_table_model.h"
#include "graph_canvas.h"
#include "listing_canvas.h"
#include "navigation_controller.h"
#include "json_util.h"

#include <QDockWidget>
#include <QGridLayout>
#include <QHeaderView>
#include <QKeySequence>
#include <QShortcut>
#include <QMenu>
#include <QTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QSplitter>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>
#include <QVBoxLayout>

MainWindow::MainWindow(const QString &project, const QString &program, const QString &binary,
                        const QString &address, QWidget *parent)
        : QMainWindow(parent), bridge_(new CoreBridge(project, this)),
          program_(program), binary_(binary), address_(address) {
        navigation_ = new NavigationController(this);
        setWindowTitle(QStringLiteral("Ventris"));
        resize(1280, 820);

        auto *central = new QWidget(this);
        auto *root = new QVBoxLayout(central);
        auto *controls = new QGridLayout();
        project_edit_ = new QLineEdit(project, central);
        program_edit_ = new QLineEdit(program, central);
        binary_edit_ = new QLineEdit(binary, central);
        address_edit_ = new QLineEdit(address, central);
        name_edit_ = new QLineEdit(central);
        comment_edit_ = new QLineEdit(central);
        comment_kind_edit_ = new QLineEdit(QStringLiteral("eol"), central);
        controls->addWidget(new QLabel(QStringLiteral("Project"), central), 0, 0);
        search_edit_ = new QLineEdit(central);
        bookmark_edit_ = new QLineEdit(central);
        patch_original_edit_ = new QLineEdit(central);
        patch_new_edit_ = new QLineEdit(central);
        controls->addWidget(project_edit_, 0, 1);
        controls->addWidget(new QLabel(QStringLiteral("Program"), central), 0, 2);
        controls->addWidget(program_edit_, 0, 3);
        controls->addWidget(new QLabel(QStringLiteral("Binary"), central), 1, 0);
        controls->addWidget(binary_edit_, 1, 1, 1, 3);
        controls->addWidget(new QLabel(QStringLiteral("Address"), central), 2, 0);
        controls->addWidget(address_edit_, 2, 1);

        auto *import = new QPushButton(QStringLiteral("Import native"), central);
        auto *open = new QPushButton(QStringLiteral("Open"), central);
        auto *refresh = new QPushButton(QStringLiteral("Refresh"), central);
        auto *back = new QPushButton(QStringLiteral("<"), central);
        auto *forward = new QPushButton(QStringLiteral(">"), central);
        auto *decompile = new QPushButton(QStringLiteral("Decompile"), central);
        auto *listing = new QPushButton(QStringLiteral("Listing"), central);
        auto *xref = new QPushButton(QStringLiteral("Xrefs"), central);
        controls->addWidget(import, 2, 2);
        controls->addWidget(open, 2, 3);
        controls->addWidget(back, 3, 0);
        controls->addWidget(forward, 3, 1);
        controls->addWidget(refresh, 3, 2);
        controls->addWidget(decompile, 3, 3);
        controls->addWidget(new QLabel(QStringLiteral("Rename"), central), 4, 0);
        controls->addWidget(name_edit_, 4, 1);
        auto *rename = new QPushButton(QStringLiteral("Apply rename"), central);
        controls->addWidget(rename, 4, 2);
        controls->addWidget(new QLabel(QStringLiteral("Comment"), central), 5, 0);
        controls->addWidget(comment_edit_, 5, 1);
        controls->addWidget(new QLabel(QStringLiteral("Kind"), central), 5, 2);
        controls->addWidget(comment_kind_edit_, 5, 3);
        auto *comment = new QPushButton(QStringLiteral("Apply comment"), central);
        auto *undo = new QPushButton(QStringLiteral("Undo"), central);
        controls->addWidget(comment, 6, 1);
        controls->addWidget(undo, 6, 2);
        controls->addWidget(listing, 6, 3);
        controls->addWidget(xref, 7, 3);
        controls->addWidget(new QLabel(QStringLiteral("Search"), central), 8, 0);
        controls->addWidget(search_edit_, 8, 1);
        auto *search = new QPushButton(QStringLiteral("Find"), central);
        controls->addWidget(search, 8, 2);
        controls->addWidget(new QLabel(QStringLiteral("Bookmark"), central), 9, 0);
        controls->addWidget(bookmark_edit_, 9, 1);
        auto *bookmark = new QPushButton(QStringLiteral("Set bookmark"), central);
        controls->addWidget(bookmark, 9, 2);
        controls->addWidget(new QLabel(QStringLiteral("Patch old/new"), central), 10, 0);
        controls->addWidget(patch_original_edit_, 10, 1);
        controls->addWidget(patch_new_edit_, 10, 2);
        auto *patch = new QPushButton(QStringLiteral("Apply patch"), central);
        controls->addWidget(patch, 10, 3);
        root->addLayout(controls);
        listing_canvas_ = new ListingCanvas(central);
        root->addWidget(listing_canvas_, 1);
        connect(listing_canvas_, &ListingCanvas::addressSelected, this,
                [this](const QString &address, bool record) {
                    navigation_->goTo(address, record);
                });
        connect(listing_canvas_, &ListingCanvas::windowNeeded, this,
                [this](const QString &start) { loadListingAt(start); });
        connect(listing_canvas_, &ListingCanvas::backRequested, navigation_,
                &NavigationController::back);
        connect(listing_canvas_, &ListingCanvas::forwardRequested, navigation_,
                &NavigationController::forward);
        connect(listing_canvas_, &ListingCanvas::contextMenuRequested, this,
                &MainWindow::listingContextMenu);
        auto *bytes_toggle = new QShortcut(QKeySequence(QStringLiteral("Ctrl+B")), this);
        connect(bytes_toggle, &QShortcut::activated, this, [this]() {
            listing_canvas_->setBytesVisible(!listing_canvas_->bytesVisible());
        });
        status_ = new QLabel(this);
        root->addWidget(status_);
        setCentralWidget(central);

        auto *functions_panel = new QWidget(this);
        auto *functions_layout = new QVBoxLayout(functions_panel);
        functions_layout->setContentsMargins(0, 0, 0, 0);
        function_filter_edit_ = new QLineEdit(functions_panel);
        function_filter_edit_->setObjectName(QStringLiteral("functionFilterEdit"));
        function_filter_edit_->setPlaceholderText(
            QStringLiteral("Filter (substring, or re: for regex)"));
        function_filter_timer_ = new QTimer(function_filter_edit_);
        function_filter_timer_->setSingleShot(true);
        function_filter_timer_->setInterval(250);
        connect(function_filter_edit_, &QLineEdit::textChanged, function_filter_timer_,
                qOverload<>(&QTimer::start));
        connect(function_filter_timer_, &QTimer::timeout, this, [this]() {
            function_model_->setFilter(function_filter_edit_->text());
        });
        functions_layout->addWidget(function_filter_edit_);
        functions_ = new QTableView(functions_panel);
        functions_->setObjectName(QStringLiteral("functionsView"));
        function_model_ = new FunctionTableModel(bridge_, functions_);
        functions_->setModel(function_model_);
        functions_->setSelectionBehavior(QAbstractItemView::SelectRows);
        functions_->setSelectionMode(QAbstractItemView::SingleSelection);
        functions_->horizontalHeader()->setStretchLastSection(true);
        functions_->verticalHeader()->setVisible(false);
        functions_->setAlternatingRowColors(true);
        functions_->setSortingEnabled(true);
        functions_layout->addWidget(functions_, 1);
        auto *functions_dock = new QDockWidget(QStringLiteral("Functions"), this);
        functions_dock->setObjectName(QStringLiteral("functionsDock"));
        functions_dock->setWidget(functions_panel);
        addDockWidget(Qt::LeftDockWidgetArea, functions_dock);

        decompiler_ = new DecompilerView(this);
        auto *decompiler_dock = new QDockWidget(QStringLiteral("Decompiler"), this);
        decompiler_dock->setObjectName(QStringLiteral("decompilerDock"));
        decompiler_dock->setWidget(decompiler_);
        addDockWidget(Qt::BottomDockWidgetArea, decompiler_dock);

        auto *facts_tabs = new QTabWidget(this);
        symbols_ = new QTableWidget(0, 4, facts_tabs);
        symbols_->setHorizontalHeaderLabels(
            {QStringLiteral("Address"), QStringLiteral("Name"), QStringLiteral("Source"),
             QStringLiteral("External")});
        strings_ = new QTableWidget(0, 3, facts_tabs);
        strings_->setHorizontalHeaderLabels(
            {QStringLiteral("Address"), QStringLiteral("Kind"), QStringLiteral("Value")});
        search_results_ = new QTableWidget(0, 4, facts_tabs);
        search_results_->setHorizontalHeaderLabels(
            {QStringLiteral("Address"), QStringLiteral("Kind"), QStringLiteral("Name"),
             QStringLiteral("Context")});
        facts_tabs->addTab(symbols_, QStringLiteral("Symbols"));
        facts_tabs->addTab(strings_, QStringLiteral("Strings"));
        facts_tabs->addTab(search_results_, QStringLiteral("Search"));
        auto *facts_dock = new QDockWidget(QStringLiteral("Symbols / strings / search"), this);
        facts_dock->setObjectName(QStringLiteral("factsDock"));
        facts_dock->setWidget(facts_tabs);
        addDockWidget(Qt::RightDockWidgetArea, facts_dock);

        auto *memory_panel = new QWidget(this);
        auto *memory_layout = new QVBoxLayout(memory_panel);
        memory_regions_ = new QTableWidget(0, 5, memory_panel);
        memory_regions_->setHorizontalHeaderLabels(
            {QStringLiteral("Name"), QStringLiteral("Start"), QStringLiteral("Size"),
             QStringLiteral("Permissions"), QStringLiteral("Source")});
        hex_view_ = new QPlainTextEdit(memory_panel);
        hex_view_->setReadOnly(true);
        hex_view_->setPlaceholderText(QStringLiteral("Select an address to inspect bytes"));
        memory_layout->addWidget(memory_regions_, 1);
        memory_layout->addWidget(hex_view_, 1);
        auto *memory_dock = new QDockWidget(QStringLiteral("Memory map / hex"), this);
        memory_dock->setObjectName(QStringLiteral("memoryDock"));
        memory_dock->setWidget(memory_panel);
        addDockWidget(Qt::RightDockWidgetArea, memory_dock);

        graph_canvas_ = new GraphCanvas(this);
        auto *graph_dock = new QDockWidget(QStringLiteral("Function graph"), this);
        graph_dock->setObjectName(QStringLiteral("functionGraphDock"));
        graph_dock->setWidget(graph_canvas_);
        addDockWidget(Qt::BottomDockWidgetArea, graph_dock);

        auto *analyst_tabs = new QTabWidget(this);
        bookmarks_ = new QTableWidget(0, 3, analyst_tabs);
        bookmarks_->setHorizontalHeaderLabels(
            {QStringLiteral("Address"), QStringLiteral("Label"), QStringLiteral("Comment")});
        patches_ = new QTableWidget(0, 4, analyst_tabs);
        patches_->setHorizontalHeaderLabels(
            {QStringLiteral("Address"), QStringLiteral("Original"), QStringLiteral("Patched"),
             QStringLiteral("Enabled")});
        analyst_tabs->addTab(bookmarks_, QStringLiteral("Bookmarks"));
        analyst_tabs->addTab(patches_, QStringLiteral("Patches"));
        auto *analyst_dock = new QDockWidget(QStringLiteral("Analyst data"), this);
        analyst_dock->setObjectName(QStringLiteral("analystDataDock"));
        analyst_dock->setWidget(analyst_tabs);
        addDockWidget(Qt::LeftDockWidgetArea, analyst_dock);

        auto *type_panel = new QWidget(this);
        auto *type_layout = new QVBoxLayout(type_panel);
        auto *type_editor = new QGridLayout();
        type_name_edit_ = new QLineEdit(type_panel);
        type_kind_edit_ = new QLineEdit(QStringLiteral("struct"), type_panel);
        type_definition_edit_ = new QLineEdit(type_panel);
        type_size_edit_ = new QLineEdit(type_panel);
        type_alignment_edit_ = new QLineEdit(type_panel);
        type_base_edit_ = new QLineEdit(type_panel);
        type_editor->addWidget(new QLabel(QStringLiteral("Type"), type_panel), 0, 0);
        type_editor->addWidget(type_name_edit_, 0, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Kind"), type_panel), 0, 2);
        type_editor->addWidget(type_kind_edit_, 0, 3);
        type_editor->addWidget(new QLabel(QStringLiteral("Definition"), type_panel), 1, 0);
        type_editor->addWidget(type_definition_edit_, 1, 1, 1, 3);
        type_editor->addWidget(new QLabel(QStringLiteral("Size"), type_panel), 2, 0);
        type_editor->addWidget(type_size_edit_, 2, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Alignment"), type_panel), 2, 2);
        type_editor->addWidget(type_alignment_edit_, 2, 3);
        type_editor->addWidget(new QLabel(QStringLiteral("Base type"), type_panel), 3, 0);
        type_editor->addWidget(type_base_edit_, 3, 1);

        field_ordinal_edit_ = new QLineEdit(QStringLiteral("0"), type_panel);
        field_name_edit_ = new QLineEdit(type_panel);
        field_offset_edit_ = new QLineEdit(QStringLiteral("0"), type_panel);
        field_size_edit_ = new QLineEdit(type_panel);
        field_type_edit_ = new QLineEdit(type_panel);
        type_editor->addWidget(new QLabel(QStringLiteral("Field ordinal"), type_panel), 4, 0);
        type_editor->addWidget(field_ordinal_edit_, 4, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Field name"), type_panel), 4, 2);
        type_editor->addWidget(field_name_edit_, 4, 3);
        type_editor->addWidget(new QLabel(QStringLiteral("Field offset"), type_panel), 5, 0);
        type_editor->addWidget(field_offset_edit_, 5, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Field size"), type_panel), 5, 2);
        type_editor->addWidget(field_size_edit_, 5, 3);
        type_editor->addWidget(new QLabel(QStringLiteral("Field type"), type_panel), 6, 0);
        type_editor->addWidget(field_type_edit_, 6, 1, 1, 3);

        prototype_signature_edit_ = new QLineEdit(type_panel);
        calling_convention_edit_ = new QLineEdit(type_panel);
        type_editor->addWidget(new QLabel(QStringLiteral("Prototype"), type_panel), 7, 0);
        type_editor->addWidget(prototype_signature_edit_, 7, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Calling convention"), type_panel), 7, 2);
        type_editor->addWidget(calling_convention_edit_, 7, 3);

        stack_name_edit_ = new QLineEdit(type_panel);
        stack_storage_edit_ = new QLineEdit(type_panel);
        stack_type_edit_ = new QLineEdit(type_panel);
        stack_offset_edit_ = new QLineEdit(type_panel);
        stack_size_edit_ = new QLineEdit(type_panel);
        type_editor->addWidget(new QLabel(QStringLiteral("Stack variable"), type_panel), 8, 0);
        type_editor->addWidget(stack_name_edit_, 8, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Storage"), type_panel), 8, 2);
        type_editor->addWidget(stack_storage_edit_, 8, 3);
        type_editor->addWidget(new QLabel(QStringLiteral("Variable type"), type_panel), 9, 0);
        type_editor->addWidget(stack_type_edit_, 9, 1);
        type_editor->addWidget(new QLabel(QStringLiteral("Offset / size"), type_panel), 9, 2);
        auto *stack_numbers = new QWidget(type_panel);
        auto *stack_numbers_layout = new QHBoxLayout(stack_numbers);
        stack_numbers_layout->setContentsMargins(0, 0, 0, 0);
        stack_numbers_layout->addWidget(stack_offset_edit_);
        stack_numbers_layout->addWidget(stack_size_edit_);
        type_editor->addWidget(stack_numbers, 9, 3);

        auto *type_actions = new QHBoxLayout();
        auto *save_type = new QPushButton(QStringLiteral("Save type"), type_panel);
        auto *save_field = new QPushButton(QStringLiteral("Save field"), type_panel);
        auto *save_prototype = new QPushButton(QStringLiteral("Save prototype"), type_panel);
        auto *save_stack = new QPushButton(QStringLiteral("Save stack variable"), type_panel);
        auto *propagate = new QPushButton(QStringLiteral("Propagate types"), type_panel);
        type_actions->addWidget(save_type);
        type_actions->addWidget(save_field);
        type_actions->addWidget(save_prototype);
        type_actions->addWidget(save_stack);
        type_actions->addWidget(propagate);
        type_layout->addLayout(type_editor);
        type_layout->addLayout(type_actions);

        auto *type_tabs = new QTabWidget(type_panel);
        types_ = new QTableWidget(0, 7, type_tabs);
        types_->setHorizontalHeaderLabels(
            {QStringLiteral("Name"), QStringLiteral("Kind"), QStringLiteral("Definition"),
             QStringLiteral("Size"), QStringLiteral("Align"), QStringLiteral("Base"),
             QStringLiteral("Provenance")});
        type_fields_ = new QTableWidget(0, 6, type_tabs);
        type_fields_->setHorizontalHeaderLabels(
            {QStringLiteral("Type"), QStringLiteral("Ordinal"), QStringLiteral("Field"),
             QStringLiteral("Offset"), QStringLiteral("Size"), QStringLiteral("Type ref")});
        prototypes_ = new QTableWidget(0, 4, type_tabs);
        prototypes_->setHorizontalHeaderLabels(
            {QStringLiteral("Function"), QStringLiteral("Signature"),
             QStringLiteral("Calling convention"), QStringLiteral("Return type")});
        stack_variables_ = new QTableWidget(0, 7, type_tabs);
        stack_variables_->setHorizontalHeaderLabels(
            {QStringLiteral("Function"), QStringLiteral("Ordinal"), QStringLiteral("Name"),
             QStringLiteral("Storage"), QStringLiteral("Type"), QStringLiteral("Offset"),
             QStringLiteral("Size")});
        type_links_ = new QTableWidget(0, 4, type_tabs);
        type_links_->setHorizontalHeaderLabels(
            {QStringLiteral("Source"), QStringLiteral("Target"), QStringLiteral("Kind"),
             QStringLiteral("Provenance")});
        type_tabs->addTab(types_, QStringLiteral("Types"));
        type_tabs->addTab(type_fields_, QStringLiteral("Fields"));
        type_tabs->addTab(prototypes_, QStringLiteral("Prototypes"));
        type_tabs->addTab(stack_variables_, QStringLiteral("Stack"));
        type_tabs->addTab(type_links_, QStringLiteral("Graph"));
        type_layout->addWidget(type_tabs, 1);
        auto *type_dock = new QDockWidget(QStringLiteral("Types / prototypes"), this);
        type_dock->setObjectName(QStringLiteral("typesDock"));
        type_dock->setWidget(type_panel);
        addDockWidget(Qt::LeftDockWidgetArea, type_dock);

        xrefs_ = new QTableWidget(0, 3, this);
        xrefs_->setObjectName(QStringLiteral("xrefsView"));
        xrefs_->setHorizontalHeaderLabels(
            {QStringLiteral("From"), QStringLiteral("Kind"), QStringLiteral("To")});
        xrefs_->horizontalHeader()->setStretchLastSection(true);
        xrefs_->verticalHeader()->setVisible(false);
        auto *xrefs_dock = new QDockWidget(QStringLiteral("Xrefs"), this);
        xrefs_dock->setObjectName(QStringLiteral("xrefsDock"));
        xrefs_dock->setWidget(xrefs_);
        addDockWidget(Qt::RightDockWidgetArea, xrefs_dock);

        jobs_ = new QListWidget(this);
        jobs_->setObjectName(QStringLiteral("analysisJobs"));
        auto *jobs_dock = new QDockWidget(QStringLiteral("Analysis jobs"), this);
        jobs_dock->setObjectName(QStringLiteral("analysisJobsDock"));
        jobs_dock->setWidget(jobs_);
        addDockWidget(Qt::BottomDockWidgetArea, jobs_dock);

        connect(navigation_, &NavigationController::addressChanged, this,
                [this](const QString &address) {
                    address_edit_->setText(address);
                    this->decompile();
                    loadListing();
                    loadXrefs();
                });
        connect(navigation_, &NavigationController::historyChanged, back,
                &QPushButton::setEnabled);
        connect(navigation_, &NavigationController::historyChanged, forward,
                &QPushButton::setEnabled);
        connect(import, &QPushButton::clicked, this, &MainWindow::importNative);
        connect(open, &QPushButton::clicked, this, &MainWindow::openProgram);
        connect(refresh, &QPushButton::clicked, function_model_, &FunctionTableModel::refresh);
        connect(back, &QPushButton::clicked, navigation_, &NavigationController::back);
        connect(save_type, &QPushButton::clicked, this, &MainWindow::saveTypeDefinition);
        connect(save_field, &QPushButton::clicked, this, &MainWindow::saveTypeField);
        connect(save_prototype, &QPushButton::clicked, this, &MainWindow::savePrototype);
        connect(save_stack, &QPushButton::clicked, this, &MainWindow::saveStackVariable);
        connect(propagate, &QPushButton::clicked, this, &MainWindow::propagateTypes);
        connect(forward, &QPushButton::clicked, navigation_, &NavigationController::forward);
        connect(decompile, &QPushButton::clicked, this, &MainWindow::decompile);
        connect(listing, &QPushButton::clicked, this, &MainWindow::loadListing);
        connect(xref, &QPushButton::clicked, this, &MainWindow::loadXrefs);
        connect(rename, &QPushButton::clicked, this, &MainWindow::renameFunction);
        connect(comment, &QPushButton::clicked, this, &MainWindow::applyComment);
        connect(undo, &QPushButton::clicked, this, &MainWindow::undoCommand);
        auto *undo_shortcut = new QShortcut(QKeySequence::Undo, this);
        connect(undo_shortcut, &QShortcut::activated, this, &MainWindow::undoCommand);
        connect(search, &QPushButton::clicked, this, &MainWindow::loadFacts);
        connect(bookmark, &QPushButton::clicked, this, &MainWindow::setBookmark);
        connect(patch, &QPushButton::clicked, this, &MainWindow::setPatch);
        connect(memory_regions_, &QTableWidget::cellClicked, this,
                [this](int row, int) {
                    if (auto *item = memory_regions_->item(row, 1)) {
                        navigation_->goTo(item->text(), true);
                    }
                });
        connect(address_edit_, &QLineEdit::returnPressed, this, [this]() {
            navigation_->goTo(address_edit_->text(), true);
        });
        connect(functions_, &QTableView::clicked, this, [this](const QModelIndex &index) {
            if (!index.isValid()) {
                return;
            }
            name_edit_->setText(
                function_model_->data(function_model_->index(index.row(), 1)).toString());
        });
        auto jump_to_index = [this](const QModelIndex &index) {
            if (!index.isValid()) {
                return;
            }
            name_edit_->setText(
                function_model_->data(function_model_->index(index.row(), 1)).toString());
            navigation_->goTo(
                function_model_->data(function_model_->index(index.row(), 0)).toString(), true);
        };
        connect(functions_, &QTableView::doubleClicked, this, jump_to_index);
        connect(functions_, &QTableView::activated, this, jump_to_index);
        connect(function_model_, &FunctionTableModel::renameRequested, this,
                &MainWindow::renameFunctionAt);
        connect(function_model_, &FunctionTableModel::requestError, this,
                [this](const QString &message) { setStatus(message, true); });
        connect(function_model_, &FunctionTableModel::refreshed, this, [this]() {
            setStatus(QStringLiteral("%1 functions (revision %2)")
                          .arg(function_model_->total())
                          .arg(function_model_->revision()));
            loadFacts();
            loadMemory();
            loadGraph();
            loadAnalystData();
            loadTypes();
        });
        if (!bridge_->startupError().isEmpty()) {
            setStatus(bridge_->startupError(), true);
        } else if (!program_.isEmpty()) {
            function_model_->setProgram(program_);
            navigation_->setProgram(program_);
        }
        restoreWorkspace();
    }

MainWindow::~MainWindow() {
        saveWorkspace();
        bridge_->shutdown();
    }
// private slots:

void MainWindow::importNative() {
        const int job = beginJob(QStringLiteral("native import"));
        const QString binary = binary_edit_->text();

        const QString program = program_edit_->text();
        bridge_->request(QJsonObject{{"method", "import_native"},
                                     {"binary", binary},
                                     {"name", program}},
                         [this, job, program](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             finishJob(job, true, QStringLiteral("imported %1").arg(program));
                             function_model_->setProgram(program);
                             navigation_->setProgram(program);
                         });
    }

void MainWindow::openProgram() {
        const int job = beginJob(QStringLiteral("open program"));
        const QString program = program_edit_->text();
        bridge_->request(QJsonObject{{"method", "open"}, {"program", program}},
                         [this, job, program](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             finishJob(job, true, QStringLiteral("opened %1").arg(program));
                             function_model_->setProgram(program);
                             navigation_->setProgram(program);
                         });
    }

void MainWindow::decompile() {
        const int job = beginJob(QStringLiteral("decompile %1").arg(address_edit_->text()));
        bridge_->request(QJsonObject{{"method", "decompile_doc"},
                                     {"binary", binary_edit_->text()},
                                     {"program", program_edit_->text()},
                                     {"address", address_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                            const QJsonObject result = response.value("result").toObject();
                            const QJsonArray tokens = result.value("tokens").toArray();
                            QVector<TokenView> views;
                            views.reserve(tokens.size());
                            for (const QJsonValue &token : tokens) {
                                views.append(TokenView::fromJson(token.toObject()));
                            }
                            decompiler_->setTokens(views);
                            finishJob(job, true,
                                      QStringLiteral("%1 tokens, revision %2")
                                          .arg(views.size())
                                          .arg(result.value("revision").toInteger()));
                         });
    }

void MainWindow::loadListing() {
    loadListingAt(address_edit_->text());
}

void MainWindow::loadListingAt(const QString &address) {
    if (address.isEmpty() || binary_edit_->text().isEmpty()) {
        return;
    }
    const int job = beginJob(QStringLiteral("listing %1").arg(address));
    bridge_->request(QJsonObject{{"method", "listing"},
                                 {"binary", binary_edit_->text()},
                                 {"start", address},
                                 {"count", 128}},
                     [this, job, address](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishJob(job, false, error);
                             return;
                         }
                         const QJsonArray rows =
                             response.value("result").toObject().value("rows").toArray();
                         QVector<ListingRowView> views;
                         views.reserve(rows.size());
                         for (const QJsonValue &row : rows) {
                             views.append(ListingRowView::fromJson(row.toObject()));
                         }
                         listing_canvas_->setWindow(views);
                         listing_canvas_->setAddress(address);
                         finishJob(job, true, QStringLiteral("listing loaded"));
                     });
}

void MainWindow::listingContextMenu(const QPoint &global_pos, const QString &address) {
    QMenu menu(this);
    menu.addAction(QStringLiteral("Rename…"), this, [this, address]() {
        address_edit_->setText(address);
        name_edit_->setFocus();
        renameFunctionAt(address, name_edit_->text());
    });
    menu.addAction(QStringLiteral("Add comment…"), this, [this, address]() {
        address_edit_->setText(address);
        applyComment();
    });
    menu.addAction(QStringLiteral("Show xrefs"), this, [this, address]() {
        address_edit_->setText(address);
        loadXrefs();
    });
    menu.addAction(QStringLiteral("Decompile here"), this, [this, address]() {
        address_edit_->setText(address);
        decompile();
    });
    menu.exec(global_pos);
}

void MainWindow::loadXrefs() {
        const int job = beginJob(QStringLiteral("xrefs %1").arg(address_edit_->text()));
        bridge_->request(QJsonObject{{"method", "xrefs_page"},
                                     {"program", program_edit_->text()},
                                     {"address", address_edit_->text()},
                                     {"incoming", true},
                                     {"offset", 0},
                                     {"limit", 256}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows =
                                 response.value("result").toObject().value("rows").toArray();
                             xrefs_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = xrefs_->rowCount();
                                 xrefs_->insertRow(index);
                                 xrefs_->setItem(index, 0,
                                                 new QTableWidgetItem(addressText(row.value("from"))));
                                 xrefs_->setItem(index, 1,
                                                 new QTableWidgetItem(row.value("kind").toString()));
                                 xrefs_->setItem(index, 2,
                                                 new QTableWidgetItem(addressText(row.value("to"))));
                             }
                             finishJob(job, true,
                                       QStringLiteral("%1 incoming xrefs").arg(rows.size()));
                         });
    }

void MainWindow::loadFacts() {
        const QString program = program_edit_->text();
        int job = beginJob(QStringLiteral("symbols"));
        bridge_->request(QJsonObject{{"method", "symbols_page"},
                                     {"program", program},
                                     {"offset", 0},
                                     {"limit", 256}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows =
                                 response.value("result").toObject().value("rows").toArray();
                             symbols_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = symbols_->rowCount();
                                 symbols_->insertRow(index);
                                 symbols_->setItem(index, 0,
                                                   new QTableWidgetItem(addressText(row.value("address"))));
                                 symbols_->setItem(index, 1,
                                                   new QTableWidgetItem(row.value("name").toString()));
                                 symbols_->setItem(index, 2,
                                                   new QTableWidgetItem(row.value("source").toString()));
                                 symbols_->setItem(index, 3,
                                                   new QTableWidgetItem(
                                                       row.value("external").toBool() ? "yes" : "no"));
                             }
                             finishJob(job, true, QStringLiteral("%1 symbols").arg(rows.size()));
                         });

        job = beginJob(QStringLiteral("strings"));
        bridge_->request(QJsonObject{{"method", "strings"}, {"program", program}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             strings_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = strings_->rowCount();
                                 strings_->insertRow(index);
                                 strings_->setItem(index, 0,
                                                   new QTableWidgetItem(addressText(row.value("address"))));
                                 strings_->setItem(index, 1,
                                                   new QTableWidgetItem(row.value("kind").toString()));
                                 strings_->setItem(index, 2,
                                                   new QTableWidgetItem(row.value("value").toString()));
                             }
                             finishJob(job, true, QStringLiteral("%1 strings").arg(rows.size()));
                         });

        job = beginJob(QStringLiteral("search"));
        bridge_->request(QJsonObject{{"method", "search"},
                                     {"program", program},
                                     {"term", search_edit_->text()},
                                     {"limit", 256}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             search_results_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = search_results_->rowCount();
                                 search_results_->insertRow(index);
                                 search_results_->setItem(index, 0,
                                                   new QTableWidgetItem(addressText(row.value("address"))));
                                 search_results_->setItem(index, 1,
                                                   new QTableWidgetItem(row.value("kind").toString()));
                                 search_results_->setItem(index, 2,
                                                   new QTableWidgetItem(row.value("name").toString()));
                                 search_results_->setItem(index, 3,
                                                   new QTableWidgetItem(row.value("context").toString()));
                             }
                             finishJob(job, true,
                                       QStringLiteral("%1 search hits").arg(rows.size()));
                         });
    }

void MainWindow::loadMemory() {
        const int job = beginJob(QStringLiteral("memory map"));
        bridge_->request(QJsonObject{{"method", "memory_regions"},
                                     {"program", program_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             memory_regions_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = memory_regions_->rowCount();
                                 memory_regions_->insertRow(index);
                                 memory_regions_->setItem(index, 0,
                                                   new QTableWidgetItem(row.value("name").toString()));
                                 memory_regions_->setItem(index, 1,
                                                   new QTableWidgetItem(addressText(row.value("start"))));
                                 memory_regions_->setItem(index, 2,
                                                   new QTableWidgetItem(
                                                       QStringLiteral("0x%1")
                                                           .arg(row.value("size").toInteger(), 0, 16)));
                                 memory_regions_->setItem(index, 3,
                                                   new QTableWidgetItem(
                                                       row.value("permissions").toString()));
                                 memory_regions_->setItem(index, 4,
                                                   new QTableWidgetItem(row.value("source").toString()));
                             }
                             finishJob(job, true,
                                       QStringLiteral("%1 memory regions").arg(rows.size()));
                             loadHex();
                         });
    }

void MainWindow::loadHex() {
        const int job = beginJob(QStringLiteral("hex %1").arg(address_edit_->text()));
        bridge_->request(QJsonObject{{"method", "memory"},
                                     {"binary", binary_edit_->text()},
                                     {"address", address_edit_->text()},
                                     {"size", 128}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonObject result = response.value("result").toObject();
                             const QString bytes = result.value("bytes_hex").toString();
                             QString output;
                             for (int offset = 0; offset < bytes.size(); offset += 32) {
                                 output += QStringLiteral("%1  %2\n")
                                               .arg(address_edit_->text())
                                               .arg(bytes.mid(offset, 32).toUpper());
                             }
                             hex_view_->setPlainText(output);
                             finishJob(job, true,
                                       QStringLiteral("%1 bytes").arg(bytes.size() / 2));
                         });
    }

void MainWindow::loadGraph() {
        const int job = beginJob(QStringLiteral("function graph"));
        bridge_->request(QJsonObject{{"method", "function_graph"},
                                     {"program", program_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             graph_canvas_->setGraph(response.value("result").toObject());
                             finishJob(job, true, QStringLiteral("graph loaded"));
                         });
    }

void MainWindow::loadAnalystData() {
        const int job = beginJob(QStringLiteral("bookmarks"));
        bridge_->request(QJsonObject{{"method", "bookmarks"},
                                     {"program", program_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             bookmarks_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = bookmarks_->rowCount();
                                 bookmarks_->insertRow(index);
                                 bookmarks_->setItem(index, 0,
                                                      new QTableWidgetItem(addressText(row.value("address"))));
                                 bookmarks_->setItem(index, 1,
                                                      new QTableWidgetItem(row.value("label").toString()));
                                 bookmarks_->setItem(index, 2,
                                                      new QTableWidgetItem(row.value("comment").toString()));
                             }
                             finishJob(job, true,
                                       QStringLiteral("%1 bookmarks").arg(rows.size()));
                         });
        const int patch_job = beginJob(QStringLiteral("patches"));
        bridge_->request(QJsonObject{{"method", "patches"},
                                     {"program", program_edit_->text()}},
                         [this, patch_job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(patch_job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             patches_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = patches_->rowCount();
                                 patches_->insertRow(index);
                                 patches_->setItem(index, 0,
                                                   new QTableWidgetItem(addressText(row.value("address"))));
                                 patches_->setItem(index, 1,
                                                   new QTableWidgetItem(
                                                       bytesText(row.value("original").toArray())));
                                 patches_->setItem(index, 2,
                                                   new QTableWidgetItem(
                                                       bytesText(row.value("patched").toArray())));
                                 patches_->setItem(index, 3,
                                                   new QTableWidgetItem(
                                                       row.value("enabled").toBool() ? "yes" : "no"));
                             }
                             finishJob(patch_job, true,
                                       QStringLiteral("%1 patches").arg(rows.size()));
                         });
    }

void MainWindow::setBookmark() {
        const int job = beginJob(QStringLiteral("set bookmark"));
        bridge_->request(
            QJsonObject{{"method", "set_bookmark"},
                        {"program", program_edit_->text()},
                        {"bookmark",
                         QJsonObject{{"address", address_edit_->text()},
                                     {"label", bookmark_edit_->text()},
                                     {"comment", comment_edit_->text()}}}},
            [this, job](const QJsonObject &response) {
                QString error;
                if (!successful(response, &error)) {
                    finishJob(job, false, error);
                    return;
                }
                loadAnalystData();
                finishJob(job, true, QStringLiteral("bookmark committed"));
            });
    }

void MainWindow::setPatch() {
        const int job = beginJob(QStringLiteral("set patch"));
        bridge_->request(
            QJsonObject{{"method", "set_patch"},
                        {"program", program_edit_->text()},
                        {"address", address_edit_->text()},
                        {"original", bytesFromText(patch_original_edit_->text())},
                        {"patched", bytesFromText(patch_new_edit_->text())},
                        {"enabled", true}},
            [this, job](const QJsonObject &response) {
                QString error;
                if (!successful(response, &error)) {
                    finishJob(job, false, error);
                    return;
                }
                loadAnalystData();
                finishJob(job, true, QStringLiteral("patch committed"));
            });
    }


void MainWindow::loadTypes() {
        const QString program = program_edit_->text();
        const int type_job = beginJob(QStringLiteral("types"));
        bridge_->request(QJsonObject{{"method", "type_defs"}, {"program", program}},
                         [this, type_job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(type_job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             types_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = types_->rowCount();
                                 types_->insertRow(index);
                                 types_->setItem(index, 0,
                                                 new QTableWidgetItem(row.value("name").toString()));
                                 types_->setItem(index, 1,
                                                 new QTableWidgetItem(row.value("kind").toString()));
                                 types_->setItem(
                                     index, 2,
                                     new QTableWidgetItem(row.value("definition").toString()));
                                 types_->setItem(
                                     index, 3,
                                     new QTableWidgetItem(
                                         row.value("size").isNull()
                                             ? QString()
                                             : QString::number(row.value("size").toInteger())));
                                 types_->setItem(
                                     index, 4,
                                     new QTableWidgetItem(
                                         row.value("alignment").isNull()
                                             ? QString()
                                             : QString::number(
                                                   row.value("alignment").toInteger())));
                                 types_->setItem(index, 5,
                                                 new QTableWidgetItem(
                                                     row.value("base_type").toString()));
                                 types_->setItem(index, 6,
                                                 new QTableWidgetItem(
                                                     row.value("provenance").toString()));
                             }
                             finishJob(type_job, true,
                                       QStringLiteral("%1 types").arg(rows.size()));
                         });

        const int field_job = beginJob(QStringLiteral("type fields"));
        bridge_->request(QJsonObject{{"method", "type_fields"}, {"program", program}},
                         [this, field_job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(field_job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             type_fields_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = type_fields_->rowCount();
                                 type_fields_->insertRow(index);
                                 type_fields_->setItem(
                                     index, 0,
                                     new QTableWidgetItem(row.value("type_name").toString()));
                                 type_fields_->setItem(
                                     index, 1,
                                     new QTableWidgetItem(
                                         QString::number(row.value("ordinal").toInteger())));
                                 type_fields_->setItem(
                                     index, 2,
                                     new QTableWidgetItem(row.value("field_name").toString()));
                                 type_fields_->setItem(
                                     index, 3,
                                     new QTableWidgetItem(
                                         QString::number(row.value("offset").toInteger())));
                                 type_fields_->setItem(
                                     index, 4,
                                     new QTableWidgetItem(
                                         row.value("size").isNull()
                                             ? QString()
                                             : QString::number(row.value("size").toInteger())));
                                 type_fields_->setItem(
                                     index, 5,
                                     new QTableWidgetItem(row.value("type_ref").toString()));
                             }
                             finishJob(field_job, true,
                                       QStringLiteral("%1 fields").arg(rows.size()));
                         });

        const int prototype_job = beginJob(QStringLiteral("prototypes"));
        bridge_->request(QJsonObject{{"method", "prototypes"}, {"program", program}},
                         [this, prototype_job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(prototype_job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             prototypes_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = prototypes_->rowCount();
                                 prototypes_->insertRow(index);
                                 prototypes_->setItem(
                                     index, 0,
                                     new QTableWidgetItem(addressText(row.value("function"))));
                                 prototypes_->setItem(
                                     index, 1,
                                     new QTableWidgetItem(row.value("signature").toString()));
                                 prototypes_->setItem(
                                     index, 2,
                                     new QTableWidgetItem(
                                         row.value("calling_convention").toString()));
                                 prototypes_->setItem(
                                     index, 3,
                                     new QTableWidgetItem(row.value("return_type").toString()));
                             }
                             finishJob(prototype_job, true,
                                       QStringLiteral("%1 prototypes").arg(rows.size()));
                         });

        const int stack_job = beginJob(QStringLiteral("stack variables"));
        bridge_->request(QJsonObject{{"method", "stack_variables"}, {"program", program}},
                         [this, stack_job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(stack_job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result").toArray();
                             stack_variables_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = stack_variables_->rowCount();
                                 stack_variables_->insertRow(index);
                                 stack_variables_->setItem(
                                     index, 0,
                                     new QTableWidgetItem(addressText(row.value("function"))));
                                 stack_variables_->setItem(
                                     index, 1,
                                     new QTableWidgetItem(
                                         QString::number(row.value("ordinal").toInteger())));
                                 stack_variables_->setItem(
                                     index, 2,
                                     new QTableWidgetItem(row.value("name").toString()));
                                 stack_variables_->setItem(
                                     index, 3,
                                     new QTableWidgetItem(row.value("storage").toString()));
                                 stack_variables_->setItem(
                                     index, 4,
                                     new QTableWidgetItem(row.value("type_name").toString()));
                                 stack_variables_->setItem(
                                     index, 5,
                                     new QTableWidgetItem(
                                         row.value("offset").isNull()
                                             ? QString()
                                             : QString::number(row.value("offset").toInteger())));
                                 stack_variables_->setItem(
                                     index, 6,
                                     new QTableWidgetItem(
                                         row.value("size").isNull()
                                             ? QString()
                                             : QString::number(row.value("size").toInteger())));
                             }
                             finishJob(stack_job, true,
                                       QStringLiteral("%1 stack variables").arg(rows.size()));
                         });

        const int graph_job = beginJob(QStringLiteral("type graph"));
        bridge_->request(QJsonObject{{"method", "type_graph"}, {"program", program}},
                         [this, graph_job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(graph_job, false, error);
                                 return;
                             }
                             const QJsonArray rows =
                                 response.value("result").toObject().value("edges").toArray();
                             type_links_->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = type_links_->rowCount();
                                 type_links_->insertRow(index);
                                 type_links_->setItem(
                                     index, 0,
                                     new QTableWidgetItem(row.value("source").toString()));
                                 type_links_->setItem(
                                     index, 1,
                                     new QTableWidgetItem(row.value("target").toString()));
                                 type_links_->setItem(
                                     index, 2,
                                     new QTableWidgetItem(row.value("kind").toString()));
                                 type_links_->setItem(
                                     index, 3,
                                     new QTableWidgetItem(row.value("provenance").toString()));
                             }
                             finishJob(graph_job, true,
                                       QStringLiteral("%1 type links").arg(rows.size()));
                         });
    }

void MainWindow::saveTypeDefinition() {
        if (type_name_edit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("type name is required"), true);
            return;
        }
        const int job = beginJob(QStringLiteral("save type"));
        bridge_->request(
            QJsonObject{
                {"method", "set_type_def"},
                {"program", program_edit_->text()},
                {"row", QJsonObject{
                            {"name", type_name_edit_->text()},
                            {"kind", type_kind_edit_->text()},
                            {"definition", type_definition_edit_->text()},
                            {"size", optionalInteger(type_size_edit_->text())},
                            {"alignment", optionalInteger(type_alignment_edit_->text())},
                            {"base_type", type_base_edit_->text().isEmpty()
                                              ? QJsonValue(QJsonValue::Null)
                                              : QJsonValue(type_base_edit_->text())},
                            {"provenance", "ui"}}}},
            [this, job](const QJsonObject &response) {
                QString error;
                if (!successful(response, &error)) {
                    finishJob(job, false, error);
                    return;
                }
                loadTypes();
                finishJob(job, true, QStringLiteral("type saved"));
            });
    }

void MainWindow::saveTypeField() {
        if (type_name_edit_->text().trimmed().isEmpty() ||
            field_name_edit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("type and field names are required"), true);
            return;
        }
        const int job = beginJob(QStringLiteral("save type field"));
        bridge_->request(
            QJsonObject{
                {"method", "set_type_field"},
                {"program", program_edit_->text()},
                {"row", QJsonObject{
                            {"type_name", type_name_edit_->text()},
                            {"ordinal", optionalInteger(field_ordinal_edit_->text())},
                            {"field_name", field_name_edit_->text()},
                            {"offset", optionalInteger(field_offset_edit_->text())},
                            {"size", optionalInteger(field_size_edit_->text())},
                            {"type_ref", field_type_edit_->text().isEmpty()
                                             ? QJsonValue(QJsonValue::Null)
                                             : QJsonValue(field_type_edit_->text())}}}},
            [this, job](const QJsonObject &response) {
                QString error;
                if (!successful(response, &error)) {
                    finishJob(job, false, error);
                    return;
                }
                loadTypes();
                finishJob(job, true, QStringLiteral("type field saved"));
            });
    }

void MainWindow::savePrototype() {
        const int job = beginJob(QStringLiteral("save prototype"));
        bridge_->request(
            QJsonObject{{"method", "set_prototype"},
                        {"program", program_edit_->text()},
                        {"row", QJsonObject{
                                    {"function", address_edit_->text()},
                                    {"signature", prototype_signature_edit_->text()},
                                    {"calling_convention", calling_convention_edit_->text()
                                                               .isEmpty()
                                                           ? QJsonValue(QJsonValue::Null)
                                                           : QJsonValue(
                                                                 calling_convention_edit_->text())},
                                    {"return_type", QJsonValue(QJsonValue::Null)}}}},
            [this, job](const QJsonObject &response) {
                QString error;
                if (!successful(response, &error)) {
                    finishJob(job, false, error);
                    return;
                }
                loadTypes();
                finishJob(job, true, QStringLiteral("prototype saved"));
            });
    }

void MainWindow::saveStackVariable() {
        const int job = beginJob(QStringLiteral("save stack variable"));
        bridge_->request(
            QJsonObject{
                {"method", "set_stack_variable"},
                {"program", program_edit_->text()},
                {"row", QJsonObject{
                            {"function", address_edit_->text()},
                            {"ordinal", optionalInteger(field_ordinal_edit_->text())},
                            {"name", stack_name_edit_->text()},
                            {"storage", stack_storage_edit_->text()},
                            {"type_name", stack_type_edit_->text().isEmpty()
                                              ? QJsonValue(QJsonValue::Null)
                                              : QJsonValue(stack_type_edit_->text())},
                            {"offset", optionalInteger(stack_offset_edit_->text())},
                            {"size", optionalInteger(stack_size_edit_->text())}}}},
            [this, job](const QJsonObject &response) {
                QString error;
                if (!successful(response, &error)) {
                    finishJob(job, false, error);
                    return;
                }
                loadTypes();
                finishJob(job, true, QStringLiteral("stack variable saved"));
            });
    }

void MainWindow::propagateTypes() {
        const int job = beginJob(QStringLiteral("propagate types"));
        bridge_->request(QJsonObject{{"method", "propagate_type_links"},
                                     {"program", program_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             loadTypes();
                             finishJob(job, true,
                                       QStringLiteral("%1 type links")
                                           .arg(response.value("result").toArray().size()));
                         });
    }

void MainWindow::renameFunction() {
    renameFunctionAt(address_edit_->text(), name_edit_->text());
}

void MainWindow::renameFunctionAt(const QString &address, const QString &name) {
    if (address.isEmpty() || name.trimmed().isEmpty()) {
        setStatus(QStringLiteral("address and new name are required"), true);
        return;
    }
    const int job = beginJob(QStringLiteral("rename %1").arg(address));
    bridge_->request(QJsonObject{{"method", "rename"},
                                 {"program", program_edit_->text()},
                                 {"address", address},
                                 {"name", name}},
                     [this, job, address](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishJob(job, false, error);
                             return;
                         }
                         function_model_->refresh();
                         finishJob(job, true, QStringLiteral("renamed %1").arg(address));
                     });
}

void MainWindow::applyComment() {
        const int job = beginJob(QStringLiteral("comment %1").arg(address_edit_->text()));
        bridge_->request(QJsonObject{{"method", "comment"},
                                     {"program", program_edit_->text()},
                                     {"address", address_edit_->text()},
                                     {"kind", comment_kind_edit_->text()},
                                     {"text", comment_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             finishJob(job, true, QStringLiteral("comment committed"));
                         });
    }

void MainWindow::undoCommand() {
        const int job = beginJob(QStringLiteral("undo"));
        bridge_->request(QJsonObject{{"method", "undo"},
                                     {"program", program_edit_->text()}},
                         [this, job](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             function_model_->refresh();
                             finishJob(job, true,
                                       response.value("result").toObject().value("message").toString());
                         });
    }

int MainWindow::beginJob(const QString &label) {
        jobs_->addItem(label + QStringLiteral(" — running"));
        jobs_->scrollToBottom();
        return jobs_->count() - 1;
    }

void MainWindow::finishJob(int index, bool ok, const QString &detail) {
        if (auto *item = jobs_->item(index)) {
            item->setText((ok ? QStringLiteral("PASS ") : QStringLiteral("FAIL ")) + detail);
        }
        setStatus(detail, !ok);
    }

void MainWindow::setStatus(const QString &message, bool error) {
        status_->setText(message);
        status_->setStyleSheet(error ? QStringLiteral("color:#e06c75")
                                     : QStringLiteral("color:#98c379"));
    }

void MainWindow::restoreWorkspace() {
        QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
        const QByteArray geometry = settings.value(QStringLiteral("geometry")).toByteArray();
        const QByteArray state = settings.value(QStringLiteral("state")).toByteArray();
        if (!geometry.isEmpty()) {
            restoreGeometry(geometry);
        }
        if (!state.isEmpty()) {
            restoreState(state);
        }
    }

void MainWindow::saveWorkspace() {
        QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
        settings.setValue(QStringLiteral("geometry"), saveGeometry());
        settings.setValue(QStringLiteral("state"), saveState());
    }
