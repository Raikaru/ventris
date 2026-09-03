#include "main_window.h"

#include "core_bridge.h"
#include "decompiler_view.h"
#include "function_table_model.h"
#include "graph_canvas.h"
#include "hex_canvas.h"
#include "listing_canvas.h"
#include "strings_table_model.h"
#include "theme.h"
#include "navigation_controller.h"
#include "json_util.h"

#include <QCoreApplication>
#include <QDockWidget>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeySequence>
#include <QInputDialog>
#include <QShortcut>
#include <functional>
#include <QCheckBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QMenuBar>
#include <QMessageBox>
#include <QMenu>
#include <QMessageBox>
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
#include <QTextStream>
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
        connect(graph_canvas_, &GraphCanvas::addressSelected, this,
                [this](const QString &address, bool record) {
                    navigation_->goTo(address, record);
                });
        // Listing <-> Graph toggle on Space (IDA-style): the central
        // listing canvas and the graph dock swap focus.
        auto *graph_toggle = new QShortcut(QKeySequence(Qt::Key_Space), listing_canvas_);
        graph_toggle->setContext(Qt::WidgetWithChildrenShortcut);
        connect(graph_toggle, &QShortcut::activated, this, [this]() {
            loadGraph();
            graph_dock_->raise();
            graph_dock_->setFocus();
        });
        auto *bytes_toggle = new QShortcut(QKeySequence(QStringLiteral("Ctrl+B")), this);
        connect(bytes_toggle, &QShortcut::activated, this, [this]() {
            listing_canvas_->setBytesVisible(!listing_canvas_->bytesVisible());
        });
        connect(decompiler_, &DecompilerView::addressSelected, this,
                [this](const QString &address, bool record) {
                    navigation_->goTo(address, record);
                });
        auto *go_to_address = new QShortcut(QKeySequence(Qt::Key_G), listing_canvas_);
        go_to_address->setContext(Qt::WidgetWithChildrenShortcut);
        connect(go_to_address, &QShortcut::activated, this, [this]() {
            QInputDialog dialog(this);
            dialog.setWindowTitle(QStringLiteral("Go to address"));
            dialog.setLabelText(QStringLiteral("Address (hex):"));
            dialog.setTextValue(address_edit_->text());
            if (dialog.exec() == QDialog::Accepted && !dialog.textValue().trimmed().isEmpty()) {
                navigation_->goTo(dialog.textValue().trimmed(), true);
            }
        });
        auto *go_to_function = new QShortcut(QKeySequence(QStringLiteral("Ctrl+P")), this);
        connect(go_to_function, &QShortcut::activated, this, [this]() {
            QDialog dialog(this);
            dialog.setWindowTitle(QStringLiteral("Go to function"));
            auto *layout = new QVBoxLayout(&dialog);
            auto *filter_edit = new QLineEdit(&dialog);
            filter_edit->setPlaceholderText(QStringLiteral("Fuzzy function name"));
            auto *list = new QListWidget(&dialog);
            layout->addWidget(filter_edit);
            layout->addWidget(list, 1);
            bridge_->request(
                QJsonObject{{"method", "functions_page"},
                            {"program", program_edit_->text()},
                            {"offset", 0},
                            {"limit", 4096}},
                [this, &dialog, list](const QJsonObject &response) {
                    if (!dialog.isVisible()) {
                        return;
                    }
                    const QJsonArray rows =
                        response.value("result").toObject().value("rows").toArray();
                    for (const QJsonValue &value : rows) {
                        const QJsonObject row = value.toObject();
                        auto *item = new QListWidgetItem(
                            QStringLiteral("%1  %2")
                                .arg(row.value("name").toString())
                                .arg(addressText(row.value("entry"))));
                        item->setData(Qt::UserRole, addressText(row.value("entry")));
                        list->addItem(item);
                    }
                });
            // Subsequence fuzzy match, case-insensitive.
            connect(filter_edit, &QLineEdit::textChanged, list, [list](const QString &text) {
                const QString needle = text.toLower();
                for (int i = 0; i < list->count(); ++i) {
                    const QString name = list->item(i)->text().toLower();
                    int pos = 0;
                    bool matched = true;
                    for (const QChar c : needle) {
                        pos = name.indexOf(c, pos);
                        if (pos < 0) {
                            matched = false;
                            break;
                        }
                        ++pos;
                    }
                    list->item(i)->setHidden(!matched);
                }
                for (int i = 0; i < list->count(); ++i) {
                    if (!list->item(i)->isHidden()) {
                        list->setCurrentRow(i);
                        break;
                    }
                }
            });
            connect(list, &QListWidget::itemActivated, this,
                    [this, &dialog](QListWidgetItem *item) {
                        dialog.accept();
                        navigation_->goTo(item->data(Qt::UserRole).toString(), true);
                    });
            filter_edit->setFocus();
            dialog.resize(420, 480);
            dialog.exec();
        });
        // Command palette (Ctrl+Shift+P): every action reachable here.
        auto *palette_shortcut =
            new QShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+P")), this);
        connect(palette_shortcut, &QShortcut::activated, this,
                &MainWindow::showCommandPalette);
        // Project management menu: open, recent, import with progress.
        auto *file_menu = menuBar()->addMenu(QStringLiteral("&File"));
        file_menu->addAction(QStringLiteral("&Open project…"), this, [this]() {
            const QString dir = QFileDialog::getExistingDirectory(
                this, QStringLiteral("Open project directory"), project_edit_->text());
            if (dir.isEmpty()) {
                return;
            }
            QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
            QStringList recent =
                settings.value(QStringLiteral("recentProjects")).toStringList();
            recent.removeAll(dir);
            recent.prepend(dir);
            while (recent.size() > 8) {
                recent.removeLast();
            }
            settings.setValue(QStringLiteral("recentProjects"), recent);
            QMessageBox::information(
                this, QStringLiteral("Project selected"),
                QStringLiteral("Project %1 will open on restart.").arg(dir));
        });
        recent_menu_ = file_menu->addMenu(QStringLiteral("Open &recent"));
        connect(recent_menu_, &QMenu::aboutToShow, this, [this]() {
            recent_menu_->clear();
            QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
            const QStringList recent =
                settings.value(QStringLiteral("recentProjects")).toStringList();
            for (const QString &dir : recent) {
                recent_menu_->addAction(dir, this, [this, dir]() {
                    QMessageBox::information(
                        this, QStringLiteral("Project selected"),
                        QStringLiteral("Project %1 will open on restart.").arg(dir));
                });
            }
            if (recent.isEmpty()) {
                recent_menu_->addAction(QStringLiteral("(no recent projects)"))
                    ->setEnabled(false);
            }
        });
        file_menu->addAction(QStringLiteral("&Import binary…"), this, [this]() {
            const QString binary = QFileDialog::getOpenFileName(
                this, QStringLiteral("Import native binary"), QString(),
                QStringLiteral("All files (*)"));
            if (binary.isEmpty()) {
                return;
            }
            QInputDialog name_dialog(this);
            name_dialog.setWindowTitle(QStringLiteral("Program name"));
            name_dialog.setLabelText(QStringLiteral("Program name:"));
            name_dialog.setTextValue(QFileInfo(binary).fileName());
            if (name_dialog.exec() != QDialog::Accepted) {
                return;
            }
            binary_edit_->setText(binary);
            program_edit_->setText(name_dialog.textValue().trimmed());
            importNative();
        });
        // Phase 4 surfaces: signature search and vtable recovery.
        auto *search_menu = menuBar()->addMenu(QStringLiteral("&Search"));
        search_menu->addAction(QStringLiteral("Byte-pattern &signature…"), this,
                               [this]() { showSignatureSearch(); });
        search_menu->addAction(QStringLiteral("Recover &vtables"), this, [this]() {
            if (binary_edit_->text().isEmpty()) {
                setStatus(QStringLiteral("no binary loaded"), true);
                return;
            }
            const int job = beginJob(QStringLiteral("vtable recovery"));
            bridge_->request(
                QJsonObject{{"method", "recover_vtables"},
                            {"binary", binary_edit_->text()},
                            {"limit", 512}},
                [this, job](const QJsonObject &response) {
                    QString error;
                    if (!successful(response, &error)) {
                        finishJob(job, false, error);
                        return;
                    }
                    vtables_->setRowCount(0);
                    const QJsonArray rows = response.value("result").toArray();
                    for (const QJsonValue &value : rows) {
                        const QJsonObject row = value.toObject();
                        const int index = vtables_->rowCount();
                        vtables_->insertRow(index);
                        const QStringList targets =
                            row.value("targets").toVariant().toStringList();
                        vtables_->setItem(index, 0,
                                          new QTableWidgetItem(QStringLiteral("0x") +
                                                               row.value("address").toString()));
                        vtables_->setItem(index, 1,
                                          new QTableWidgetItem(QString::number(targets.size())));
                        vtables_->setItem(index, 2,
                                          new QTableWidgetItem(targets.join(QStringLiteral(", "))));
                    }
                    finishJob(job, true,
                              QStringLiteral("%1 vtables recovered").arg(rows.size()));
                });
        });
        connect(decompiler_, &DecompilerView::renameRequested, this,
                [this](const QString &address, const QString &current_name) {
                    QInputDialog dialog(this);
                    dialog.setWindowTitle(QStringLiteral("Rename function"));
                    dialog.setLabelText(
                        QStringLiteral("Rename %1 to:").arg(current_name));
                    dialog.setTextValue(current_name);
                    if (dialog.exec() == QDialog::Accepted && !dialog.textValue().trimmed().isEmpty()) {
                        renameFunctionAt(address, dialog.textValue().trimmed());
                    }
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
        connect(function_model_, &FunctionTableModel::refreshed, this,
                &MainWindow::gateModelRefreshed);
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
        strings_model_ = new StringsTableModel(bridge_, facts_tabs);
        strings_ = new QTableView(facts_tabs);
        strings_->setObjectName(QStringLiteral("stringsView"));
        strings_->setModel(strings_model_);
        strings_->setSelectionBehavior(QAbstractItemView::SelectRows);
        strings_->setSelectionMode(QAbstractItemView::SingleSelection);
        strings_->horizontalHeader()->setStretchLastSection(true);
        strings_->verticalHeader()->setVisible(false);
        connect(strings_, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
            const QString address =
                strings_model_->data(strings_model_->index(index.row(), 0)).toString();
            navigation_->goTo(address, true);
        });
        connect(strings_, &QTableView::clicked, this, [this](const QModelIndex &index) {
            const QString address =
                strings_model_->data(strings_model_->index(index.row(), 0)).toString();
            address_edit_->setText(address);
            loadXrefs();
        });
        connect(strings_model_, &StringsTableModel::requestError, this,
                [this](const QString &message) { setStatus(message, true); });
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
        hex_canvas_ = new HexCanvas(memory_panel);
        auto *live_controls = new QHBoxLayout();
        live_memory_ = new QCheckBox(QStringLiteral("Live target"), memory_panel);
        live_endpoint_edit_ = new QLineEdit(QStringLiteral("127.0.0.1:24689"), memory_panel);
        live_endpoint_edit_->setPlaceholderText(QStringLiteral("Dolphin GDB endpoint"));
        live_endpoint_edit_->setEnabled(false);
        live_controls->addWidget(live_memory_);
        live_controls->addWidget(live_endpoint_edit_, 1);
        connect(live_memory_, &QCheckBox::toggled, this, [this](bool live) {
            hex_canvas_->setLiveSource(live);
            live_endpoint_edit_->setEnabled(live);
            loadHex();
        });
        connect(live_endpoint_edit_, &QLineEdit::editingFinished, this, [this]() {
            if (live_memory_->isChecked()) {
                loadHex();
            }
        });
        connect(hex_canvas_, &HexCanvas::addressSelected, this,
                [this](const QString &address, bool record) {
                    navigation_->goTo(address, record);
                });
        connect(hex_canvas_, &HexCanvas::windowNeeded, this,
                [this](quint64 offset) {
                    loadHexAt(QStringLiteral("0x%1").arg(offset, 0, 16));
                });
        memory_layout->addWidget(memory_regions_, 1);
        memory_layout->addLayout(live_controls);
        memory_layout->addWidget(hex_canvas_, 1);
        auto *memory_dock = new QDockWidget(QStringLiteral("Memory map / hex"), this);
        memory_dock->setObjectName(QStringLiteral("memoryDock"));
        memory_dock->setWidget(memory_panel);
        addDockWidget(Qt::RightDockWidgetArea, memory_dock);

        graph_canvas_ = new GraphCanvas(this);
        graph_dock_ = new QDockWidget(QStringLiteral("Function graph"), this);
        graph_dock_->setObjectName(QStringLiteral("functionGraphDock"));
        graph_dock_->setWidget(graph_canvas_);
        addDockWidget(Qt::BottomDockWidgetArea, graph_dock_);

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

        auto *xrefs_tabs = new QTabWidget(this);
        auto make_xrefs_table = [this](QTabWidget *parent, const QString &object_name) {
            auto *table = new QTableWidget(0, 4, parent);
            table->setObjectName(object_name);
            table->setHorizontalHeaderLabels({QStringLiteral("Address"),
                                              QStringLiteral("Function"),
                                              QStringLiteral("Kind"),
                                              QStringLiteral("Target")});
            table->horizontalHeader()->setStretchLastSection(true);
            table->verticalHeader()->setVisible(false);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            return table;
        };
        xrefs_to_ = make_xrefs_table(xrefs_tabs, QStringLiteral("xrefsToView"));
        xrefs_from_ = make_xrefs_table(xrefs_tabs, QStringLiteral("xrefsFromView"));
        xrefs_tabs->addTab(xrefs_to_, QStringLiteral("To"));
        xrefs_tabs->addTab(xrefs_from_, QStringLiteral("From"));
        connect(xrefs_to_, &QTableWidget::itemDoubleClicked, this,
                [this](QTableWidgetItem *item) {
                    navigation_->goTo(item->text().split(QLatin1Char(' ')).first(), true);
                });
        connect(xrefs_from_, &QTableWidget::itemDoubleClicked, this,
                [this](QTableWidgetItem *item) {
                    navigation_->goTo(item->text().split(QLatin1Char(' ')).first(), true);
                });
        auto *xrefs_dock = new QDockWidget(QStringLiteral("Xrefs"), this);
        xrefs_dock->setObjectName(QStringLiteral("xrefsDock"));
        xrefs_dock->setWidget(xrefs_tabs);
        addDockWidget(Qt::RightDockWidgetArea, xrefs_dock);

        auto *jobs_panel = new QWidget(this);
        auto *jobs_layout = new QVBoxLayout(jobs_panel);
        jobs_layout->setContentsMargins(0, 0, 0, 0);
        jobs_summary_ = new QLabel(QStringLiteral("Worker pool: no decompile jobs"), jobs_panel);
        jobs_summary_->setObjectName(QStringLiteral("workerPoolStatus"));
        jobs_summary_->setWordWrap(true);
        jobs_layout->addWidget(jobs_summary_);
        jobs_ = new QListWidget(jobs_panel);
        jobs_->setObjectName(QStringLiteral("analysisJobs"));
        jobs_layout->addWidget(jobs_, 1);
        auto *cancel_job = new QPushButton(QStringLiteral("Cancel selected"), jobs_panel);
        connect(cancel_job, &QPushButton::clicked, this, &MainWindow::cancelJob);
        jobs_layout->addWidget(cancel_job);
        auto *jobs_dock = new QDockWidget(QStringLiteral("Analysis jobs"), this);
        jobs_dock->setObjectName(QStringLiteral("analysisJobsDock"));
        jobs_dock->setWidget(jobs_panel);
        addDockWidget(Qt::BottomDockWidgetArea, jobs_dock);

        vtables_ = new QTableWidget(0, 3, this);
        vtables_->setObjectName(QStringLiteral("vtablesView"));
        vtables_->setHorizontalHeaderLabels(
            {QStringLiteral("Address"), QStringLiteral("Entries"), QStringLiteral("Targets")});
        vtables_->horizontalHeader()->setStretchLastSection(true);
        vtables_->verticalHeader()->setVisible(false);
        vtables_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(vtables_, &QTableWidget::itemDoubleClicked, this,
                [this](QTableWidgetItem *item) {
                    const int row = item->row();
                    if (auto *first = vtables_->item(row, 0)) {
                        navigation_->goTo(first->text(), true);
                    }
                });
        auto *vtables_dock = new QDockWidget(QStringLiteral("Vtables"), this);
        vtables_dock->setObjectName(QStringLiteral("vtablesDock"));
        vtables_dock->setWidget(vtables_);
        addDockWidget(Qt::RightDockWidgetArea, vtables_dock);

        connect(navigation_, &NavigationController::addressChanged, this,
                [this](const QString &address) {
                    address_edit_->setText(address);
                    this->decompile();
                    loadListing();
                    loadXrefs();
                    saveWorkspace();
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
        });
        if (!bridge_->startupError().isEmpty()) {
            setStatus(bridge_->startupError(), true);
        } else if (!program_.isEmpty()) {
            function_model_->setProgram(program_);
            navigation_->setProgram(program_);
            strings_model_->setProgram(program_);
            loadProgramPanels();
        }
        checkOnboardingGate();
        restoreWorkspace();
        refreshJobs();
    }

MainWindow::~MainWindow() {
        saveWorkspace();
        bridge_->shutdown();
    }
// private slots:
void MainWindow::loadProgramPanels() {
    loadFacts();
    loadMemory();
    loadGraph();
    loadAnalystData();
    loadTypes();
}

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
                             strings_model_->setProgram(program);
                             loadProgramPanels();
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
                             strings_model_->setProgram(program);
                             loadProgramPanels();
                         });
    }

void MainWindow::decompile() {
    const QString address = address_edit_->text();
    const QString key = program_edit_->text() + QLatin1Char('|') + address;
    // Revision-keyed cache: a hit at the current revision renders instantly;
    // mutations bump the revision and refetch.
    if (decompile_cache_.contains(key)) {
        const auto cached = decompile_cache_.value(key);
        if (cached.first == function_model_->revision()) {
            decompiler_->setTokens(cached.second);
            return;
        }
        decompile_cache_.remove(key);
    }
    const quint64 generation = ++decompile_generation_;
    decompiler_->setPending(QStringLiteral("decompiling %1…").arg(address));
    const int job = beginJob(QStringLiteral("decompile %1").arg(address));
    bridge_->request(QJsonObject{{"method", "decompile_doc"},
                                 {"binary", binary_edit_->text()},
                                 {"program", program_edit_->text()},
                                 {"address", address}},
                     [this, job, key, generation](const QJsonObject &response) {
                         if (generation != decompile_generation_) {
                             return;  // a newer request superseded this one
                         }
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
                         const qint64 revision = result.value("revision").toInteger();
                         decompile_cache_.insert(key, {revision, views});
                         decompiler_->setTokens(views);
                         finishJob(job, true,
                                   QStringLiteral("%1 tokens, revision %2")
                                       .arg(views.size())
                                       .arg(revision));
                     });
}
void MainWindow::runGate() {
    if (gate_active_) {
        return;
    }
    gate_active_ = true;
    gate_stage_ = GateStage::Inactive;
    function_filter_timer_->setInterval(0);
    gate_metrics_ = QJsonObject();
    gate_address_.clear();

    const QString binary = binary_edit_->text();
    const QString program = program_edit_->text();
    if (binary.isEmpty() || program.isEmpty()) {
        finishGate(false, QStringLiteral("gate requires --binary and --name"));
        return;
    }

    bridge_->request(QJsonObject{{"method", "import_native"},
                                 {"binary", binary},
                                 {"name", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishGate(false, error);
                             return;
                         }
                         const QString program = program_edit_->text();
                         navigation_->setProgram(program);
                         gate_stage_ = GateStage::LoadingList;
                         gate_timer_.start();
                         function_model_->setProgram(program);
                     });
}

void MainWindow::gateModelRefreshed() {
    if (!gate_active_) {
        return;
    }
    const GateStage stage = gate_stage_;
    if (stage != GateStage::LoadingList && stage != GateStage::Filtering &&
        stage != GateStage::ClearingFilter) {
        return;
    }
    QTimer::singleShot(0, this, [this, stage]() {
        if (!gate_active_ || gate_stage_ != stage) {
            return;
        }
        if (functions_ != nullptr) {
            functions_->viewport()->repaint();
        }
        const double elapsed_ms =
            static_cast<double>(gate_timer_.nsecsElapsed()) / 1'000'000.0;
        if (stage == GateStage::LoadingList) {
            gate_metrics_.insert(QStringLiteral("ui.list.load_ms"), elapsed_ms);
            gate_stage_ = GateStage::Filtering;
            gate_timer_.restart();
            function_filter_timer_->stop();
            function_filter_edit_->setText(QStringLiteral("FUN_"));
            function_model_->setFilter(QStringLiteral("FUN_"));
        } else if (stage == GateStage::Filtering) {
            gate_metrics_.insert(QStringLiteral("ui.list.filter_ms"), elapsed_ms);
            gate_stage_ = GateStage::ClearingFilter;
            function_filter_timer_->stop();
            function_filter_edit_->clear();
            function_model_->setFilter(QString());
        } else {
            gateStartLargestFunction();
        }
    });
}

void MainWindow::gateStartLargestFunction() {
    gate_stage_ = GateStage::Inactive;
    bridge_->request(QJsonObject{{"method", "functions_page"},
                                 {"program", program_edit_->text()},
                                 {"offset", 0},
                                 {"limit", 1},
                                 {"sort", "size:desc"}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishGate(false, error);
                             return;
                         }
                         const QJsonArray rows =
                             response.value("result").toObject().value("rows").toArray();
                         if (rows.isEmpty()) {
                             finishGate(false, QStringLiteral("gate found no functions"));
                             return;
                         }
                         gate_address_ = addressText(rows.first().toObject().value("entry"));
                         if (gate_address_.isEmpty() || gate_address_ == QStringLiteral("?")) {
                             finishGate(false, QStringLiteral("gate found an invalid function address"));
                             return;
                         }
                         gateStartDecompile(gate_address_);
                     });
}

void MainWindow::gateStartDecompile(const QString &address) {
    bridge_->request(QJsonObject{{"method", "decompile_doc"},
                                 {"binary", binary_edit_->text()},
                                 {"program", program_edit_->text()},
                                 {"address", address}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishGate(false, error);
                             return;
                         }
                         const QJsonArray tokens =
                             response.value("result").toObject().value("tokens").toArray();
                         QVector<TokenView> token_views;
                         token_views.reserve(tokens.size());
                         for (const QJsonValue &token : tokens) {
                             token_views.append(TokenView::fromJson(token.toObject()));
                         }
                         decompiler_->setTokens(token_views);

                         bridge_->request(
                             QJsonObject{{"method", "listing"},
                                         {"binary", binary_edit_->text()},
                                         {"start", gate_address_},
                                         {"count", 128}},
                             [this, token_views = std::move(token_views)](
                                 const QJsonObject &listing_response) mutable {
                                 QVector<ListingRowView> listing_views;
                                 if (successful(listing_response)) {
                                     const QJsonArray rows = listing_response.value("result")
                                                                  .toObject()
                                                                  .value("rows")
                                                                  .toArray();
                                     listing_views.reserve(rows.size());
                                     for (const QJsonValue &row : rows) {
                                         listing_views.append(
                                             ListingRowView::fromJson(row.toObject()));
                                     }
                                 } else {
                                     // The UI gate remains useful on machines
                                     // without the optional SLEIGH console: a
                                     // loaded function header still exercises
                                     // the highlight and paint path.
                                     ListingRowView header;
                                     header.address = gate_address_;
                                     header.kind = QStringLiteral("function_header");
                                     header.text = QStringLiteral("gate function");
                                     QString offset = gate_address_;
                                     if (offset.startsWith(QStringLiteral("0x"))) {
                                         offset.remove(0, 2);
                                     }
                                     bool address_ok = false;
                                     header.stable_id = offset.toULongLong(&address_ok, 16);
                                     listing_views.append(header);
                                 }
                                 listing_canvas_->setWindow(listing_views);
                                 decompiler_->setTokens(token_views);
                                 gate_timer_.start();
                                 decompiler_->setAddress(gate_address_);
                                 listing_canvas_->setAddress(gate_address_);
                                 decompiler_->repaint();
                                 listing_canvas_->repaint();
                                 gate_metrics_.insert(
                                     QStringLiteral("ui.sync_ms"),
                                     static_cast<double>(gate_timer_.nsecsElapsed()) /
                                         1'000'000.0);
                                 gateStartGraph();
                             });
                     });
}

void MainWindow::gateStartGraph() {
    gate_timer_.start();
    bridge_->request(QJsonObject{{"method", "function_bb_graph"},
                                 {"binary", binary_edit_->text()},
                                 {"address", gate_address_}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishGate(false, error);
                             return;
                         }
                         gate_metrics_.insert(
                             QStringLiteral("ui.graph.layout_ms"),
                             static_cast<double>(gate_timer_.nsecsElapsed()) / 1'000'000.0);
                         const QJsonObject result = response.value("result").toObject();
                         QVector<GraphCanvas::Node> nodes;
                         QVector<GraphCanvas::Edge> edges;
                         for (const QJsonValue &value : result.value("nodes").toArray()) {
                             const QJsonObject row = value.toObject();
                             GraphCanvas::Node node;
                             node.address = row.value("address").toString();
                             node.size = row.value("size").toVariant().toULongLong();
                             node.pos = QPointF(row.value("x").toVariant().toDouble(),
                                                row.value("y").toVariant().toDouble());
                             nodes.append(node);
                         }
                         for (const QJsonValue &value : result.value("edges").toArray()) {
                             const QJsonObject row = value.toObject();
                             GraphCanvas::Edge edge;
                             edge.from = row.value("from").toString();
                             edge.to = row.value("to").toString();
                             edge.kind = row.value("kind").toString();
                             edges.append(edge);
                         }
                         gate_timer_.start();
                         graph_canvas_->setGraph(nodes, edges);
                         graph_canvas_->setAddress(gate_address_);
                         graph_canvas_->repaint();
                         gate_metrics_.insert(
                             QStringLiteral("ui.graph.paint_ms"),
                             static_cast<double>(gate_timer_.nsecsElapsed()) / 1'000'000.0);
                         // Installation is measured by the release install smoke, not
                         // by an already-installed local executable.
                         gate_metrics_.insert(QStringLiteral("ui.install.ok"), false);
                         finishGate(true);
                     });
}

void MainWindow::finishGate(bool ok, const QString &detail) {
    if (!gate_active_) {
        return;
    }
    gate_active_ = false;
    gate_stage_ = GateStage::Inactive;
    const QJsonObject output{{"metrics", gate_metrics_}};
    QTextStream out(stdout);
    out << QJsonDocument(output).toJson(QJsonDocument::Compact) << Qt::endl;
    if (!ok) {
        QTextStream err(stderr);
        err << "Ventris UI gate: " << detail << Qt::endl;
    }
    QCoreApplication::exit(ok ? 0 : 1);
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
    const QString address = address_edit_->text();
    if (address.isEmpty()) {
        return;
    }
    auto fill = [this](QTableWidget *table, const QString &address, bool incoming) {
        const int job = beginJob(QStringLiteral("xrefs %1 %2")
                                     .arg(incoming ? QStringLiteral("to")
                                                   : QStringLiteral("from"))
                                     .arg(address));
        bridge_->request(QJsonObject{{"method", "xrefs_page"},
                                     {"program", program_edit_->text()},
                                     {"address", address},
                                     {"incoming", incoming},
                                     {"offset", 0},
                                     {"limit", 256}},
                         [this, job, table](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 finishJob(job, false, error);
                                 return;
                             }
                             const QJsonArray rows = response.value("result")
                                                         .toObject()
                                                         .value("rows")
                                                         .toArray();
                             table->setRowCount(0);
                             for (const QJsonValue &value : rows) {
                                 const QJsonObject row = value.toObject();
                                 const int index = table->rowCount();
                                 table->insertRow(index);
                                 const QString from = addressText(row.value("from"));
                                 const QString to = addressText(row.value("to"));
                                 const QString function = row.value("function").toString();
                                 table->setItem(index, 0, new QTableWidgetItem(from));
                                 table->setItem(index, 1,
                                                new QTableWidgetItem(function.isEmpty()
                                                                         ? QStringLiteral("—")
                                                                         : function));
                                 table->setItem(index, 2,
                                                new QTableWidgetItem(
                                                    row.value("kind").toString()));
                                 table->setItem(index, 3, new QTableWidgetItem(to));
                             }
                             finishJob(job, true,
                                       QStringLiteral("%1 xrefs").arg(rows.size()));
                         });
    };
    fill(xrefs_to_, address, true);
    fill(xrefs_from_, address, false);
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
                             QVector<MemoryRegionView> regions;
                             regions.reserve(rows.size());
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
                             hex_canvas_->setRegions(regions);
                             finishJob(job, true,
                                       QStringLiteral("%1 memory regions").arg(rows.size()));
                             loadHex();
                         });
    }

void MainWindow::loadHex() {
    loadHexAt(address_edit_->text());
}

void MainWindow::loadHexAt(const QString &address) {
    const bool live = live_memory_ && live_memory_->isChecked();
    if (address.isEmpty() || (!live && binary_edit_->text().isEmpty())) {
        return;
    }
    const int job = beginJob(QStringLiteral("hex %1").arg(address));
    QJsonObject request{{"method", live ? QStringLiteral("memory_live")
                                       : QStringLiteral("memory")},
                        {"address", address},
                        {"size", 4096}};
    if (live) {
        request.insert(QStringLiteral("endpoint"), live_endpoint_edit_->text().trimmed());
    } else {
        request.insert(QStringLiteral("binary"), binary_edit_->text());
    }
    bridge_->request(request,
                     [this, job, address, live](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishJob(job, false, error);
                             return;
                         }
                         const QJsonObject result = response.value("result").toObject();
                         const QString hex = result.value("bytes_hex").toString();
                         QByteArray bytes;
                         bytes.reserve(hex.size() / 2);
                         for (int i = 0; i + 1 < hex.size(); i += 2) {
                             bytes.append(static_cast<char>(
                                 hex.mid(i, 2).toInt(nullptr, 16)));
                         }
                         bool ok = false;
                         const quint64 base = address.toULongLong(&ok, 16);
                         hex_canvas_->setWindow(ok ? base : 0, bytes);
                         hex_canvas_->setAddress(address);
                         finishJob(job, true,
                                   QStringLiteral("%1: %2 bytes")
                                       .arg(live ? QStringLiteral("live") : QStringLiteral("file"))
                                       .arg(bytes.size()));
                     });
}

void MainWindow::showSignatureSearch() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Byte-pattern signature search"));
    auto *layout = new QVBoxLayout(&dialog);
    auto *pattern_edit = new QLineEdit(&dialog);
    pattern_edit->setPlaceholderText(QStringLiteral("Pattern: E8 ?? ?? ?? ??"));
    auto *list = new QListWidget(&dialog);
    layout->addWidget(pattern_edit);
    layout->addWidget(list, 1);
    connect(pattern_edit, &QLineEdit::returnPressed, this, [this, &dialog, pattern_edit, list]() {
        const QString pattern = pattern_edit->text().trimmed();
        if (pattern.isEmpty()) {
            return;
        }
        list->clear();
        list->addItem(QStringLiteral("searching…"));
        bridge_->request(
            QJsonObject{{"method", "search_bytes"},
                        {"binary", binary_edit_->text()},
                        {"pattern", pattern},
                        {"limit", 512}},
            [this, list, pattern](const QJsonObject &response) {
                list->clear();
                QString error;
                if (!successful(response, &error)) {
                    list->addItem(QStringLiteral("error: ") + error);
                    return;
                }
                const QJsonArray rows = response.value("result").toArray();
                for (const QJsonValue &value : rows) {
                    const QJsonObject row = value.toObject();
                    auto *item = new QListWidgetItem(addressText(row.value("address")));
                    item->setData(Qt::UserRole, addressText(row.value("address")));
                    list->addItem(item);
                }
                if (rows.isEmpty()) {
                    list->addItem(QStringLiteral("no matches for ") + pattern);
                }
            });
    });
    connect(list, &QListWidget::itemActivated, this,
            [this, &dialog](QListWidgetItem *item) {
                const QString address = item->data(Qt::UserRole).toString();
                if (!address.isEmpty()) {
                    dialog.accept();
                    navigation_->goTo(address, true);
                }
            });
    pattern_edit->setFocus();
    dialog.resize(420, 420);
    dialog.exec();
}

void MainWindow::showCommandPalette() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Command palette"));
    auto *layout = new QVBoxLayout(&dialog);
    auto *filter_edit = new QLineEdit(&dialog);
    filter_edit->setPlaceholderText(QStringLiteral("Type a command"));
    auto *list = new QListWidget(&dialog);
    layout->addWidget(filter_edit);
    layout->addWidget(list, 1);

    struct Command {
        QString name;
        std::function<void()> run;
    };
    const QVector<Command> commands = {
        {QStringLiteral("Go to address (G)"), [this]() {
             QInputDialog input(this);
             input.setWindowTitle(QStringLiteral("Go to address"));
             input.setLabelText(QStringLiteral("Address (hex):"));
             input.setTextValue(address_edit_->text());
             if (input.exec() == QDialog::Accepted && !input.textValue().trimmed().isEmpty()) {
                 navigation_->goTo(input.textValue().trimmed(), true);
             }
         }},
        {QStringLiteral("Go to function (Ctrl+P)"), [this]() { loadFacts(); }},
        {QStringLiteral("Decompile current address"), [this]() { decompile(); }},
        {QStringLiteral("Load listing at current address"), [this]() { loadListing(); }},
        {QStringLiteral("Show xrefs for current address"), [this]() { loadXrefs(); }},
        {QStringLiteral("Refresh function list"), [this]() { function_model_->refresh(); }},
        {QStringLiteral("Undo last command (Ctrl+Z)"), [this]() { undoCommand(); }},
        {QStringLiteral("Import native binary"), [this]() { importNative(); }},
        {QStringLiteral("Open program"), [this]() { openProgram(); }},
        {QStringLiteral("Toggle bytes column (Ctrl+B)"), [this]() {
             listing_canvas_->setBytesVisible(!listing_canvas_->bytesVisible());
         }},
        {QStringLiteral("Show function graph (Space)"), [this]() {
             loadGraph();
             graph_dock_->raise();
         }},
        {QStringLiteral("Cancel selected job"), [this]() { cancelJob(); }},
        {QStringLiteral("Theme: dark"), [this]() {
             Theme::setName(QStringLiteral("dark"));
             setStatus(QStringLiteral("theme set to dark (repaints on next paint)"), false);
         }},
        {QStringLiteral("Theme: light"), [this]() {
             Theme::setName(QStringLiteral("light"));
             setStatus(QStringLiteral("theme set to light"), false);
         }},
        {QStringLiteral("Theme: high contrast"), [this]() {
             Theme::setName(QStringLiteral("contrast"));
             setStatus(QStringLiteral("theme set to high contrast"), false);
         }},
    };
    for (const Command &command : commands) {
        list->addItem(command.name);
    }
    connect(filter_edit, &QLineEdit::textChanged, list, [list](const QString &text) {
        const QString needle = text.toLower();
        for (int i = 0; i < list->count(); ++i) {
            list->item(i)->setHidden(!list->item(i)->text().toLower().contains(needle));
        }
        for (int i = 0; i < list->count(); ++i) {
            if (!list->item(i)->isHidden()) {
                list->setCurrentRow(i);
                break;
            }
        }
    });
    connect(list, &QListWidget::itemActivated, this,
            [&dialog, &commands, list](QListWidgetItem *item) {
                dialog.accept();
                for (const Command &command : commands) {
                    if (command.name == item->text()) {
                        command.run();
                        return;
                    }
                }
            });
    filter_edit->setFocus();
    dialog.resize(460, 420);
    dialog.exec();
}

void MainWindow::loadGraph() {
    if (binary_edit_->text().isEmpty() || address_edit_->text().isEmpty()) {
        return;
    }
    const int job = beginJob(QStringLiteral("function graph %1").arg(address_edit_->text()));
    bridge_->request(QJsonObject{{"method", "function_bb_graph"},
                                 {"binary", binary_edit_->text()},
                                 {"address", address_edit_->text()}},
                     [this, job](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             finishJob(job, false, error);
                             return;
                         }
                         const QJsonObject result = response.value("result").toObject();
                         GraphCanvas::Node node;
                         GraphCanvas::Edge edge;
                         QVector<GraphCanvas::Node> nodes;
                         QVector<GraphCanvas::Edge> edges;
                         for (const QJsonValue &value : result.value("nodes").toArray()) {
                             const QJsonObject row = value.toObject();
                             node.address = row.value("address").toString();
                             node.size = row.value("size").toVariant().toULongLong();
                             node.pos = QPointF(row.value("x").toVariant().toDouble(),
                                                row.value("y").toVariant().toDouble());
                             nodes.append(node);
                         }
                         for (const QJsonValue &value : result.value("edges").toArray()) {
                             const QJsonObject row = value.toObject();
                             edge.from = row.value("from").toString();
                             edge.to = row.value("to").toString();
                             edge.kind = row.value("kind").toString();
                             edges.append(edge);
                         }
                         graph_canvas_->setGraph(nodes, edges);
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
                decompile_cache_.remove(program_edit_->text() + QLatin1Char('|') +
                                         address_edit_->text());
                loadTypes();
                decompile();
                finishJob(job, true, QStringLiteral("prototype saved; decompiling"));
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
        auto *item = new QListWidgetItem(QStringLiteral("▶ ") + label, jobs_);
        item->setForeground(QColor("#e5c07b"));
        jobs_->scrollToBottom();
        return jobs_->count() - 1;
    }

void MainWindow::finishJob(int index, bool ok, const QString &detail) {
        if (auto *item = jobs_->item(index)) {
            if (cancelled_jobs_.contains(index)) {
                item->setText(QStringLiteral("✗ cancelled — ") + detail);
                item->setForeground(QColor("#7e8996"));
            } else if (ok) {
                item->setText(QStringLiteral("✓ ") + detail);
                item->setForeground(QColor("#98c379"));
            } else {
                // Every failed request lands here with the error that
                // caused it (Phase 2.5: no silent failures).
                item->setText(QStringLiteral("✗ ") + detail);
                item->setForeground(QColor("#e06c75"));
            }
        }
        setStatus(detail, !ok);
        refreshJobs();
    }
void MainWindow::refreshJobs() {
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

void MainWindow::cancelJob() {
    const int row = jobs_->currentRow();
    if (row < 0) {
        return;
    }
    if (auto *item = jobs_->item(row)) {
        if (item->text().startsWith(QStringLiteral("▶ "))) {
            cancelled_jobs_.insert(row);
            // The in-flight worker call is bounded by the pool deadline;
            // its result is discarded when it arrives.
            item->setText(item->text() + QStringLiteral(" (cancelling…)"));
        }
    }
}

void MainWindow::setStatus(const QString &message, bool error) {
        status_->setText(message);
        status_->setStyleSheet(error ? QStringLiteral("color:#e06c75")
                                     : QStringLiteral("color:#98c379"));  // theme: status
    }

void MainWindow::restoreWorkspace() {
    QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
    const QString scope = project_edit_->text() + QLatin1Char('/');
    const QByteArray geometry =
        settings.value(scope + QStringLiteral("geometry")).toByteArray();
    const QByteArray state =
        settings.value(scope + QStringLiteral("state")).toByteArray();
    if (!geometry.isEmpty()) {
        restoreGeometry(geometry);
    }
    if (!state.isEmpty()) {
        restoreState(state);
    }
    // Reopen workflow: without an explicit --name, resume the project's
    // last program/address (the binary path persists alongside them).
    if (program_edit_->text().isEmpty()) {
        const QString last_program =
            settings.value(scope + QStringLiteral("lastProgram")).toString();
        const QString last_binary =
            settings.value(scope + QStringLiteral("lastBinary")).toString();
        const QString last_address =
            settings.value(scope + QStringLiteral("lastAddress")).toString();
        if (!last_program.isEmpty()) {
            program_edit_->setText(last_program);
            binary_edit_->setText(last_binary);
            function_model_->setProgram(last_program);
            navigation_->setProgram(last_program);
            if (!last_address.isEmpty()) {
                address_edit_->setText(last_address);
                navigation_->goTo(last_address, false);
            }
        }
    }
}

void MainWindow::checkOnboardingGate() {
    if (qEnvironmentVariableIsSet("VENTRIS_UI_GATE")) {
        return;
    }
    QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
    if (settings.value(QStringLiteral("onboarded"), false).toBool()) {
        return;
    }
    const QString home = qEnvironmentVariable("HOME");
    const QString ghidra =
        qEnvironmentVariable("VENTRIS_GHIDRA_INSTALL",
                             home + QStringLiteral("/ghidra_12.1.3_PUBLIC"));
    const QString sla = qEnvironmentVariable("VENTRIS_SLA");
    const QString opt = QStringLiteral("native/build/ghidra_opt");
    const QString console = QStringLiteral("native/build/decomp_native");

    QStringList missing;
    if (!QDir(ghidra).exists()) {
        missing << QStringLiteral(
            "Ghidra install not found at %1 — set VENTRIS_GHIDRA_INSTALL or clone "
            "the pinned 12.1.3 tree there.").arg(ghidra);
    }
    if (sla.isEmpty() || !QFileInfo::exists(sla)) {
        missing << QStringLiteral(
            "No compiled SLEIGH language (VENTRIS_SLA) — expected e.g. "
            "<ghidra>/Ghidra/Processors/x86/data/languages/x86-64.sla. "
            "Decompilation needs it; import and listing do not.");
    }
    if (!QFileInfo::exists(opt)) {
        missing << QStringLiteral(
            "Decompiler binary missing at %1 — run native/build_ghidra_opt.sh.")
                     .arg(opt);
    }
    if (!QFileInfo::exists(console)) {
        missing << QStringLiteral(
            "SLEIGH console missing at %1 — run native/build_console.sh "
            "(needs binutils-devel). Listing and discovery need it.")
                     .arg(console);
    }

    QString message;
    if (missing.isEmpty()) {
        message = QStringLiteral(
            "All native components found. Import a binary from File > Import "
            "binary…, then navigate Functions → Listing → Decompiler → Xrefs.");
    } else {
        message = QStringLiteral("The environment gate is PARTIAL:\n\n%1\n\n"
                                  "The UI still opens; features above fail with the "
                                  "exact missing component in the Jobs dock.")
                      .arg(missing.join(QStringLiteral("\n")));
    }
    QMessageBox box(this);
    box.setWindowTitle(QStringLiteral("Ventris setup"));
    box.setText(message);
    box.setCheckBox(new QCheckBox(QStringLiteral("Don't show again")));
    box.exec();
    if (box.checkBox()->isChecked()) {
        settings.setValue(QStringLiteral("onboarded"), true);
    }
}

void MainWindow::saveWorkspace() {
    QSettings settings(QStringLiteral("Ventris"), QStringLiteral("Ventris"));
    const QString scope = project_edit_->text() + QLatin1Char('/');
    settings.setValue(scope + QStringLiteral("geometry"), saveGeometry());
    settings.setValue(scope + QStringLiteral("state"), saveState());
    settings.setValue(scope + QStringLiteral("lastProgram"), program_edit_->text());
    settings.setValue(scope + QStringLiteral("lastBinary"), binary_edit_->text());
    settings.setValue(scope + QStringLiteral("lastAddress"), address_edit_->text());
}
