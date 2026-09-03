#pragma once

#include <QMainWindow>

#include "views.h"
#include <QSet>
#include <QStringList>

class CoreBridge;
class DecompilerView;
class FunctionTableModel;
class GraphCanvas;
class HexCanvas;
class ListingCanvas;
class NavigationController;
class QInputDialog;
class QDialog;
class QLabel;
class QTimer;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QTableView;
class StringsTableModel;
class QTableWidget;

/// Root window: owns the CoreBridge, every dock, and the workspace
/// persistence. Navigation state moves to NavigationController in Phase 0;
/// dock construction moves to per-dock widgets through Phase 1.
class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(const QString &project, const QString &program,
                        const QString &binary, const QString &address,
                        QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void importNative();
    void openProgram();
    void decompile();
    void loadListing();
    void loadXrefs();
    void loadMemory();
    void loadFacts();
    void loadListingAt(const QString &address);
    void listingContextMenu(const QPoint &global_pos, const QString &address);
    void loadHex();
    void loadHexAt(const QString &address);
    void renameFunctionAt(const QString &address, const QString &name);
    void loadGraph();
    void loadAnalystData();
    void setBookmark();
    void setPatch();
    void loadTypes();
    void saveTypeDefinition();
    void saveTypeField();
    void savePrototype();
    void saveStackVariable();
    void propagateTypes();
    void renameFunction();
    void applyComment();
    void undoCommand();

private:
    int beginJob(const QString &label);
    void finishJob(int index, bool ok, const QString &detail);
    void cancelJob();
    void showCommandPalette();
    void setStatus(const QString &message, bool error = false);
    void restoreWorkspace();
    void saveWorkspace();

    CoreBridge *bridge_;
    QString program_;
    QString binary_;
    QString address_;
    NavigationController *navigation_;
    QHash<QString, QPair<qint64, QVector<TokenView>>> decompile_cache_;
    quint64 decompile_generation_ = 0;
    QLineEdit *project_edit_ = nullptr;
    QLineEdit *program_edit_ = nullptr;
    QLineEdit *binary_edit_ = nullptr;
    QLineEdit *address_edit_ = nullptr;
    QLineEdit *name_edit_ = nullptr;
    QLineEdit *comment_edit_ = nullptr;
    QLineEdit *comment_kind_edit_ = nullptr;
    QLineEdit *search_edit_ = nullptr;
    QLineEdit *bookmark_edit_ = nullptr;
    QLineEdit *patch_original_edit_ = nullptr;
    QTableView *functions_ = nullptr;
    QLineEdit *function_filter_edit_ = nullptr;
    QTimer *function_filter_timer_ = nullptr;
    QLineEdit *patch_new_edit_ = nullptr;
    FunctionTableModel *function_model_ = nullptr;
    QTableWidget *xrefs_to_ = nullptr;
    QTableWidget *xrefs_from_ = nullptr;
    QTableWidget *symbols_ = nullptr;
    QTableView *strings_ = nullptr;
    StringsTableModel *strings_model_ = nullptr;
    QTableWidget *search_results_ = nullptr;
    QTableWidget *memory_regions_ = nullptr;
    QTableWidget *bookmarks_ = nullptr;
    QTableWidget *patches_ = nullptr;
    QListWidget *jobs_ = nullptr;
    QSet<int> cancelled_jobs_;
    ListingCanvas *listing_canvas_ = nullptr;
    GraphCanvas *graph_canvas_ = nullptr;
    QDockWidget *graph_dock_ = nullptr;
    DecompilerView *decompiler_ = nullptr;
    QLabel *status_ = nullptr;
    HexCanvas *hex_canvas_ = nullptr;
    QLineEdit *type_name_edit_ = nullptr;
    QLineEdit *type_kind_edit_ = nullptr;
    QLineEdit *type_size_edit_ = nullptr;
    QLineEdit *type_alignment_edit_ = nullptr;
    QLineEdit *type_definition_edit_ = nullptr;
    QLineEdit *field_ordinal_edit_ = nullptr;
    QLineEdit *type_base_edit_ = nullptr;
    QLineEdit *field_name_edit_ = nullptr;
    QLineEdit *field_offset_edit_ = nullptr;
    QLineEdit *field_size_edit_ = nullptr;
    QLineEdit *field_type_edit_ = nullptr;
    QLineEdit *prototype_signature_edit_ = nullptr;
    QLineEdit *calling_convention_edit_ = nullptr;
    QLineEdit *stack_name_edit_ = nullptr;
    QLineEdit *stack_storage_edit_ = nullptr;
    QLineEdit *stack_type_edit_ = nullptr;
    QLineEdit *stack_offset_edit_ = nullptr;
    QLineEdit *stack_size_edit_ = nullptr;
    QTableWidget *types_ = nullptr;
    QTableWidget *type_fields_ = nullptr;
    QTableWidget *prototypes_ = nullptr;
    QTableWidget *stack_variables_ = nullptr;
    QTableWidget *type_links_ = nullptr;
};
