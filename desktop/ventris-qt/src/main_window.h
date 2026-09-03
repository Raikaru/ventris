#pragma once

#include <QHash>
#include <QMainWindow>
#include <QPair>
#include <QVector>

#include "views.h"

class AnalystDock;
class CoreBridge;
class DecompilerDock;
class FactsDock;
class FunctionsDock;
class GateRunner;
class GraphDock;
class JobsDock;
class ListingCanvas;
class MemoryDock;
class NavigationController;
class TypesDock;
class VtablesDock;
class XrefsDock;

class QLabel;
class QLineEdit;
class QMenu;

/// Root window: owns the CoreBridge, dock coordination, and workspace persistence.
class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(const QString &project, const QString &program,
                        const QString &binary, const QString &address,
                        QWidget *parent = nullptr);
    ~MainWindow() override;

    /// Runs the deterministic offscreen UI gate and exits the application.
    void runGate();

    // Getters for modular docks and controllers
    FunctionsDock *functionsDock() const { return functions_dock_; }
    DecompilerDock *decompilerDock() const { return decompiler_dock_; }
    GraphDock *graphDock() const { return graph_dock_; }
    ListingCanvas *listingCanvas() const { return listing_canvas_; }
    NavigationController *navigation() const { return navigation_; }
    QString program() const;
    QString binary() const;

private slots:
    void importNative();
    void openProgram();
    void decompile();
    void loadListing();
    void loadListingAt(const QString &address);
    void listingContextMenu(const QPoint &global_pos, const QString &address);
    void renameFunctionAt(const QString &address, const QString &name);
    void loadProgramPanels();
    void renameFunction();
    void applyComment();
    void undoCommand();

private:
    void showCommandPalette();
    void checkOnboardingGate();
    void showSignatureSearch();
    void setStatus(const QString &message, bool error = false);
    void restoreWorkspace();
    void saveWorkspace();

    CoreBridge *bridge_;
    QString program_;
    QString binary_;
    QString address_;
    NavigationController *navigation_;
    GateRunner *gate_runner_ = nullptr;

    QHash<QString, QPair<qint64, QVector<TokenView>>> decompile_cache_;
    quint64 decompile_generation_ = 0;

    // Controls
    QLineEdit *project_edit_ = nullptr;
    QLineEdit *program_edit_ = nullptr;
    QLineEdit *binary_edit_ = nullptr;
    QLineEdit *address_edit_ = nullptr;
    QLineEdit *name_edit_ = nullptr;
    QLineEdit *comment_edit_ = nullptr;
    QLineEdit *comment_kind_edit_ = nullptr;
    QLineEdit *search_edit_ = nullptr;
    QLabel *status_ = nullptr;
    QMenu *recent_menu_ = nullptr;

    // Central Listing
    ListingCanvas *listing_canvas_ = nullptr;

    // Modular Docks
    FunctionsDock *functions_dock_ = nullptr;
    DecompilerDock *decompiler_dock_ = nullptr;
    FactsDock *facts_dock_ = nullptr;
    MemoryDock *memory_dock_ = nullptr;
    GraphDock *graph_dock_ = nullptr;
    AnalystDock *analyst_dock_ = nullptr;
    TypesDock *types_dock_ = nullptr;
    XrefsDock *xrefs_dock_ = nullptr;
    JobsDock *jobs_dock_ = nullptr;
    VtablesDock *vtables_dock_ = nullptr;
};
