#include "decompiler_dock.h"

#include "decompiler_view.h"

DecompilerDock::DecompilerDock(QWidget *parent)
    : QDockWidget(QStringLiteral("Decompiler"), parent) {
    setObjectName(QStringLiteral("decompilerDock"));
    view_ = new DecompilerView(this);
    setWidget(view_);
}
