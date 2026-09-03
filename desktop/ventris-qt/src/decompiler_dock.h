#pragma once

#include <QDockWidget>

class DecompilerView;

class DecompilerDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit DecompilerDock(QWidget *parent = nullptr);

    DecompilerView *view() const { return view_; }

private:
    DecompilerView *view_ = nullptr;
};
