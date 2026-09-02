#include "navigation_controller.h"

NavigationController::NavigationController(QObject *parent) : QObject(parent) {}

void NavigationController::setProgram(const QString &program) {
    if (program_ == program) {
        return;
    }
    program_ = program;
    emit programChanged(program_);
}

QString NavigationController::program() const { return program_; }

void NavigationController::goTo(const QString &address, bool record) {
    if (address.isEmpty()) {
        return;
    }
    if (record) {
        while (history_.size() > history_index_ + 1) {
            history_.removeLast();
        }
        if (history_.isEmpty() || history_.last() != address) {
            history_.append(address);
        }
        history_index_ = history_.size() - 1;
    }
    address_ = address;
    emit addressChanged(address_);
    emit historyChanged(canGoBack(), canGoForward());
}

QString NavigationController::address() const { return address_; }

bool NavigationController::canGoBack() const { return history_index_ > 0; }

bool NavigationController::canGoForward() const {
    return history_index_ + 1 < history_.size();
}

void NavigationController::back() {
    if (!canGoBack()) {
        return;
    }
    --history_index_;
    address_ = history_.at(history_index_);
    emit addressChanged(address_);
    emit historyChanged(canGoBack(), canGoForward());
}

void NavigationController::forward() {
    if (!canGoForward()) {
        return;
    }
    ++history_index_;
    address_ = history_.at(history_index_);
    emit addressChanged(address_);
    emit historyChanged(canGoBack(), canGoForward());
}
