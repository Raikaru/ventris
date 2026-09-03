#pragma once

#include <QDockWidget>

class CoreBridge;
class HexCanvas;
class QCheckBox;
class QLineEdit;
class QTableWidget;

class MemoryDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit MemoryDock(CoreBridge *bridge, QWidget *parent = nullptr);

    HexCanvas *canvas() const { return hex_canvas_; }

    void loadMemory(const QString &program, const QString &binary, const QString &address);
    void loadHex(const QString &binary, const QString &address);
    void loadHexAt(const QString &binary, const QString &address);

signals:
    void addressSelected(const QString &address, bool record);
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);

private:
    CoreBridge *bridge_;
    QTableWidget *memory_regions_ = nullptr;
    HexCanvas *hex_canvas_ = nullptr;
    QCheckBox *live_memory_ = nullptr;
    QLineEdit *live_endpoint_edit_ = nullptr;
    QString last_binary_;
    QString last_address_;
};
