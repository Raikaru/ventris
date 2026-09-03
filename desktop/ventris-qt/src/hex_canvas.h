#pragma once

#include <QByteArray>
#include <QVector>
#include <QWidget>

#include "views.h"

class QKeyEvent;
class QMouseEvent;

/// Virtualized paint-based hex view over `memory` request windows (Phase
/// 2.2). Sixteen bytes per row with offset, hex, and ASCII columns; qwords
/// that resolve into a mapped region render as pointers and jump on click.
/// The canvas never holds more than one fetched window.
class HexCanvas final : public QWidget {
    Q_OBJECT

public:
    explicit HexCanvas(QWidget *parent = nullptr);

    /// Replaces the visible window; `base_offset` is the file offset of
    /// bytes[0].
    void setWindow(quint64 base_offset, const QByteArray &bytes);
    /// Centers the view on `address` (requests a window when outside).
    void setAddress(const QString &address);
    void setRegions(const QVector<MemoryRegionView> &regions);
    QSize sizeHint() const override;

signals:
    void addressSelected(const QString &address, bool record);
    void windowNeeded(quint64 offset);

protected:
    void paintEvent(QPaintEvent *) override;
    void wheelEvent(QWheelEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    int rowHeight() const;
    int visibleRows() const;
    int cursorRow() const;
    void moveCursor(int delta, bool record);
    void ensureWindowAround(int row);
    QString addressAtRow(int row) const;
    /// The qword at `row`/`byte_column` when it points into a region.
    QString pointerAt(int row, int byte_column) const;

    QByteArray bytes_;
    quint64 base_offset_ = 0;
    int cursor_ = 0;
    QVector<MemoryRegionView> regions_;
    quint64 region_low_ = 0;
    quint64 region_high_ = 0;
};
