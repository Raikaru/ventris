#include "memory_dock.h"

#include "core_bridge.h"
#include "hex_canvas.h"
#include "json_util.h"
#include "views.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QTableWidget>
#include <QVBoxLayout>

MemoryDock::MemoryDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Memory map / hex"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("memoryDock"));

    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);

    memory_regions_ = new QTableWidget(0, 5, panel);
    memory_regions_->setHorizontalHeaderLabels(
        {QStringLiteral("Name"), QStringLiteral("Start"), QStringLiteral("Size"),
         QStringLiteral("Permissions"), QStringLiteral("Source")});
    memory_regions_->horizontalHeader()->setStretchLastSection(true);
    memory_regions_->verticalHeader()->setVisible(false);
    memory_regions_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect(memory_regions_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
        if (auto *start_item = memory_regions_->item(item->row(), 1)) {
            emit addressSelected(start_item->text(), true);
        }
    });

    hex_canvas_ = new HexCanvas(panel);
    auto *live_controls = new QHBoxLayout();
    live_memory_ = new QCheckBox(QStringLiteral("Live target"), panel);
    live_endpoint_edit_ = new QLineEdit(QStringLiteral("127.0.0.1:24689"), panel);
    live_endpoint_edit_->setPlaceholderText(QStringLiteral("Dolphin GDB endpoint"));
    live_endpoint_edit_->setEnabled(false);
    live_controls->addWidget(live_memory_);
    live_controls->addWidget(live_endpoint_edit_, 1);

    connect(live_memory_, &QCheckBox::toggled, this, [this](bool live) {
        hex_canvas_->setLiveSource(live);
        live_endpoint_edit_->setEnabled(live);
        loadHex(last_binary_, last_address_);
    });
    connect(live_endpoint_edit_, &QLineEdit::editingFinished, this, [this]() {
        if (live_memory_->isChecked()) {
            loadHex(last_binary_, last_address_);
        }
    });
    connect(hex_canvas_, &HexCanvas::addressSelected, this,
            [this](const QString &address, bool record) {
                emit addressSelected(address, record);
            });
    connect(hex_canvas_, &HexCanvas::windowNeeded, this,
            [this](quint64 offset) {
                loadHexAt(last_binary_, QStringLiteral("0x%1").arg(offset, 0, 16));
            });

    layout->addWidget(memory_regions_, 1);
    layout->addLayout(live_controls);
    layout->addWidget(hex_canvas_, 1);
    setWidget(panel);
}

void MemoryDock::loadMemory(const QString &program, const QString &binary, const QString &address) {
    last_binary_ = binary;
    if (program.isEmpty()) {
        return;
    }
    emit jobStarted(QStringLiteral("memory map"));
    bridge_->request(QJsonObject{{"method", "memory_regions"},
                                 {"program", program}},
                     [this, binary, address](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("memory map"), false, error);
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
                         emit jobFinished(QStringLiteral("memory map"), true,
                                          QStringLiteral("%1 memory regions").arg(rows.size()));
                         loadHex(binary, address);
                     });
}

void MemoryDock::loadHex(const QString &binary, const QString &address) {
    loadHexAt(binary, address);
}

void MemoryDock::loadHexAt(const QString &binary, const QString &address) {
    last_binary_ = binary;
    const bool live = live_memory_ && live_memory_->isChecked();
    if (address.isEmpty() || (!live && binary.isEmpty())) {
        return;
    }
    emit jobStarted(QStringLiteral("hex %1").arg(address));
    QJsonObject request{{"method", live ? QStringLiteral("memory_live")
                                       : QStringLiteral("memory")},
                        {"address", address},
                        {"size", 4096}};
    if (live) {
        request.insert(QStringLiteral("endpoint"), live_endpoint_edit_->text().trimmed());
    } else {
        request.insert(QStringLiteral("binary"), binary);
    }
    bridge_->request(request,
                     [this, address, live](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("hex %1").arg(address), false, error);
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
                         emit jobFinished(QStringLiteral("hex %1").arg(address), true,
                                          QStringLiteral("%1: %2 bytes")
                                              .arg(live ? QStringLiteral("live") : QStringLiteral("file"))
                                              .arg(bytes.size()));
                     });
}
