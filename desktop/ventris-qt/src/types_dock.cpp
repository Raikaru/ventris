#include "types_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>

TypesDock::TypesDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Types / prototypes"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("typesDock"));

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

    setWidget(type_panel);
}

void TypesDock::setPrototypeAddress(const QString &address) {
    current_address_ = address;
}

void TypesDock::loadTypes(const QString &program) {
    if (program.isEmpty()) {
        return;
    }
    emit jobStarted(QStringLiteral("types"));
    bridge_->request(QJsonObject{{"method", "type_defs"}, {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("types"), false, error);
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
                         emit jobFinished(QStringLiteral("types"), true,
                                          QStringLiteral("%1 types").arg(rows.size()));
                     });

    emit jobStarted(QStringLiteral("type fields"));
    bridge_->request(QJsonObject{{"method", "type_fields"}, {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("type fields"), false, error);
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
                         emit jobFinished(QStringLiteral("type fields"), true,
                                          QStringLiteral("%1 fields").arg(rows.size()));
                     });

    emit jobStarted(QStringLiteral("prototypes"));
    bridge_->request(QJsonObject{{"method", "prototypes"}, {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("prototypes"), false, error);
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
                         emit jobFinished(QStringLiteral("prototypes"), true,
                                          QStringLiteral("%1 prototypes").arg(rows.size()));
                     });

    emit jobStarted(QStringLiteral("stack variables"));
    bridge_->request(QJsonObject{{"method", "stack_variables"}, {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("stack variables"), false, error);
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
                         emit jobFinished(QStringLiteral("stack variables"), true,
                                          QStringLiteral("%1 stack variables").arg(rows.size()));
                     });

    emit jobStarted(QStringLiteral("type graph"));
    bridge_->request(QJsonObject{{"method", "type_graph"}, {"program", program}},
                     [this](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("type graph"), false, error);
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
                         emit jobFinished(QStringLiteral("type graph"), true,
                                          QStringLiteral("%1 type links").arg(rows.size()));
                     });
}

void TypesDock::saveTypeDefinition(const QString &program) {
    if (type_name_edit_->text().trimmed().isEmpty()) {
        emit statusRequested(QStringLiteral("type name is required"), true);
        return;
    }
    emit jobStarted(QStringLiteral("save type"));
    bridge_->request(
        QJsonObject{
            {"method", "set_type_def"},
            {"program", program},
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
        [this, program](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("save type"), false, error);
                return;
            }
            loadTypes(program);
            emit jobFinished(QStringLiteral("save type"), true, QStringLiteral("type saved"));
        });
}

void TypesDock::saveTypeField(const QString &program) {
    if (type_name_edit_->text().trimmed().isEmpty() ||
        field_name_edit_->text().trimmed().isEmpty()) {
        emit statusRequested(QStringLiteral("type and field names are required"), true);
        return;
    }
    emit jobStarted(QStringLiteral("save type field"));
    bridge_->request(
        QJsonObject{
            {"method", "set_type_field"},
            {"program", program},
            {"row", QJsonObject{
                        {"type_name", type_name_edit_->text()},
                        {"ordinal", optionalInteger(field_ordinal_edit_->text())},
                        {"field_name", field_name_edit_->text()},
                        {"offset", optionalInteger(field_offset_edit_->text())},
                        {"size", optionalInteger(field_size_edit_->text())},
                        {"type_ref", field_type_edit_->text().isEmpty()
                                         ? QJsonValue(QJsonValue::Null)
                                         : QJsonValue(field_type_edit_->text())}}}},
        [this, program](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("save type field"), false, error);
                return;
            }
            loadTypes(program);
            emit jobFinished(QStringLiteral("save type field"), true, QStringLiteral("type field saved"));
        });
}

void TypesDock::savePrototype(const QString &program, const QString &address) {
    emit jobStarted(QStringLiteral("save prototype"));
    bridge_->request(
        QJsonObject{{"method", "set_prototype"},
                    {"program", program},
                    {"row", QJsonObject{
                                {"function", address},
                                {"signature", prototype_signature_edit_->text()},
                                {"calling_convention", calling_convention_edit_->text().isEmpty()
                                                           ? QJsonValue(QJsonValue::Null)
                                                           : QJsonValue(calling_convention_edit_->text())},
                                {"return_type", QJsonValue(QJsonValue::Null)}}}},
        [this, address](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("save prototype"), false, error);
                return;
            }
            emit prototypeSaved(address);
            emit jobFinished(QStringLiteral("save prototype"), true, QStringLiteral("prototype saved; decompiling"));
        });
}

void TypesDock::saveStackVariable(const QString &program, const QString &address) {
    emit jobStarted(QStringLiteral("save stack variable"));
    bridge_->request(
        QJsonObject{
            {"method", "set_stack_variable"},
            {"program", program},
            {"row", QJsonObject{
                        {"function", address},
                        {"ordinal", optionalInteger(field_ordinal_edit_->text())},
                        {"name", stack_name_edit_->text()},
                        {"storage", stack_storage_edit_->text()},
                        {"type_name", stack_type_edit_->text().isEmpty()
                                          ? QJsonValue(QJsonValue::Null)
                                          : QJsonValue(stack_type_edit_->text())},
                        {"offset", optionalInteger(stack_offset_edit_->text())},
                        {"size", optionalInteger(stack_size_edit_->text())}}}},
        [this, program](const QJsonObject &response) {
            QString error;
            if (!successful(response, &error)) {
                emit jobFinished(QStringLiteral("save stack variable"), false, error);
                return;
            }
            loadTypes(program);
            emit jobFinished(QStringLiteral("save stack variable"), true, QStringLiteral("stack variable saved"));
        });
}

void TypesDock::propagateTypes(const QString &program) {
    emit jobStarted(QStringLiteral("propagate types"));
    bridge_->request(QJsonObject{{"method", "propagate_type_links"},
                                 {"program", program}},
                     [this, program](const QJsonObject &response) {
                         QString error;
                         if (!successful(response, &error)) {
                             emit jobFinished(QStringLiteral("propagate types"), false, error);
                             return;
                         }
                         loadTypes(program);
                         emit jobFinished(QStringLiteral("propagate types"), true,
                                          QStringLiteral("%1 type links")
                                              .arg(response.value("result").toArray().size()));
                     });
}
