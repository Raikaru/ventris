#pragma once

#include <QDockWidget>

class CoreBridge;
class QLineEdit;
class QTableWidget;

class TypesDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit TypesDock(CoreBridge *bridge, QWidget *parent = nullptr);

    void loadTypes(const QString &program);
    void saveTypeDefinition(const QString &program);
    void saveTypeField(const QString &program);
    void savePrototype(const QString &program, const QString &address);
    void saveStackVariable(const QString &program, const QString &address);
    void propagateTypes(const QString &program);

    void setPrototypeAddress(const QString &address);

signals:
    void prototypeSaved(const QString &address);
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);
    void statusRequested(const QString &message, bool error);

private:
    CoreBridge *bridge_;

    QLineEdit *type_name_edit_ = nullptr;
    QLineEdit *type_kind_edit_ = nullptr;
    QLineEdit *type_definition_edit_ = nullptr;
    QLineEdit *type_size_edit_ = nullptr;
    QLineEdit *type_alignment_edit_ = nullptr;
    QLineEdit *type_base_edit_ = nullptr;

    QLineEdit *field_ordinal_edit_ = nullptr;
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

    QString current_address_;
};
