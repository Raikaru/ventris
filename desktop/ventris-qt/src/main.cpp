#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>

#include "main_window.h"

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("Ventris"));
    QCoreApplication::setApplicationName(QStringLiteral("Ventris"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Native Ventris reverse-engineering UI"));
    parser.addHelpOption();
    QCommandLineOption project_option(QStringList() << "p" << "project", "SQLite project", "dir",
                                      QStringLiteral(".lre"));
    QCommandLineOption program_option(QStringList() << "n" << "name", "Program name", "name");
    QCommandLineOption binary_option(QStringList() << "b" << "binary", "Binary path", "path");
    QCommandLineOption address_option(QStringList() << "a" << "address", "RAM address", "hex",
                                      QStringLiteral("00400466"));
    parser.addOption(project_option);
    parser.addOption(program_option);
    parser.addOption(binary_option);
    parser.addOption(address_option);
    parser.process(application);

    const QString program = parser.value(program_option);
    MainWindow window(parser.value(project_option), program, parser.value(binary_option),
                      parser.value(address_option));
    window.show();
    return application.exec();
}
