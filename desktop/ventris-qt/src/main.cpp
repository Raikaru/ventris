#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTimer>

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
    QCommandLineOption gate_option(QStringList() << "gate",
                                   "Run the offscreen UI gate and exit");
    parser.addOption(gate_option);
    parser.addOption(project_option);
    parser.addOption(program_option);
    parser.addOption(binary_option);
    parser.addOption(address_option);
    parser.process(application);

    if (parser.isSet(gate_option)) {
        qputenv("VENTRIS_UI_GATE", "1");
    }
    const QString program = parser.value(program_option);
    MainWindow window(parser.value(project_option), program, parser.value(binary_option),
                      parser.value(address_option));
    window.show();
    if (parser.isSet(gate_option)) {
        QTimer::singleShot(0, &window, &MainWindow::runGate);
    }
    return application.exec();
}
