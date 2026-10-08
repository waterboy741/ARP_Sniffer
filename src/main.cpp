#include "gui/MainWindow.hpp"

#include <QApplication>
#include <pcap/pcap.h>

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("ARP Sniffer"));
    QApplication::setApplicationVersion(QStringLiteral("0.1.0"));
    // Resolve a libpcap symbol now so the initial build verifies its link dependency.
    application.setProperty("captureLibraryVersion", pcap_lib_version());
    MainWindow window;
    window.show();
    return application.exec();
}
