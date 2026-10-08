#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QElapsedTimer>
#include <QPointer>
#include <QTest>
#include <QTimer>

class MainWindowTests : public QObject
{
    Q_OBJECT

  private slots:
    void showAndClose();
    void deleteOnClose();
    void closingLastWindowStopsApplication();
};

void MainWindowTests::showAndClose()
{
    MainWindow window;
    QVERIFY(!window.isVisible());
    QCOMPARE(window.windowTitle(), QStringLiteral("ARP Sniffer"));
    QVERIFY(window.centralWidget() != nullptr);

    window.show();
    QTRY_VERIFY(window.isVisible());
    QVERIFY(window.close());
    QTRY_VERIFY(!window.isVisible());

    // A closed, still-owned window must remain usable for a subsequent launch.
    window.show();
    QTRY_VERIFY(window.isVisible());
    QVERIFY(window.close());
    QTRY_VERIFY(!window.isVisible());
}

void MainWindowTests::deleteOnClose()
{
    QPointer<MainWindow> window = new MainWindow;
    window->setAttribute(Qt::WA_DeleteOnClose);
    window->show();
    QTRY_VERIFY(window->isVisible());
    QVERIFY(window->close());
    QTRY_VERIFY(window.isNull());
}

void MainWindowTests::closingLastWindowStopsApplication()
{
    MainWindow window;
    QApplication::setQuitOnLastWindowClosed(true);
    window.show();
    QVERIFY(window.isVisible());

    QTimer watchdog;
    watchdog.setSingleShot(true);
    connect(&watchdog, &QTimer::timeout, qApp, [] { QCoreApplication::exit(124); });
    watchdog.start(2000);
    QTimer::singleShot(20, &window, &QWidget::close);

    QElapsedTimer elapsed;
    elapsed.start();
    QCOMPARE(QApplication::exec(), 0);
    QVERIFY(!window.isVisible());
    QVERIFY2(elapsed.elapsed() < 2000, "Closing the last window failed to stop the event loop");
}

QTEST_MAIN(MainWindowTests)
#include "MainWindowTests.moc"
