#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSysInfo>
#include <QTableView>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace
{
struct BackendState {
    std::mutex mutex;
    std::condition_variable changed;
    bool interrupted = false;
    bool blockOpen = false;
    bool openEntered = false;
    bool failRead = false;
    bool blockClose = false;
    bool closeEntered = false;
    bool releaseClose = false;
    int closes = 0;
    int opens = 0;
    std::vector<arp::CapturedPacket> packets;
    std::size_t nextPacket = 0;
    std::chrono::microseconds packetDelay{0};
};

class FakeBackend final : public arp::ICaptureBackend
{
  public:
    explicit FakeBackend(std::shared_ptr<BackendState> state) : state_(std::move(state)) {}
    void open(const std::string&) override
    {
        std::unique_lock lock(state_->mutex);
        ++state_->opens;
        state_->interrupted = false;
        state_->openEntered = true;
        state_->changed.notify_all();
        if (state_->blockOpen)
            state_->changed.wait(lock, [this] { return state_->interrupted; });
    }
    arp::BackendRead read() override
    {
        std::unique_lock lock(state_->mutex);
        if (state_->failRead)
            return {arp::ReadStatus::Error, {}, "synthetic capture failure"};
        if (state_->nextPacket < state_->packets.size()) {
            auto packet = std::move(state_->packets[state_->nextPacket++]);
            const auto delay = state_->packetDelay;
            lock.unlock();
            if (delay.count() > 0)
                std::this_thread::sleep_for(delay);
            return {arp::ReadStatus::Packet, std::move(packet), {}};
        }
        state_->changed.wait(lock, [this] { return state_->interrupted; });
        return {arp::ReadStatus::End, {}, {}};
    }
    void interrupt() noexcept override
    {
        {
            std::lock_guard lock(state_->mutex);
            state_->interrupted = true;
        }
        state_->changed.notify_all();
    }
    void close() noexcept override
    {
        std::unique_lock lock(state_->mutex);
        ++state_->closes;
        state_->closeEntered = true;
        state_->changed.notify_all();
        if (state_->blockClose)
            state_->changed.wait(lock, [this] { return state_->releaseClose; });
    }
    arp::CaptureStatistics statistics() override { return {}; }
    int linkType() const override { return 1; }

  private:
    std::shared_ptr<BackendState> state_;
};

arp::ArpRecord makeRecord(std::uint64_t sequence, arp::ArpOperation operation,
                          arp::Ipv4Address senderIp, arp::Ipv4Address targetIp,
                          arp::MacAddress senderMac, std::vector<arp::VlanTag> tags = {})
{
    arp::ArpRecord record;
    record.metadata.sequenceNumber = sequence;
    record.metadata.captureTimestamp = std::chrono::milliseconds(sequence);
    record.metadata.interfaceName = "synthetic0";
    record.metadata.capturedLength = 42;
    record.metadata.originalLength = 60;
    record.operation = operation;
    record.senderIpv4 = senderIp;
    record.targetIpv4 = targetIp;
    record.senderMac = senderMac;
    record.ethernetSource = senderMac;
    record.ethernetDestination = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    record.targetMac = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    record.vlanTags = std::move(tags);
    return record;
}

arp::CapturedPacket makeCapturedArp(std::uint64_t sequence, std::uint16_t operation,
                                    arp::Ipv4Address senderIp, arp::Ipv4Address targetIp,
                                    arp::MacAddress senderMac, arp::MacAddress targetMac)
{
    arp::CapturedPacket packet;
    const arp::MacAddress broadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const auto appendAddress = [&packet](const auto& address) {
        packet.bytes.insert(packet.bytes.end(), address.begin(), address.end());
    };
    const auto append16 = [&packet](std::uint16_t value) {
        packet.bytes.push_back(static_cast<std::uint8_t>(value >> 8));
        packet.bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
    };
    appendAddress(broadcast);
    appendAddress(senderMac);
    append16(0x0806);
    append16(1);
    append16(0x0800);
    packet.bytes.push_back(6);
    packet.bytes.push_back(4);
    append16(operation);
    appendAddress(senderMac);
    appendAddress(senderIp);
    appendAddress(targetMac);
    appendAddress(targetIp);
    packet.metadata.sequenceNumber = sequence;
    packet.metadata.captureTimestamp =
        std::chrono::nanoseconds{1735689600000000000LL} + std::chrono::milliseconds{sequence};
    packet.metadata.interfaceName = "synthetic0";
    packet.metadata.capturedLength = static_cast<std::uint32_t>(packet.bytes.size());
    packet.metadata.originalLength = 60;
    packet.metadata.linkType = 1;
    return packet;
}

MainWindow makeWindow(const std::shared_ptr<BackendState>& state)
{
    return MainWindow(std::make_unique<FakeBackend>(state), {{"synthetic0", "Test", false}});
}
} // namespace

class CaptureGuiTests : public QObject
{
    Q_OBJECT
  private slots:
    void controlsErrorsAndAsyncClose();
    void recordingOverwriteRequiresConfirmation();
    void fixturePacketsReachRowsAndCounters();
    void recordingAndReplayPreserveRowsBeyondDisplayLimit();
    void closeDuringRecordingFlushesCompleteSession();
    void optionalDeniedLiveAccess();
    void interactiveCsvExportAcceptsWritableFilename();
    void countersIgnoreDisplayFiltersAndDetailsFollowSelection();
    void retainsNewestTenThousandAndStaysResponsive();
};

void CaptureGuiTests::controlsErrorsAndAsyncClose()
{
    auto startingState = std::make_shared<BackendState>();
    startingState->blockOpen = true;
    auto startingWindow = makeWindow(startingState);
    startingWindow.show();
    auto* startingInterfaces = startingWindow.findChild<QComboBox*>("interfaceCombo");
    auto* startingButton = startingWindow.findChild<QPushButton*>("startButton");
    auto* startingStatus = startingWindow.findChild<QLabel*>("statusLabel");
    startingInterfaces->setCurrentIndex(1);
    startingButton->click();
    QTRY_VERIFY(startingStatus->text().contains("Starting"));
    QTRY_VERIFY([&] {
        std::lock_guard lock(startingState->mutex);
        return startingState->openEntered;
    }());
    startingWindow.close();
    QTRY_VERIFY(!startingWindow.isVisible());
    QCOMPARE(startingState->closes, 1);

    auto state = std::make_shared<BackendState>();
    state->blockClose = true;
    auto window = makeWindow(state);
    auto* interfaces = window.findChild<QComboBox*>("interfaceCombo");
    auto* start = window.findChild<QPushButton*>("startButton");
    auto* stop = window.findChild<QPushButton*>("stopButton");
    auto* destination = window.findChild<QLineEdit*>("recordingDestination");
    auto* status = window.findChild<QLabel*>("statusLabel");
    QVERIFY(interfaces && start && stop && destination && status);
    QVERIFY(status->text().contains("Stopped"));
    QVERIFY(!start->isEnabled());
    QVERIFY(!stop->isEnabled());
    QVERIFY(destination->isEnabled());
    QVERIFY(destination->placeholderText().contains("Optional PCAP recording destination"));

    interfaces->setCurrentIndex(1);
    QVERIFY(start->isEnabled());
    QTest::mouseClick(start, Qt::LeftButton);
    QTRY_COMPARE(window.packetModel()->rowCount(), 0);
    QTRY_VERIFY(status->text().contains("Capturing"));
    QVERIFY(!interfaces->isEnabled());
    QVERIFY(!destination->isEnabled());
    QVERIFY(!start->isEnabled());
    QVERIFY(stop->isEnabled());

    QTimer ownerTimer;
    int ticks = 0;
    connect(&ownerTimer, &QTimer::timeout, this, [&ticks] { ++ticks; });
    ownerTimer.start(1);
    window.close();
    QTRY_VERIFY([&] {
        std::lock_guard lock(state->mutex);
        return state->closeEntered;
    }());
    QTRY_VERIFY(ticks > 0);
    {
        std::lock_guard lock(state->mutex);
        state->releaseClose = true;
    }
    state->changed.notify_all();
    QTRY_VERIFY(!window.isVisible());
    QCOMPARE(state->closes, 1);
    ownerTimer.stop();

    auto failureState = std::make_shared<BackendState>();
    failureState->failRead = true;
    auto failureWindow = makeWindow(failureState);
    auto* failureInterfaces = failureWindow.findChild<QComboBox*>("interfaceCombo");
    auto* failureStart = failureWindow.findChild<QPushButton*>("startButton");
    auto* failureStatus = failureWindow.findChild<QLabel*>("statusLabel");
    auto* failureCounters = failureWindow.findChild<QLabel*>("countersLabel");
    QVERIFY(failureCounters);
    failureInterfaces->setCurrentIndex(1);
    QTest::mouseClick(failureStart, Qt::LeftButton);
    QTRY_VERIFY(failureStatus->text().contains("Capture error"));
    QTRY_COMPARE(failureWindow.errorCount(), std::uint64_t{1});
    QVERIFY(failureCounters->text().contains("Errors: 1"));
    QCOMPARE(failureState->closes, 1);
    QVERIFY(failureStart->isEnabled());
}

void CaptureGuiTests::recordingOverwriteRequiresConfirmation()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto path = directory.filePath("existing.pcap");
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("preserve", 8), qint64{8});
    }
    auto state = std::make_shared<BackendState>();
    auto window = makeWindow(state);
    auto* interfaces = window.findChild<QComboBox*>("interfaceCombo");
    auto* start = window.findChild<QPushButton*>("startButton");
    auto* stop = window.findChild<QPushButton*>("stopButton");
    auto* status = window.findChild<QLabel*>("statusLabel");
    QVERIFY(interfaces && start && stop && status);
    const auto openCount = [&] {
        std::lock_guard lock(state->mutex);
        return state->opens;
    };
    window.setRecordingDestination(path, false);
    interfaces->setCurrentIndex(1);
    const auto answerQuestion = [](QMessageBox::StandardButton answer) {
        QTimer::singleShot(0, qApp, [answer] {
            if (auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()))
                if (auto* button = box->button(answer))
                    button->click();
        });
    };
    answerQuestion(QMessageBox::No);
    start->click();
    QCOMPARE(openCount(), 0);
    QFile fileAfterDecline(path);
    QVERIFY(fileAfterDecline.open(QIODevice::ReadOnly));
    QCOMPARE(fileAfterDecline.readAll(), QByteArray("preserve", 8));
    fileAfterDecline.close();

    answerQuestion(QMessageBox::Yes);
    start->click();
    QTRY_VERIFY2(status->text().contains("Capturing"), qPrintable(status->text()));
    QCOMPARE(openCount(), 1);
    stop->click();
    QTRY_COMPARE(status->text(), QStringLiteral("Stopped"));
    QVERIFY(QFileInfo(path).size() >= 24);
}

void CaptureGuiTests::fixturePacketsReachRowsAndCounters()
{
    auto state = std::make_shared<BackendState>();
    const arp::MacAddress hostA{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a};
    const arp::MacAddress hostB{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};
    state->packets.push_back(
        makeCapturedArp(1, 1, {192, 0, 2, 10}, {198, 51, 100, 20}, hostA, arp::MacAddress{}));
    state->packets.push_back(
        makeCapturedArp(2, 2, {198, 51, 100, 20}, {192, 0, 2, 10}, hostB, hostA));
    arp::CapturedPacket malformed;
    malformed.bytes = {0x02, 0x00, 0x00};
    malformed.metadata.interfaceName = "synthetic0";
    malformed.metadata.capturedLength = 3;
    malformed.metadata.originalLength = 3;
    malformed.metadata.linkType = 1;
    state->packets.push_back(std::move(malformed));

    auto window = makeWindow(state);
    auto* interfaces = window.findChild<QComboBox*>("interfaceCombo");
    auto* start = window.findChild<QPushButton*>("startButton");
    auto* operation = window.findChild<QComboBox*>("operationFilter");
    auto* table = window.findChild<QTableView*>("packetTable");
    QVERIFY(interfaces && start && operation && table);
    interfaces->setCurrentIndex(1);
    start->click();
    QTRY_COMPARE(window.packetModel()->rowCount(), 2);
    QTRY_COMPARE(window.requestCount(), std::uint64_t{1});
    QTRY_COMPARE(window.replyCount(), std::uint64_t{1});
    QTRY_COMPARE(window.errorCount(), std::uint64_t{1});

    const auto& first = window.packetModel()->recordAt(0);
    QCOMPARE(first.metadata.sequenceNumber, std::uint64_t{1});
    QCOMPARE(first.metadata.interfaceName, std::string("synthetic0"));
    QCOMPARE(first.operation, arp::ArpOperation::Request);
    QCOMPARE(formatIpv4(first.senderIpv4), QStringLiteral("192.0.2.10"));
    QCOMPARE(formatMac(first.senderMac), QStringLiteral("02:00:00:00:00:0a"));
    QCOMPARE(table->model()->data(table->model()->index(0, 1)).toString(),
             QStringLiteral("Request"));

    operation->setCurrentIndex(1);
    QCOMPARE(table->model()->rowCount(), 1);
    QCOMPARE(window.requestCount(), std::uint64_t{1});
    QCOMPARE(window.replyCount(), std::uint64_t{1});
    QCOMPARE(window.errorCount(), std::uint64_t{1});
    window.findChild<arp::CaptureService*>()->stop();
    QTRY_COMPARE(window.findChild<QLabel*>("statusLabel")->text(), QStringLiteral("Stopped"));
}

void CaptureGuiTests::recordingAndReplayPreserveRowsBeyondDisplayLimit()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    constexpr std::size_t packetCount = 10050;
    auto state = std::make_shared<BackendState>();
    state->packetDelay = std::chrono::microseconds{50};
    state->packets.reserve(packetCount);
    const arp::MacAddress hostA{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a};
    const arp::MacAddress hostB{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};
    for (std::size_t index = 0; index < packetCount; ++index) {
        const bool request = (index & 1U) == 0;
        state->packets.push_back(makeCapturedArp(
            index + 1, request ? 1 : 2,
            request ? arp::Ipv4Address{192, 0, 2, 10} : arp::Ipv4Address{198, 51, 100, 20},
            request ? arp::Ipv4Address{198, 51, 100, 20} : arp::Ipv4Address{192, 0, 2, 10},
            request ? hostA : hostB, request ? arp::MacAddress{} : hostA));
    }
    const auto pcapPath = directory.filePath("session.pcap");
    auto window = makeWindow(state);
    auto* interfaces = window.findChild<QComboBox*>("interfaceCombo");
    auto* start = window.findChild<QPushButton*>("startButton");
    auto* stop = window.findChild<QPushButton*>("stopButton");
    auto* operation = window.findChild<QComboBox*>("operationFilter");
    auto* status = window.findChild<QLabel*>("statusLabel");
    QVERIFY(interfaces && start && stop && operation && status);
    window.setRecordingDestination(pcapPath, false);
    interfaces->setCurrentIndex(1);
    operation->setCurrentIndex(1);
    start->click();
    QTRY_COMPARE_WITH_TIMEOUT(window.requestCount() + window.replyCount(),
                              static_cast<std::uint64_t>(packetCount), 30000);
    QCOMPARE(window.requestCount(), std::uint64_t{5025});
    QCOMPARE(window.replyCount(), std::uint64_t{5025});
    QCOMPARE(window.errorCount(), std::uint64_t{0});
    QCOMPARE(window.packetModel()->rowCount(), 10000);
    QCOMPARE(window.packetModel()->discardedCount(), std::uint64_t{50});
    QVERIFY(window.findChild<QTableView*>("packetTable")->model()->rowCount() <= 10000);
    QVERIFY(window.findChild<QTableView*>("packetTable")->model()->rowCount() < 10000);
    stop->click();
    QTRY_COMPARE_WITH_TIMEOUT(status->text(), QStringLiteral("Stopped"), 10000);

    auto replayBackend = arp::makeOfflineBackend(pcapPath.toStdString());
    replayBackend->open("offline");
    std::size_t recordedCount = 0;
    for (;;) {
        const auto result = replayBackend->read();
        if (result.status == arp::ReadStatus::End)
            break;
        QCOMPARE(result.status, arp::ReadStatus::Packet);
        ++recordedCount;
    }
    replayBackend->close();
    QCOMPARE(recordedCount, packetCount);

    const auto allRowsPath = directory.filePath("all-retained.csv");
    const auto visibleRowsPath = directory.filePath("visible.csv");
    QVERIFY(window.exportRows(allRowsPath, false));
    QVERIFY(window.exportRows(visibleRowsPath, true));
    const auto countLines = [](const QString& path) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
            return qsizetype{-1};
        return file.readAll().count('\n');
    };
    QCOMPARE(countLines(allRowsPath), qsizetype{10001});
    QCOMPARE(countLines(visibleRowsPath), qsizetype{5001});

    QVERIFY(window.openRecording(pcapPath));
    QTRY_COMPARE_WITH_TIMEOUT(window.requestCount() + window.replyCount(),
                              static_cast<std::uint64_t>(packetCount), 30000);
    QCOMPARE(window.requestCount(), std::uint64_t{5025});
    QCOMPARE(window.replyCount(), std::uint64_t{5025});
    QCOMPARE(window.packetModel()->rowCount(), 10000);
    QCOMPARE(window.packetModel()->discardedCount(), std::uint64_t{50});
}

void CaptureGuiTests::interactiveCsvExportAcceptsWritableFilename()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto path = directory.filePath("interactive.csv");
    auto state = std::make_shared<BackendState>();
    auto window = makeWindow(state);
    window.appendRecords({makeRecord(1, arp::ArpOperation::Request, {192, 0, 2, 10},
                                     {192, 0, 2, 20}, {2, 0, 0, 0, 0, 10})});
    auto* exportButton = window.findChild<QPushButton*>("exportCsvButton");
    auto* status = window.findChild<QLabel*>("statusLabel");
    QVERIFY(exportButton && status);
    bool foundDialog = false;
    bool saveEnabled = false;
    int attempts = 0;
    QTimer automate;
    automate.setInterval(20);
    connect(&automate, &QTimer::timeout, &window, [&] {
        auto* dialog = qobject_cast<QFileDialog*>(QApplication::activeModalWidget());
        if (!dialog)
            return;
        foundDialog = true;
        if (attempts++ == 0) {
            dialog->setDirectory(directory.path());
            auto* filename = dialog->findChild<QLineEdit*>("fileNameEdit");
            if (filename) {
                filename->selectAll();
                QTest::keyClicks(filename, "interactive");
            }
            return;
        }
        auto* buttons = dialog->findChild<QDialogButtonBox*>();
        auto* save = buttons ? buttons->button(QDialogButtonBox::Save) : nullptr;
        saveEnabled = save && save->isEnabled();
        if (!saveEnabled && attempts < 50)
            return;
        automate.stop();
        if (saveEnabled)
            save->click();
        else
            dialog->reject();
    });
    automate.start();
    exportButton->click();
    automate.stop();
    QVERIFY(foundDialog);
    QVERIFY(saveEnabled);
    QTRY_COMPARE_WITH_TIMEOUT(status->text(), QStringLiteral("CSV export complete"), 10000);
    QVERIFY(exportButton->isEnabled());
    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const auto csv = file.readAll();
    QCOMPARE(csv.count('\n'), qsizetype{2});
    QVERIFY(csv.contains("192.0.2.10"));
    file.close();

    // Exercise the real button's cancel and separate overwrite decision paths.
    for (const auto decision : {QMessageBox::Cancel, QMessageBox::No, QMessageBox::Yes}) {
        if (decision != QMessageBox::Cancel) {
            QFile existing(path);
            QVERIFY(existing.open(QIODevice::WriteOnly | QIODevice::Truncate));
            QCOMPARE(existing.write("sentinel"), qint64{8});
        }
        bool picked = false;
        bool answered = false;
        QTimer interact;
        interact.setInterval(20);
        connect(&interact, &QTimer::timeout, &window, [&] {
            if (auto* picker = qobject_cast<QFileDialog*>(QApplication::activeModalWidget())) {
                if (decision == QMessageBox::Cancel) {
                    picked = true;
                    picker->reject();
                    return;
                }
                if (!picked) {
                    picker->setDirectory(directory.path());
                    auto* filename = picker->findChild<QLineEdit*>("fileNameEdit");
                    if (filename) {
                        filename->selectAll();
                        QTest::keyClicks(filename, "interactive.csv");
                    }
                    picked = true;
                    return;
                }
                auto* buttons = picker->findChild<QDialogButtonBox*>();
                auto* save = buttons ? buttons->button(QDialogButtonBox::Save) : nullptr;
                if (save && save->isEnabled())
                    save->click();
            } else if (auto* confirmation =
                           qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
                answered = true;
                confirmation->button(decision)->click();
            }
        });
        interact.start();
        exportButton->click();
        interact.stop();
        QVERIFY(picked);
        QCOMPARE(answered, decision != QMessageBox::Cancel);
        if (decision == QMessageBox::Yes)
            QTRY_VERIFY(exportButton->isEnabled());
        QFile result(path);
        QVERIFY(result.open(QIODevice::ReadOnly));
        const auto output = result.readAll();
        if (decision == QMessageBox::No)
            QCOMPARE(output, QByteArray("sentinel"));
        else
            QCOMPARE(output, csv);
    }
}

void CaptureGuiTests::optionalDeniedLiveAccess()
{
    const auto interface = qEnvironmentVariable("ARP_TEST_DENIED_INTERFACE");
    if (interface.isEmpty())
        QSKIP("Set ARP_TEST_DENIED_INTERFACE to explicitly exercise a denied live interface");
    MainWindow window(arp::makePcapBackend(), {{interface.toStdString(), "Denied access", false}});
    auto* interfaces = window.findChild<QComboBox*>("interfaceCombo");
    auto* start = window.findChild<QPushButton*>("startButton");
    auto* stop = window.findChild<QPushButton*>("stopButton");
    auto* status = window.findChild<QLabel*>("statusLabel");
    QVERIFY(interfaces && start && stop && status);
    interfaces->setCurrentIndex(1);
    start->click();
    QTRY_COMPARE_WITH_TIMEOUT(window.errorCount(), std::uint64_t{1}, 10000);
    const auto error = status->text();
    QVERIFY2(error.contains("Permission denied", Qt::CaseInsensitive) ||
                 error.contains("Operation not permitted", Qt::CaseInsensitive),
             qPrintable(error));
    QTRY_VERIFY(start->isEnabled());
    QVERIFY(!stop->isEnabled());
    QCOMPARE(window.packetModel()->rowCount(), 0);
    qInfo().noquote() << "Observed denied-access GUI status:" << error;
    window.close();
}

void CaptureGuiTests::closeDuringRecordingFlushesCompleteSession()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto path = directory.filePath("closed-session.pcap");
    auto state = std::make_shared<BackendState>();
    const arp::MacAddress host{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a};
    constexpr std::size_t packetCount = 128;
    std::vector<arp::CapturedPacket> expected;
    for (std::size_t index = 0; index < packetCount; ++index)
        expected.push_back(
            makeCapturedArp(index + 1, 1, {192, 0, 2, 10}, {192, 0, 2, 20}, host, {}));
    state->packets = expected;
    auto window = makeWindow(state);
    window.show();
    window.setRecordingDestination(path);
    auto* interfaces = window.findChild<QComboBox*>("interfaceCombo");
    auto* start = window.findChild<QPushButton*>("startButton");
    auto* status = window.findChild<QLabel*>("statusLabel");
    QVERIFY(interfaces && start && status);
    interfaces->setCurrentIndex(1);
    start->click();
    QTRY_COMPARE(window.requestCount(), static_cast<std::uint64_t>(packetCount));
    QVERIFY(window.isVisible());
    window.close();
    QTRY_VERIFY_WITH_TIMEOUT(!window.isVisible(), 10000);
    QTRY_COMPARE(status->text(), QStringLiteral("Stopped"));
    QCOMPARE(window.errorCount(), std::uint64_t{0});
    {
        std::lock_guard lock(state->mutex);
        QCOMPARE(state->closes, 1);
    }
    auto replay = arp::makeOfflineBackend(path.toStdString());
    replay->open("offline");
    for (const auto& packet : expected) {
        const auto read = replay->read();
        QCOMPARE(read.status, arp::ReadStatus::Packet);
        QCOMPARE(read.packet.bytes, packet.bytes);
        QCOMPARE(read.packet.metadata.captureTimestamp, packet.metadata.captureTimestamp);
        QCOMPARE(read.packet.metadata.capturedLength, packet.metadata.capturedLength);
        QCOMPARE(read.packet.metadata.originalLength, packet.metadata.originalLength);
    }
    QCOMPARE(replay->read().status, arp::ReadStatus::End);
    replay->close();
}

void CaptureGuiTests::countersIgnoreDisplayFiltersAndDetailsFollowSelection()
{
    auto state = std::make_shared<BackendState>();
    auto window = makeWindow(state);
    auto* operation = window.findChild<QComboBox*>("operationFilter");
    auto* ip = window.findChild<QLineEdit*>("ipFilter");
    auto* mac = window.findChild<QLineEdit*>("macFilter");
    auto* table = window.findChild<QTableView*>("packetTable");
    auto* details = window.findChild<QPlainTextEdit*>("detailsPane");
    auto* counters = window.findChild<QLabel*>("countersLabel");
    QVERIFY(operation && ip && mac && table && details && counters);

    const auto request =
        makeRecord(2, arp::ArpOperation::Request, {192, 0, 2, 10}, {198, 51, 100, 20},
                   {0x02, 0x10, 0, 0, 0, 1}, {{0x8100, 0xb064}});
    const auto reply = makeRecord(1, arp::ArpOperation::Reply, {198, 51, 100, 20}, {192, 0, 2, 10},
                                  {0x02, 0x20, 0, 0, 0, 2});
    window.appendRecords({request, reply});
    QCOMPARE(window.packetModel()->rowCount(), 2);
    QCOMPARE(window.requestCount(), std::uint64_t{1});
    QCOMPARE(window.replyCount(), std::uint64_t{1});

    operation->setCurrentIndex(1);
    QCOMPARE(table->model()->rowCount(), 1);
    ip->setText("198.51.100");
    QCOMPARE(table->model()->rowCount(), 1);
    mac->setText("02:10");
    QCOMPARE(table->model()->rowCount(), 1);
    QCOMPARE(window.requestCount(), std::uint64_t{1});
    QCOMPARE(window.replyCount(), std::uint64_t{1});
    QVERIFY(counters->text().contains("Requests: 1"));
    QVERIFY(counters->text().contains("Replies: 1"));

    const auto index = table->model()->index(0, 0);
    table->setCurrentIndex(index);
    QTRY_VERIFY(details->toPlainText().contains("VLAN tags: 1"));
    QVERIFY(details->toPlainText().contains("TPID 0x8100"));
    QVERIFY(details->toPlainText().contains("Ethernet source:"));

    operation->setCurrentIndex(0);
    ip->clear();
    mac->clear();
    QCOMPARE(table->model()->rowCount(), 2);
    table->sortByColumn(1, Qt::AscendingOrder);
    QCOMPARE(table->model()->data(table->model()->index(0, 1)).toString(), QStringLiteral("Reply"));
    table->sortByColumn(0, Qt::AscendingOrder);
    QCOMPARE(table->model()->data(table->model()->index(0, 0)).toString(),
             QStringLiteral("1970-01-01 00:00:00.001 UTC"));
}

void CaptureGuiTests::retainsNewestTenThousandAndStaysResponsive()
{
    auto state = std::make_shared<BackendState>();
    auto window = makeWindow(state);
    window.show();
    QTRY_VERIFY(window.isVisible());
    constexpr std::uint64_t total = 100000;
    constexpr std::size_t batchSize = 1000;
    constexpr std::size_t batches = static_cast<std::size_t>(total) / batchSize;
    std::size_t completed = 0;
    int heartbeats = 0;
    qint64 lastHeartbeat = 0;
    qint64 maximumHeartbeatGap = 0;
    QElapsedTimer elapsed;
    QTimer heartbeat;
    heartbeat.setInterval(1);
    connect(&heartbeat, &QTimer::timeout, this, [&] {
        ++heartbeats;
        const auto now = elapsed.elapsed();
        if (lastHeartbeat != 0)
            maximumHeartbeatGap = std::max(maximumHeartbeatGap, now - lastHeartbeat);
        lastHeartbeat = now;
    });
    QTimer producer;
    producer.setInterval(0);
    connect(&producer, &QTimer::timeout, this, [&] {
        std::vector<arp::ArpRecord> batch;
        batch.reserve(batchSize);
        for (std::size_t offset = 0; offset < batchSize; ++offset) {
            const auto sequence = static_cast<std::uint64_t>(completed * batchSize + offset);
            const bool request = (sequence & 1U) == 0;
            batch.push_back(makeRecord(
                sequence, request ? arp::ArpOperation::Request : arp::ArpOperation::Reply,
                {192, 0, 2, static_cast<std::uint8_t>(sequence % 250 + 1)}, {198, 51, 100, 1},
                {0x02, 0, 0, 0, 0, 1}));
        }
        window.appendRecords(batch);
        ++completed;
        if (completed == batches)
            producer.stop();
    });
    heartbeat.start();
    elapsed.start();
    producer.start();
    QTRY_VERIFY_WITH_TIMEOUT(completed == batches, 30000);
    const auto milliseconds = elapsed.elapsed();
    heartbeat.stop();

    QCOMPARE(window.packetModel()->rowCount(), 10000);
    QCOMPARE(window.packetModel()->discardedCount(), std::uint64_t{90000});
    QCOMPARE(window.packetModel()->recordAt(0).metadata.sequenceNumber, std::uint64_t{90000});
    QCOMPARE(window.packetModel()->recordAt(9999).metadata.sequenceNumber, std::uint64_t{99999});
    QCOMPARE(window.requestCount(), std::uint64_t{50000});
    QCOMPARE(window.replyCount(), std::uint64_t{50000});
    QVERIFY(heartbeats > 0);
    QVERIFY2(maximumHeartbeatGap < 1000, "Owner-thread heartbeat stalled for one second");
    qInfo().noquote() << "100,000 synthetic records on" << QSysInfo::prettyProductName() << "("
                      << QSysInfo::currentCpuArchitecture() << "):" << milliseconds << "ms;"
                      << heartbeats << "owner-thread timer ticks; maximum gap"
                      << maximumHeartbeatGap << "ms";
}

QTEST_MAIN(CaptureGuiTests)
#include "CaptureGuiTests.moc"
