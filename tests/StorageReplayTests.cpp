#include "capture/CaptureService.hpp"
#include "storage/CsvExport.hpp"
#include "storage/SessionWriter.hpp"

#include <QFile>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

#include <pcap/pcap.h>

#include <condition_variable>
#include <mutex>
#include <thread>

namespace
{
using Bytes = std::vector<std::uint8_t>;

arp::CapturedPacket makePacket(std::uint64_t sequence)
{
    arp::CapturedPacket packet;
    const arp::MacAddress destination{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const arp::MacAddress source{0x02, 0x10, 0x20,
                                 0x30, 0x40, static_cast<std::uint8_t>(sequence & 0xff)};
    const arp::Ipv4Address sender{192, 0, 2, static_cast<std::uint8_t>(sequence % 250 + 1)};
    const arp::MacAddress target{};
    const arp::Ipv4Address targetIp{198, 51, 100, 129};
    const auto address = [&packet](const auto& value) {
        packet.bytes.insert(packet.bytes.end(), value.begin(), value.end());
    };
    const auto word = [&packet](std::uint16_t value) {
        packet.bytes.push_back(static_cast<std::uint8_t>(value >> 8));
        packet.bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
    };
    address(destination);
    address(source);
    word(0x0806);
    word(1);
    word(0x0800);
    packet.bytes.insert(packet.bytes.end(), {6, 4});
    word(sequence % 2 == 0 ? 1 : 2);
    address(source);
    address(sender);
    address(target);
    address(targetIp);
    packet.metadata.sequenceNumber = sequence;
    packet.metadata.captureTimestamp =
        std::chrono::nanoseconds{1735689600123456789LL} + std::chrono::nanoseconds{sequence * 37};
    packet.metadata.interfaceName = "fixture0";
    packet.metadata.capturedLength = static_cast<std::uint32_t>(packet.bytes.size());
    packet.metadata.originalLength = packet.metadata.capturedLength + 18;
    packet.metadata.linkType = 1;
    return packet;
}

struct SinkState {
    std::mutex mutex;
    std::condition_variable changed;
    bool failOpen = false;
    bool failWrite = false;
    bool failFinish = false;
    bool blockOpen = false;
    bool openEntered = false;
    bool releaseOpen = false;
    bool blockFirstWrite = false;
    bool firstWriteEntered = false;
    bool releaseWrite = false;
    int opens = 0;
    int writes = 0;
    int finishes = 0;
    std::vector<std::uint64_t> sequences;
};

class FakeSink final : public arp::IRecordingSink
{
  public:
    explicit FakeSink(std::shared_ptr<SinkState> state) : state_(std::move(state)) {}
    void open(const std::string&, int, bool) override
    {
        std::unique_lock lock(state_->mutex);
        ++state_->opens;
        state_->openEntered = true;
        state_->changed.notify_all();
        if (state_->blockOpen)
            state_->changed.wait(lock, [this] { return state_->releaseOpen; });
        if (state_->failOpen)
            throw std::runtime_error("synthetic open failure");
    }
    void write(const arp::CapturedPacket& packet) override
    {
        std::unique_lock lock(state_->mutex);
        ++state_->writes;
        state_->sequences.push_back(packet.metadata.sequenceNumber);
        if (state_->writes == 1 && state_->blockFirstWrite) {
            state_->firstWriteEntered = true;
            state_->changed.notify_all();
            state_->changed.wait(lock, [this] { return state_->releaseWrite; });
        }
        state_->changed.notify_all();
        if (state_->failWrite)
            throw std::runtime_error("synthetic write failure");
    }
    void finish() override
    {
        std::lock_guard lock(state_->mutex);
        ++state_->finishes;
        state_->changed.notify_all();
        if (state_->failFinish)
            throw std::runtime_error("synthetic flush failure");
    }

  private:
    std::shared_ptr<SinkState> state_;
};

struct BackendState {
    std::mutex mutex;
    std::condition_variable changed;
    bool interrupted = false;
    bool failOpen = false;
    int opens = 0;
    std::size_t nextPacket = 0;
    std::vector<arp::CapturedPacket> packets;
    std::shared_ptr<SinkState> pacedSink;
};

class FakeBackend final : public arp::ICaptureBackend
{
  public:
    explicit FakeBackend(std::shared_ptr<BackendState> state) : state_(std::move(state)) {}
    void open(const std::string&) override
    {
        std::lock_guard lock(state_->mutex);
        ++state_->opens;
        if (state_->failOpen)
            throw std::runtime_error("synthetic backend open failure");
    }
    arp::BackendRead read() override
    {
        std::unique_lock lock(state_->mutex);
        if (state_->nextPacket < state_->packets.size()) {
            const auto index = state_->nextPacket++;
            auto packet = std::move(state_->packets[index]);
            auto pacedSink = state_->pacedSink;
            lock.unlock();
            if (pacedSink && index != 0) {
                std::unique_lock sinkLock(pacedSink->mutex);
                if (!pacedSink->changed.wait_for(sinkLock, std::chrono::seconds(3), [&] {
                        return static_cast<std::size_t>(pacedSink->writes) >= index;
                    }))
                    return {arp::ReadStatus::Error, {}, "recording sink pacing timed out"};
            }
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
    void close() noexcept override {}
    arp::CaptureStatistics statistics() override { return {}; }
    int linkType() const override { return 1; }

  private:
    std::shared_ptr<BackendState> state_;
};

void writePcap(const std::string& path, const std::vector<arp::CapturedPacket>& packets)
{
    pcap_t* dead =
        pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 65535, PCAP_TSTAMP_PRECISION_NANO);
    if (!dead)
        throw std::runtime_error("cannot create synthetic PCAP handle");
    pcap_dumper_t* dumper = pcap_dump_open(dead, path.c_str());
    if (!dumper) {
        pcap_close(dead);
        throw std::runtime_error("cannot create synthetic PCAP file");
    }
    for (const auto& packet : packets) {
        const auto timestamp = packet.metadata.captureTimestamp.count();
        pcap_pkthdr header{};
        header.caplen = packet.metadata.capturedLength;
        header.len = packet.metadata.originalLength;
        header.ts.tv_sec = static_cast<decltype(header.ts.tv_sec)>(timestamp / 1000000000LL);
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>(timestamp % 1000000000LL);
        pcap_dump(reinterpret_cast<u_char*>(dumper), &header, packet.bytes.data());
    }
    const bool failed = pcap_dump_flush(dumper) != 0;
    pcap_dump_close(dumper);
    pcap_close(dead);
    if (failed)
        throw std::runtime_error("cannot flush synthetic PCAP file");
}

std::string readFile(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        throw std::runtime_error("cannot read test output");
    return file.readAll().toStdString();
}

} // namespace

class StorageReplayTests : public QObject
{
    Q_OBJECT
  private slots:
    void pcapRoundTripPreservesBytesLengthsAndNanoseconds();
    void writerIdleActiveAndFailurePaths();
    void writerQueueOverflowIsReported();
    void serviceSurfacesRecordingOpenWriteAndFlushErrorsDuringStop();
    void destinationOverwriteProtection();
    void csvQuotingScopeAndOverwrite();
    void malformedPcapIsRejected();
    void replayDrainsMoreThanGuiQueueCapacity();
    void recordingPrecedesBackendOpenAndSurvivesGuiQueueDrops();
};

void StorageReplayTests::pcapRoundTripPreservesBytesLengthsAndNanoseconds()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto path = directory.filePath("roundtrip.pcap");
    const auto original = makePacket(11);
    arp::SessionWriter writer;
    writer.start(path.toStdString());
    QVERIFY(writer.enqueue(original));
    writer.finish();

    char error[PCAP_ERRBUF_SIZE]{};
    pcap_t* handle = pcap_open_offline_with_tstamp_precision(path.toStdString().c_str(),
                                                             PCAP_TSTAMP_PRECISION_NANO, error);
    QVERIFY2(handle != nullptr, error);
    QCOMPARE(pcap_datalink(handle), DLT_EN10MB);
    pcap_pkthdr* header = nullptr;
    const u_char* bytes = nullptr;
    QCOMPARE(pcap_next_ex(handle, &header, &bytes), 1);
    QCOMPARE(header->caplen, original.metadata.capturedLength);
    QCOMPARE(header->len, original.metadata.originalLength);
    QCOMPARE(static_cast<std::int64_t>(header->ts.tv_sec) * 1000000000LL + header->ts.tv_usec,
             original.metadata.captureTimestamp.count());
    QVERIFY(Bytes(bytes, bytes + header->caplen) == original.bytes);
    pcap_close(handle);

    auto replay = arp::makeOfflineBackend(path.toStdString());
    replay->open("offline");
    const auto result = replay->read();
    QCOMPARE(result.status, arp::ReadStatus::Packet);
    QVERIFY(result.packet.bytes == original.bytes);
    QCOMPARE(result.packet.metadata.capturedLength, original.metadata.capturedLength);
    QCOMPARE(result.packet.metadata.originalLength, original.metadata.originalLength);
    QCOMPARE(result.packet.metadata.captureTimestamp.count(),
             original.metadata.captureTimestamp.count());
    QCOMPARE(result.packet.metadata.linkType, original.metadata.linkType);
    QCOMPARE(result.packet.metadata.sequenceNumber, std::uint64_t{1});
    replay->close();
}

void StorageReplayTests::writerIdleActiveAndFailurePaths()
{
    auto idleState = std::make_shared<SinkState>();
    arp::SessionWriter idle(std::make_unique<FakeSink>(idleState));
    idle.start("memory", 1);
    idle.finish();
    QCOMPARE(idleState->writes, 0);
    QCOMPARE(idleState->finishes, 1);

    auto activeState = std::make_shared<SinkState>();
    arp::SessionWriter active(std::make_unique<FakeSink>(activeState));
    active.start("memory", 1);
    for (std::uint64_t sequence = 1; sequence <= 20; ++sequence)
        QVERIFY(active.enqueue(makePacket(sequence)));
    active.finish();
    QCOMPARE(activeState->writes, 20);
    QCOMPARE(activeState->finishes, 1);

    auto openFailure = std::make_shared<SinkState>();
    openFailure->failOpen = true;
    arp::SessionWriter openWriter(std::make_unique<FakeSink>(openFailure));
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, openWriter.start("memory"));
    QCOMPARE(openFailure->finishes, 1);

    auto writeFailure = std::make_shared<SinkState>();
    writeFailure->failWrite = true;
    arp::SessionWriter writeWriter(std::make_unique<FakeSink>(writeFailure));
    writeWriter.start("memory");
    QVERIFY(writeWriter.enqueue(makePacket(1)));
    QTRY_VERIFY(!writeWriter.error().empty());
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, writeWriter.finish());
    QVERIFY(writeWriter.error().find("write failure") != std::string::npos);

    auto flushFailure = std::make_shared<SinkState>();
    flushFailure->failFinish = true;
    arp::SessionWriter flushWriter(std::make_unique<FakeSink>(flushFailure));
    flushWriter.start("memory");
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, flushWriter.finish());
    QVERIFY(flushWriter.error().find("flush failure") != std::string::npos);

    for (const auto invalid : {0, 1, 2, 3, 4}) {
        auto packet = makePacket(1);
        switch (invalid) {
        case 0:
            packet.metadata.linkType = 12;
            break;
        case 1:
            ++packet.metadata.capturedLength;
            break;
        case 2:
            packet.metadata.originalLength = packet.metadata.capturedLength - 1;
            break;
        case 3:
            packet.metadata.captureTimestamp = std::chrono::nanoseconds{-1};
            break;
        case 4:
            packet.metadata.captureTimestamp =
                std::chrono::nanoseconds{5000000000LL} * 1000000000LL;
            break;
        }
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        arp::SessionWriter invalidWriter;
        invalidWriter.start(directory.filePath("invalid.pcap").toStdString());
        QVERIFY(invalidWriter.enqueue(std::move(packet)));
        QTRY_VERIFY(!invalidWriter.error().empty());
        QVERIFY_THROWS_EXCEPTION(std::runtime_error, invalidWriter.finish());
    }
}

void StorageReplayTests::writerQueueOverflowIsReported()
{
    auto state = std::make_shared<SinkState>();
    state->blockFirstWrite = true;
    arp::SessionWriter writer(std::make_unique<FakeSink>(state));
    writer.start("memory");
    QVERIFY(writer.enqueue(makePacket(1)));
    {
        std::unique_lock lock(state->mutex);
        QVERIFY(state->changed.wait_for(lock, std::chrono::seconds(3),
                                        [&] { return state->firstWriteEntered; }));
    }
    for (std::size_t index = 0; index < arp::SessionWriter::queueCapacity; ++index)
        QVERIFY(writer.enqueue(makePacket(index + 2)));
    QVERIFY(!writer.enqueue(makePacket(9999)));
    QVERIFY(writer.error().find("overflow") != std::string::npos);
    {
        std::lock_guard lock(state->mutex);
        state->releaseWrite = true;
    }
    state->changed.notify_all();
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, writer.finish());
    QCOMPARE(state->writes, static_cast<int>(arp::SessionWriter::queueCapacity + 1));
    QCOMPARE(state->finishes, 1);
}

void StorageReplayTests::serviceSurfacesRecordingOpenWriteAndFlushErrorsDuringStop()
{
    auto openSinkState = std::make_shared<SinkState>();
    openSinkState->blockOpen = true;
    openSinkState->failOpen = true;
    auto openBackendState = std::make_shared<BackendState>();
    arp::CaptureService openService(std::make_unique<FakeBackend>(openBackendState));
    openService.setRecording("memory", false, std::make_unique<FakeSink>(openSinkState));
    QSignalSpy openErrors(&openService, &arp::CaptureService::errorOccurred);
    QVERIFY(openService.start("fake0"));
    QTRY_VERIFY([&] {
        std::lock_guard lock(openSinkState->mutex);
        return openSinkState->openEntered;
    }());
    openService.stop();
    {
        std::lock_guard lock(openSinkState->mutex);
        openSinkState->releaseOpen = true;
    }
    openSinkState->changed.notify_all();
    QTRY_COMPARE(openErrors.count(), 1);
    QCOMPARE(openService.state(), arp::CaptureState::Error);
    QCOMPARE(openBackendState->opens, 0);
    QVERIFY(openErrors.front().front().toString().contains("open failure"));

    auto writeSinkState = std::make_shared<SinkState>();
    writeSinkState->failWrite = true;
    auto writeBackendState = std::make_shared<BackendState>();
    writeBackendState->packets.push_back(makePacket(1));
    arp::CaptureService writeService(std::make_unique<FakeBackend>(writeBackendState));
    writeService.setRecording("memory", false, std::make_unique<FakeSink>(writeSinkState));
    QSignalSpy writeErrors(&writeService, &arp::CaptureService::errorOccurred);
    QVERIFY(writeService.start("fake0"));
    QTRY_COMPARE(writeService.state(), arp::CaptureState::Running);
    QTRY_VERIFY([&] {
        std::lock_guard lock(writeSinkState->mutex);
        return writeSinkState->writes > 0;
    }());
    writeService.stop();
    QTRY_COMPARE(writeErrors.count(), 1);
    QCOMPARE(writeService.state(), arp::CaptureState::Error);
    QVERIFY(writeErrors.front().front().toString().contains("write failure"));

    auto flushSinkState = std::make_shared<SinkState>();
    flushSinkState->failFinish = true;
    auto flushBackendState = std::make_shared<BackendState>();
    arp::CaptureService flushService(std::make_unique<FakeBackend>(flushBackendState));
    flushService.setRecording("memory", false, std::make_unique<FakeSink>(flushSinkState));
    QSignalSpy flushErrors(&flushService, &arp::CaptureService::errorOccurred);
    QVERIFY(flushService.start("fake0"));
    QTRY_COMPARE(flushService.state(), arp::CaptureState::Running);
    flushService.stop();
    QTRY_COMPARE(flushErrors.count(), 1);
    QCOMPARE(flushService.state(), arp::CaptureState::Error);
    QVERIFY(flushErrors.front().front().toString().contains("flush failure"));
}

void StorageReplayTests::destinationOverwriteProtection()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto path = directory.filePath("existing.pcap");
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("keep-this", 9), qint64{9});
    }
    arp::SessionWriter writer;
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, writer.start(path.toStdString(), 1, false));
    QCOMPARE(readFile(path), std::string("keep-this"));

    QVERIFY_THROWS_EXCEPTION(std::runtime_error,
                             writer.start(directory.path().toStdString(), 1, true));
    QVERIFY_THROWS_EXCEPTION(
        std::runtime_error,
        writer.start(directory.filePath("missing/out.pcap").toStdString(), 1, true));
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, writer.start(path.toStdString(), DLT_RAW, true));

    writer.start(path.toStdString(), 1, true);
    writer.finish();
    QVERIFY(readFile(path).size() >= 24);
}

void StorageReplayTests::csvQuotingScopeAndOverwrite()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto first = makePacket(11);
    arp::ArpRecord row;
    row.metadata = first.metadata;
    row.metadata.interfaceName = "eth0, \"lab\"\nsecond";
    row.operation = arp::ArpOperation::Request;
    row.ethernetSource = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    row.ethernetDestination = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    row.senderMac = row.ethernetSource;
    row.senderIpv4 = {192, 0, 2, 7};
    row.targetMac = {};
    row.targetIpv4 = {198, 51, 100, 129};
    row.vlanTags = {{0x8100, 0xb064}, {0x88a8, 7}};
    row.metadata.captureTimestamp = std::chrono::nanoseconds{9876543210LL};
    const auto path = directory.filePath("rows.csv");
    arp::exportCsv(path.toStdString(), {row});
    const auto csv = readFile(path);
    QVERIFY(csv.find("sequence,timestamp_unix_nanoseconds,interface,operation,") == 0);
    const std::string escapedRow =
        "\"11\",\"9876543210\",\"eth0, \"\"lab\"\"\nsecond\",\"Request\","
        "\"02:10:20:30:40:50\",\"ff:ff:ff:ff:ff:ff\",\"02:10:20:30:40:50\","
        "\"192.0.2.7\",\"00:00:00:00:00:00\",\"198.51.100.129\","
        "\"33024:45156;34984:7\",\"42\",\"60\"\r\n";
    QVERIFY(csv.find(escapedRow) != std::string::npos);
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, arp::exportCsv(path.toStdString(), {row}, false));
    const auto selectedPath = directory.filePath("selection.csv");
    auto secondRow = row;
    secondRow.metadata.sequenceNumber = 12;
    arp::exportCsv(path.toStdString(), {row, secondRow}, true);
    const auto allRetained = readFile(path);
    QVERIFY(allRetained.find("\"11\"") != std::string::npos);
    QVERIFY(allRetained.find("\"12\"") != std::string::npos);
    arp::exportCsv(selectedPath.toStdString(), {row}, false);
    const auto selected = readFile(selectedPath);
    QVERIFY(selected.find("\"11\"") != std::string::npos);
    QVERIFY(selected.find("\"12\"") == std::string::npos);
    QVERIFY_THROWS_EXCEPTION(std::runtime_error,
                             arp::exportCsv(selectedPath.toStdString(), {}, false));
    arp::exportCsv(selectedPath.toStdString(), {row}, true);
}

void StorageReplayTests::malformedPcapIsRejected()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto path = directory.filePath("malformed.pcap");
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly));
    QCOMPARE(file.write("not a pcap", 10), qint64{10});
    file.close();
    auto backend = arp::makeOfflineBackend(path.toStdString());
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, backend->open("offline"));
}

void StorageReplayTests::replayDrainsMoreThanGuiQueueCapacity()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    constexpr std::uint64_t packetCount = 600;
    std::vector<arp::CapturedPacket> packets;
    packets.reserve(packetCount);
    for (std::uint64_t sequence = 1; sequence <= packetCount; ++sequence)
        packets.push_back(makePacket(sequence));
    const auto path = directory.filePath("many.pcap");
    writePcap(path.toStdString(), packets);

    arp::CaptureService service(arp::makeOfflineBackend(path.toStdString()));
    service.setReplayMode(true);
    std::vector<std::uint64_t> delivered;
    connect(&service, &arp::CaptureService::packetsAvailable, &service, [&] {
        for (;;) {
            auto batch = service.takeBatch(64);
            if (batch.empty())
                break;
            for (const auto& packet : batch)
                delivered.push_back(packet.metadata.sequenceNumber);
        }
    });
    QVERIFY(service.start("offline"));
    QTRY_COMPARE_WITH_TIMEOUT(service.state(), arp::CaptureState::Stopped, 10000);
    QTRY_COMPARE_WITH_TIMEOUT(delivered.size(), static_cast<std::size_t>(packetCount), 10000);
    QCOMPARE(service.applicationDrops(), std::uint64_t{0});
    for (std::uint64_t index = 0; index < packetCount; ++index)
        QCOMPARE(delivered[static_cast<std::size_t>(index)], index + 1);
}

void StorageReplayTests::recordingPrecedesBackendOpenAndSurvivesGuiQueueDrops()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const auto existingPath = directory.filePath("blocked.pcap");
    {
        QFile file(existingPath);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("preserve", 8), qint64{8});
    }
    auto unopenedState = std::make_shared<BackendState>();
    arp::CaptureService unopened(std::make_unique<FakeBackend>(unopenedState));
    unopened.setRecording(existingPath.toStdString(), false);
    QVERIFY(unopened.start("fake0"));
    QTRY_COMPARE(unopened.state(), arp::CaptureState::Error);
    QCOMPARE(unopenedState->opens, 0);
    QCOMPARE(readFile(existingPath), std::string("preserve"));

    auto sinkState = std::make_shared<SinkState>();
    auto backendState = std::make_shared<BackendState>();
    backendState->pacedSink = sinkState;
    constexpr std::size_t packetCount = 400;
    backendState->packets.reserve(packetCount);
    for (std::size_t index = 0; index < packetCount; ++index)
        backendState->packets.push_back(makePacket(index + 1));
    arp::CaptureService service(std::make_unique<FakeBackend>(backendState));
    service.setRecording("memory", false, std::make_unique<FakeSink>(sinkState));
    QVERIFY(service.start("fake0"));
    QTRY_COMPARE_WITH_TIMEOUT(sinkState->writes, static_cast<int>(packetCount), 10000);
    service.stop();
    QTRY_COMPARE_WITH_TIMEOUT(service.state(), arp::CaptureState::Stopped, 10000);
    QCOMPARE(service.applicationDrops(),
             std::uint64_t{packetCount - arp::CaptureService::queueCapacity});
    QCOMPARE(sinkState->writes, static_cast<int>(packetCount));
    QCOMPARE(sinkState->finishes, 1);
    QCOMPARE(sinkState->sequences.front(), std::uint64_t{1});
    QCOMPARE(sinkState->sequences.back(), std::uint64_t{packetCount});
}

QTEST_GUILESS_MAIN(StorageReplayTests)
#include "StorageReplayTests.moc"
