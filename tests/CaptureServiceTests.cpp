#include "capture/CaptureService.hpp"

#include <QSignalSpy>
#include <QTest>
#include <QTimer>

#include <condition_variable>
#include <mutex>
#include <stdexcept>

namespace
{
struct FakeState {
    std::mutex mutex;
    std::condition_variable changed;
    bool interrupted = false;
    bool failOpen = false;
    bool failRead = false;
    bool failOnlyFirstRead = false;
    bool blockOpen = false;
    bool openEntered = false;
    bool blockClose = false;
    bool closeEntered = false;
    bool releaseClose = false;
    int linkType = 1;
    int opens = 0;
    int closes = 0;
    std::size_t packetsProduced = 0;
    std::size_t packetLimit = 0;
    arp::CaptureStatistics statistics{12, 3, std::nullopt};
};

class FakeBackend final : public arp::ICaptureBackend
{
  public:
    explicit FakeBackend(std::shared_ptr<FakeState> state) : state_(std::move(state)) {}

    void open(const std::string&) override
    {
        std::unique_lock lock(state_->mutex);
        ++state_->opens;
        state_->interrupted = false;
        state_->packetsProduced = 0;
        state_->openEntered = true;
        state_->changed.notify_all();
        if (state_->blockOpen)
            state_->changed.wait(lock, [this] { return state_->interrupted; });
        if (state_->failOpen)
            throw std::runtime_error("synthetic open failure");
    }

    arp::BackendRead read() override
    {
        std::unique_lock lock(state_->mutex);
        if (state_->failRead || (state_->failOnlyFirstRead && state_->opens == 1))
            return {arp::ReadStatus::Error, {}, "synthetic read failure"};
        if (state_->packetLimit != 0 && state_->packetsProduced < state_->packetLimit) {
            arp::CapturedPacket packet;
            packet.metadata.sequenceNumber = ++state_->packetsProduced;
            packet.bytes = {static_cast<std::uint8_t>(packet.metadata.sequenceNumber & 0xff)};
            state_->changed.notify_all();
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
    arp::CaptureStatistics statistics() override { return state_->statistics; }
    int linkType() const override { return state_->linkType; }

  private:
    std::shared_ptr<FakeState> state_;
};

std::unique_ptr<arp::CaptureService> makeService(const std::shared_ptr<FakeState>& state)
{
    return std::make_unique<arp::CaptureService>(std::make_unique<FakeBackend>(state));
}
} // namespace

class CaptureServiceTests : public QObject
{
    Q_OBJECT
  private slots:
    void idleStopRestartAndDestruction();
    void asynchronousStartStopAndOwnerResponsiveness();
    void openAndReadFailures();
    void copiesPacketsAndBoundsQueue();
    void suppressesQueuedEventsFromPriorSession();
};

void CaptureServiceTests::idleStopRestartAndDestruction()
{
    auto state = std::make_shared<FakeState>();
    {
        auto service = makeService(state);
        QVERIFY(service->start("fake0"));
        QTRY_COMPARE(service->state(), arp::CaptureState::Running);
        service->stop();
        QTRY_COMPARE(service->state(), arp::CaptureState::Stopped);
        QVERIFY(service->start("fake0"));
        QTRY_COMPARE(service->state(), arp::CaptureState::Running);
        service->stop();
        QTRY_COMPARE(service->state(), arp::CaptureState::Stopped);
        QCOMPARE(state->opens, 2);
        QCOMPARE(state->closes, 2);
    }
    auto idleState = std::make_shared<FakeState>();
    auto idle = makeService(idleState);
    QVERIFY(idle->start("idle0"));
    idle.reset();
    QCOMPARE(idleState->closes, 1);
}

void CaptureServiceTests::asynchronousStartStopAndOwnerResponsiveness()
{
    auto opening = std::make_shared<FakeState>();
    opening->blockOpen = true;
    auto service = makeService(opening);
    QTimer ownerTimer;
    int ticks = 0;
    connect(&ownerTimer, &QTimer::timeout, this, [&ticks] { ++ticks; });
    ownerTimer.start(1);
    QVERIFY(service->start("slow-open"));
    QTRY_VERIFY([&] {
        std::lock_guard lock(opening->mutex);
        return opening->openEntered;
    }());
    QTRY_VERIFY(ticks > 0);
    QCOMPARE(service->state(), arp::CaptureState::Starting);
    service->stop();
    QTRY_COMPARE(service->state(), arp::CaptureState::Stopped);
    QCOMPARE(opening->closes, 1);
    ownerTimer.stop();

    auto cleaning = std::make_shared<FakeState>();
    cleaning->blockClose = true;
    auto cleanupService = makeService(cleaning);
    ownerTimer.start(1);
    QVERIFY(cleanupService->start("slow-close"));
    QTRY_COMPARE(cleanupService->state(), arp::CaptureState::Running);
    cleanupService->stop();
    QTRY_VERIFY([&] {
        std::lock_guard lock(cleaning->mutex);
        return cleaning->closeEntered;
    }());
    const int beforeCleanupWait = ticks;
    QTRY_VERIFY(ticks > beforeCleanupWait);
    {
        std::lock_guard lock(cleaning->mutex);
        cleaning->releaseClose = true;
    }
    cleaning->changed.notify_all();
    QTRY_COMPARE(cleanupService->state(), arp::CaptureState::Stopped);
    QCOMPARE(cleaning->closes, 1);
    ownerTimer.stop();
}

void CaptureServiceTests::openAndReadFailures()
{
    auto openState = std::make_shared<FakeState>();
    openState->failOpen = true;
    auto openService = makeService(openState);
    QSignalSpy openErrors(openService.get(), &arp::CaptureService::errorOccurred);
    QVERIFY(openService->start("fake0"));
    QTRY_COMPARE(openService->state(), arp::CaptureState::Error);
    QTRY_COMPARE(openErrors.count(), 1);
    QCOMPARE(openState->closes, 1);

    auto linkState = std::make_shared<FakeState>();
    linkState->linkType = 12;
    auto linkService = makeService(linkState);
    QVERIFY(linkService->start("fake0"));
    QTRY_COMPARE(linkService->state(), arp::CaptureState::Error);
    QCOMPARE(linkState->closes, 1);

    auto readState = std::make_shared<FakeState>();
    readState->failRead = true;
    auto readService = makeService(readState);
    QSignalSpy readErrors(readService.get(), &arp::CaptureService::errorOccurred);
    QVERIFY(readService->start("fake0"));
    QTRY_COMPARE(readService->state(), arp::CaptureState::Error);
    QTRY_COMPARE(readErrors.count(), 1);
    QCOMPARE(readState->closes, 1);
}

void CaptureServiceTests::copiesPacketsAndBoundsQueue()
{
    auto state = std::make_shared<FakeState>();
    state->packetLimit = arp::CaptureService::queueCapacity + 20;
    auto service = makeService(state);
    QVERIFY(service->start("fake0"));
    QTRY_COMPARE(service->state(), arp::CaptureState::Running);
    {
        std::unique_lock lock(state->mutex);
        QVERIFY(state->changed.wait_for(lock, std::chrono::seconds(3), [&] {
            return state->packetsProduced == state->packetLimit;
        }));
    }
    QTRY_COMPARE(service->applicationDrops(), std::uint64_t{20});
    QCOMPARE(service->statistics().received.value(), std::uint64_t{12});
    QCOMPARE(service->statistics().dropped.value(), std::uint64_t{3});
    QVERIFY(!service->statistics().interfaceDropped.has_value());
    auto first = service->takeBatch(1000);
    QCOMPARE(first.size(), std::size_t{64});
    QCOMPARE(first.front().metadata.sequenceNumber, std::uint64_t{1});
    QCOMPARE(first.back().metadata.sequenceNumber, std::uint64_t{64});
    QCOMPARE(first.front().bytes.front(), std::uint8_t{1});
    auto second = service->takeBatch(64);
    QCOMPARE(second.size(), std::size_t{64});
    QCOMPARE(second.front().metadata.sequenceNumber, std::uint64_t{65});
    service->stop();
    QTRY_COMPARE(service->state(), arp::CaptureState::Stopped);
}

void CaptureServiceTests::suppressesQueuedEventsFromPriorSession()
{
    auto state = std::make_shared<FakeState>();
    state->failOnlyFirstRead = true;
    auto service = makeService(state);
    QSignalSpy errors(service.get(), &arp::CaptureService::errorOccurred);
    QSignalSpy states(service.get(), &arp::CaptureService::stateChanged);
    QVERIFY(service->start("first"));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (service->state() != arp::CaptureState::Error &&
           std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    QCOMPARE(service->state(), arp::CaptureState::Error);

    QVERIFY(service->start("second"));
    QTRY_COMPARE(service->state(), arp::CaptureState::Running);
    QCOMPARE(errors.count(), 0);
    for (const auto& arguments : states)
        QVERIFY(arguments.front().value<arp::CaptureState>() != arp::CaptureState::Error);
    service->stop();
    QTRY_COMPARE(service->state(), arp::CaptureState::Stopped);
}

QTEST_GUILESS_MAIN(CaptureServiceTests)
#include "CaptureServiceTests.moc"
