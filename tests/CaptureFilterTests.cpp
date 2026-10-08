#include "capture/CaptureBackend.hpp"

#include <QTemporaryFile>
#include <QTest>

#include <pcap/pcap.h>

#include <cstdint>
#include <deque>
#include <vector>

namespace
{
using Frame = std::vector<std::uint8_t>;

void append16(Frame& frame, std::uint16_t value)
{
    frame.push_back(static_cast<std::uint8_t>(value >> 8));
    frame.push_back(static_cast<std::uint8_t>(value & 0xff));
}

Frame makeFrame(const std::vector<std::uint16_t>& tags, std::uint16_t finalType = 0x0806)
{
    Frame frame{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1};
    for (auto tpid : tags) {
        append16(frame, tpid);
        append16(frame, 1);
    }
    append16(frame, finalType);
    frame.resize(frame.size() + (finalType == 0x0806 ? 28 : 20), 0);
    return frame;
}

bool accepts(const bpf_program& filter, const Frame& frame)
{
    pcap_pkthdr header{};
    header.caplen = static_cast<bpf_u_int32>(frame.size());
    header.len = header.caplen;
    return pcap_offline_filter(&filter, &header, frame.data()) != 0;
}
} // namespace

class CaptureFilterTests : public QObject
{
    Q_OBJECT
  private slots:
    void acceptsUntaggedAndOneOrTwoVlans();
    void excludesUnrelatedAndTooDeepTraffic();
    void offlineBackendOwnsPacketBytes();
    void drainsAvailablePacketsBeforeWaiting();
};

void CaptureFilterTests::acceptsUntaggedAndOneOrTwoVlans()
{
    pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
    QVERIFY(dead != nullptr);
    bpf_program filter{};
    const auto expression = arp::captureFilter();
    const int compiled = pcap_compile(dead, &filter, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN);
    QVERIFY2(compiled == 0, pcap_geterr(dead));
    const std::vector<Frame> accepted{makeFrame({}), makeFrame({0x8100}), makeFrame({0x88a8}),
                                      makeFrame({0x88a8, 0x8100}), makeFrame({0x8100, 0x8100})};
    for (const auto& frame : accepted)
        QVERIFY(accepts(filter, frame));
    pcap_freecode(&filter);
    pcap_close(dead);
}

void CaptureFilterTests::excludesUnrelatedAndTooDeepTraffic()
{
    pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
    QVERIFY(dead != nullptr);
    bpf_program filter{};
    const auto expression = arp::captureFilter();
    const int compiled = pcap_compile(dead, &filter, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN);
    QVERIFY2(compiled == 0, pcap_geterr(dead));
    const std::vector<Frame> rejected{makeFrame({}, 0x0800), makeFrame({0x8100}, 0x0800),
                                      makeFrame({0x88a8, 0x8100}, 0x86dd),
                                      makeFrame({0x8100, 0x8100, 0x8100})};
    for (const auto& frame : rejected)
        QVERIFY(!accepts(filter, frame));
    pcap_freecode(&filter);
    pcap_close(dead);
}

void CaptureFilterTests::offlineBackendOwnsPacketBytes()
{
    QTemporaryFile file;
    QVERIFY(file.open());
    const auto path = file.fileName().toStdString();
    file.close();
    pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
    QVERIFY(dead != nullptr);
    pcap_dumper_t* dumper = pcap_dump_open(dead, path.c_str());
    QVERIFY(dumper != nullptr);
    auto firstFrame = makeFrame({});
    auto secondFrame = makeFrame({0x8100});
    firstFrame[6] = 0x02;
    secondFrame[6] = 0x04;
    for (const auto* frame : {&firstFrame, &secondFrame}) {
        pcap_pkthdr header{};
        header.caplen = static_cast<bpf_u_int32>(frame->size());
        header.len = header.caplen;
        pcap_dump(reinterpret_cast<u_char*>(dumper), &header, frame->data());
    }
    pcap_dump_close(dumper);
    pcap_close(dead);

    auto backend = arp::makeOfflineBackend(path);
    backend->open("synthetic");
    auto first = backend->read();
    auto second = backend->read();
    QCOMPARE(first.status, arp::ReadStatus::Packet);
    QCOMPARE(second.status, arp::ReadStatus::Packet);
    QCOMPARE(first.packet.bytes[6], std::uint8_t{0x02});
    QCOMPARE(second.packet.bytes[6], std::uint8_t{0x04});
    QVERIFY(first.packet.bytes != second.packet.bytes);
    QVERIFY(!backend->statistics().received.has_value());
    backend->close();
}

void CaptureFilterTests::drainsAvailablePacketsBeforeWaiting()
{
    std::deque<arp::BackendRead> input{{arp::ReadStatus::Packet, {}, {}},
                                       {arp::ReadStatus::Packet, {}, {}},
                                       {arp::ReadStatus::Idle, {}, {}},
                                       {arp::ReadStatus::Packet, {}, {}}};
    int waits = 0;
    const auto readAvailable = [&input] {
        auto result = std::move(input.front());
        input.pop_front();
        return result;
    };
    const auto waitForReady = [&waits] {
        ++waits;
        return arp::BackendRead{arp::ReadStatus::Idle, {}, {}};
    };

    QCOMPARE(arp::readAvailableThenWait(readAvailable, waitForReady).status,
             arp::ReadStatus::Packet);
    QCOMPARE(waits, 0);
    QCOMPARE(arp::readAvailableThenWait(readAvailable, waitForReady).status,
             arp::ReadStatus::Packet);
    QCOMPARE(waits, 0);
    QCOMPARE(arp::readAvailableThenWait(readAvailable, waitForReady).status,
             arp::ReadStatus::Packet);
    QCOMPARE(waits, 1);
}

QTEST_GUILESS_MAIN(CaptureFilterTests)
#include "CaptureFilterTests.moc"
