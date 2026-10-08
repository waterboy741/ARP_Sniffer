#include "core/ArpParser.hpp"

#include <QTest>

#include <algorithm>
#include <chrono>
#include <random>
#include <vector>

namespace
{
using Bytes = std::vector<std::uint8_t>;

// Synthetic locally administered MACs and RFC 5737 documentation IPv4 addresses.
const arp::MacAddress ethernetSource{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const arp::MacAddress ethernetDestination{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const arp::MacAddress senderMac{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
const arp::MacAddress targetMac{0x02, 0x66, 0x77, 0x88, 0x99, 0x00};
const arp::Ipv4Address senderIpv4{192, 0, 2, 7};
const arp::Ipv4Address targetIpv4{198, 51, 100, 129};

void append16(Bytes& bytes, std::uint16_t value)
{
    bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void write16(Bytes& bytes, std::size_t offset, std::uint16_t value)
{
    bytes.at(offset) = static_cast<std::uint8_t>(value >> 8);
    bytes.at(offset + 1) = static_cast<std::uint8_t>(value & 0xff);
}

template <typename Address> void appendAddress(Bytes& bytes, const Address& address)
{
    bytes.insert(bytes.end(), address.begin(), address.end());
}

Bytes makeFrame(std::uint16_t operation = 1, std::vector<arp::VlanTag> tags = {})
{
    Bytes bytes;
    appendAddress(bytes, ethernetDestination);
    appendAddress(bytes, ethernetSource);
    for (const auto& tag : tags) {
        append16(bytes, tag.tpid);
        append16(bytes, tag.tci);
    }
    append16(bytes, 0x0806);
    append16(bytes, 1);
    append16(bytes, 0x0800);
    bytes.push_back(6);
    bytes.push_back(4);
    append16(bytes, operation);
    appendAddress(bytes, senderMac);
    appendAddress(bytes, senderIpv4);
    appendAddress(bytes, targetMac);
    appendAddress(bytes, targetIpv4);
    return bytes;
}

arp::PacketMetadata metadataFor(const Bytes& bytes)
{
    arp::PacketMetadata metadata;
    metadata.sequenceNumber = 0x123456789abcdef0ULL;
    metadata.captureTimestamp = std::chrono::nanoseconds{1735689600123456789LL};
    metadata.interfaceName = "synthetic0";
    metadata.capturedLength = static_cast<std::uint32_t>(bytes.size());
    metadata.originalLength = metadata.capturedLength + 18;
    metadata.linkType = 1;
    return metadata;
}

bool validResultShape(const arp::ParseResult& result)
{
    return (result.status == arp::ParseStatus::Valid) == result.record.has_value();
}
} // namespace

class ArpParserTests : public QObject
{
    Q_OBJECT

  private slots:
    void requestAndReply();
    void vlanVariants();
    void everyTruncationBoundary();
    void malformedFields();
    void unsupportedFormats();
    void invalidMetadata();
    void probesGratuitousAndRepeats();
    void paddingAndUnalignedInput();
    void recordOwnsAddressesAndMetadata();
    void deterministicMutationCorpus();
};

void ArpParserTests::requestAndReply()
{
    for (std::uint16_t operation : {std::uint16_t{1}, std::uint16_t{2}}) {
        const auto bytes = makeFrame(operation);
        const auto metadata = metadataFor(bytes);
        const auto result = arp::parseEthernetArp(bytes, metadata);
        QVERIFY(result.status == arp::ParseStatus::Valid);
        QVERIFY(result.record.has_value());
        const auto& record = *result.record;
        QVERIFY(record.operation == static_cast<arp::ArpOperation>(operation));
        QVERIFY(record.ethernetSource == ethernetSource);
        QVERIFY(record.ethernetDestination == ethernetDestination);
        QVERIFY(record.senderMac == senderMac);
        QVERIFY(record.targetMac == targetMac);
        QVERIFY(record.senderIpv4 == senderIpv4);
        QVERIFY(record.targetIpv4 == targetIpv4);
        QVERIFY(record.vlanTags.empty());
        QCOMPARE(record.metadata.sequenceNumber, metadata.sequenceNumber);
        QCOMPARE(record.metadata.captureTimestamp.count(), metadata.captureTimestamp.count());
        QVERIFY(record.metadata.interfaceName == metadata.interfaceName);
        QCOMPARE(record.metadata.capturedLength, metadata.capturedLength);
        QCOMPARE(record.metadata.originalLength, metadata.originalLength);
        QCOMPARE(record.metadata.linkType, metadata.linkType);
    }
}

void ArpParserTests::vlanVariants()
{
    const std::vector<std::vector<arp::VlanTag>> cases{{{0x8100, 0xb123}},
                                                       {{0x88a8, 0xfedc}},
                                                       {{0x88a8, 0xa456}, {0x8100, 0x7123}},
                                                       {{0x8100, 0x0000}, {0x8100, 0xffff}},
                                                       {{0x8100, 0x1234}, {0x88a8, 0x5678}}};
    for (const auto& tags : cases) {
        const auto bytes = makeFrame(2, tags);
        const auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
        QVERIFY(result.status == arp::ParseStatus::Valid);
        QVERIFY(result.record.has_value());
        QCOMPARE(result.record->vlanTags.size(), tags.size());
        for (std::size_t index = 0; index < tags.size(); ++index) {
            QCOMPARE(result.record->vlanTags[index].tpid, tags[index].tpid);
            QCOMPARE(result.record->vlanTags[index].tci, tags[index].tci);
        }
        QVERIFY(result.record->senderIpv4 == senderIpv4);
        QVERIFY(result.record->targetMac == targetMac);
    }
}

void ArpParserTests::everyTruncationBoundary()
{
    for (const auto& tags : std::vector<std::vector<arp::VlanTag>>{
             {}, {{0x8100, 0x1234}}, {{0x88a8, 0xabcd}, {0x8100, 0x5678}}}) {
        const auto full = makeFrame(1, tags);
        for (std::size_t size = 0; size < full.size(); ++size) {
            const Bytes truncated(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(size));
            const auto result = arp::parseEthernetArp(truncated, metadataFor(truncated));
            QVERIFY2(
                result.status == arp::ParseStatus::Malformed,
                qPrintable(
                    QString("Expected malformed at length %1 / %2").arg(size).arg(full.size())));
            QVERIFY(!result.record.has_value());
            QVERIFY(!result.reason.empty());
        }
    }
}

void ArpParserTests::malformedFields()
{
    for (const auto offset : {18U, 19U}) {
        for (unsigned value = 0; value <= 255; ++value) {
            if (value == (offset == 18 ? 6U : 4U)) {
                continue;
            }
            auto bytes = makeFrame();
            bytes.at(offset) = static_cast<std::uint8_t>(value);
            const auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
            QVERIFY(result.status == arp::ParseStatus::Malformed);
            QVERIFY(!result.record.has_value());
            QVERIFY(!result.reason.empty());
        }
    }
}

void ArpParserTests::unsupportedFormats()
{
    for (const auto operation : {0U, 3U, 256U, 65535U}) {
        const auto bytes = makeFrame(static_cast<std::uint16_t>(operation));
        const auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
        QVERIFY(result.status == arp::ParseStatus::Unsupported);
        QVERIFY(!result.record.has_value());
        QVERIFY(!result.reason.empty());
    }
    for (const auto& field : std::vector<std::pair<std::size_t, std::uint16_t>>{
             {12, 0x0800}, {12, 0x86dd}, {12, 0}, {14, 2}, {14, 0}, {16, 0x86dd}}) {
        auto bytes = makeFrame();
        write16(bytes, field.first, field.second);
        const auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
        QVERIFY(result.status == arp::ParseStatus::Unsupported);
        QVERIFY(!result.record.has_value());
        QVERIFY(!result.reason.empty());
    }
    const auto triple = makeFrame(1, {{0x88a8, 1}, {0x8100, 2}, {0x8100, 3}});
    const auto result = arp::parseEthernetArp(triple, metadataFor(triple));
    QVERIFY(result.status == arp::ParseStatus::Unsupported);
    QVERIFY(!result.record.has_value());
    QVERIFY(!result.reason.empty());

    // The third tag is unsupported only once its complete header is available.
    for (std::size_t size = 22; size < 26; ++size) {
        const Bytes truncated(triple.begin(), triple.begin() + static_cast<std::ptrdiff_t>(size));
        const auto incomplete = arp::parseEthernetArp(truncated, metadataFor(truncated));
        QVERIFY(incomplete.status == arp::ParseStatus::Malformed);
        QVERIFY(!incomplete.record.has_value());
    }

    const auto bytes = makeFrame();
    for (const auto linkType : {0, 12, 101, 113, 127, -1}) {
        auto metadata = metadataFor(bytes);
        metadata.linkType = linkType;
        const auto unsupported = arp::parseEthernetArp(bytes, metadata);
        QVERIFY(unsupported.status == arp::ParseStatus::Unsupported);
        QVERIFY(!unsupported.record.has_value());
        QVERIFY(!unsupported.reason.empty());
    }
}

void ArpParserTests::invalidMetadata()
{
    const auto bytes = makeFrame();
    auto metadata = metadataFor(bytes);
    for (const auto capturedLength : {0U, 41U, 43U, 0xffffffffU}) {
        metadata.capturedLength = capturedLength;
        const auto result = arp::parseEthernetArp(bytes, metadata);
        QVERIFY(result.status == arp::ParseStatus::Malformed);
        QVERIFY(!result.record.has_value());
        QVERIFY(!result.reason.empty());
    }
    metadata = metadataFor(bytes);
    metadata.originalLength = metadata.capturedLength - 1;
    const auto result = arp::parseEthernetArp(bytes, metadata);
    QVERIFY(result.status == arp::ParseStatus::Malformed);
    QVERIFY(!result.record.has_value());
    QVERIFY(!result.reason.empty());

    metadata = metadataFor(bytes);
    metadata.originalLength = metadata.capturedLength;
    metadata.interfaceName.clear();
    metadata.captureTimestamp = std::chrono::nanoseconds{-1};
    QVERIFY(arp::parseEthernetArp(bytes, metadata).status == arp::ParseStatus::Valid);
}

void ArpParserTests::probesGratuitousAndRepeats()
{
    auto probe = makeFrame();
    std::fill(probe.begin() + 28, probe.begin() + 32, 0);
    std::fill(probe.begin() + 32, probe.begin() + 38, 0);
    const auto result = arp::parseEthernetArp(probe, metadataFor(probe));
    QVERIFY(result.status == arp::ParseStatus::Valid);
    QVERIFY(result.record->senderIpv4 == arp::Ipv4Address{});
    QVERIFY(result.record->targetMac == arp::MacAddress{});
    QVERIFY(result.record->targetIpv4 == targetIpv4);

    for (std::uint16_t operation : {std::uint16_t{1}, std::uint16_t{2}}) {
        auto gratuitous = makeFrame(operation);
        std::copy(senderIpv4.begin(), senderIpv4.end(), gratuitous.begin() + 38);
        const auto observation = arp::parseEthernetArp(gratuitous, metadataFor(gratuitous));
        QVERIFY(observation.status == arp::ParseStatus::Valid);
        QVERIFY(observation.record->senderIpv4 == observation.record->targetIpv4);
    }

    const auto bytes = makeFrame();
    auto metadata = metadataFor(bytes);
    const auto first = arp::parseEthernetArp(bytes, metadata);
    ++metadata.sequenceNumber;
    metadata.captureTimestamp += std::chrono::nanoseconds{123};
    const auto second = arp::parseEthernetArp(bytes, metadata);
    QVERIFY(first.status == arp::ParseStatus::Valid);
    QVERIFY(second.status == arp::ParseStatus::Valid);
    QCOMPARE(second.record->metadata.sequenceNumber, first.record->metadata.sequenceNumber + 1);
    QCOMPARE(second.record->metadata.captureTimestamp.count(),
             first.record->metadata.captureTimestamp.count() + 123);
    QVERIFY(first.record->senderMac == second.record->senderMac);
}

void ArpParserTests::paddingAndUnalignedInput()
{
    auto bytes = makeFrame();
    bytes.resize(60, 0xcc);
    auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
    QVERIFY(result.status == arp::ParseStatus::Valid);
    QVERIFY(result.record->targetIpv4 == targetIpv4);
    QCOMPARE(result.record->metadata.capturedLength, 60U);

    const auto metadata = metadataFor(bytes);
    bytes.insert(bytes.begin(), 0xff);
    result = arp::parseEthernetArp(std::span<const std::uint8_t>(bytes).subspan(1), metadata);
    QVERIFY(result.status == arp::ParseStatus::Valid);
    QVERIFY(result.record->senderMac == senderMac);
}

void ArpParserTests::recordOwnsAddressesAndMetadata()
{
    auto bytes = makeFrame(2, {{0x88a8, 0xb123}});
    auto metadata = metadataFor(bytes);
    const auto result = arp::parseEthernetArp(bytes, metadata);
    QVERIFY(result.status == arp::ParseStatus::Valid);
    QVERIFY(result.record.has_value());
    std::fill(bytes.begin(), bytes.end(), 0);
    metadata.interfaceName = "overwritten";
    metadata.sequenceNumber = 0;
    metadata.captureTimestamp = std::chrono::nanoseconds{};
    QVERIFY(result.record->senderMac == senderMac);
    QVERIFY(result.record->targetIpv4 == targetIpv4);
    QVERIFY(result.record->metadata.interfaceName == "synthetic0");
    QCOMPARE(result.record->metadata.sequenceNumber, 0x123456789abcdef0ULL);
    QCOMPARE(result.record->metadata.captureTimestamp.count(), 1735689600123456789LL);
    QCOMPARE(result.record->vlanTags.front().tci, std::uint16_t{0xb123});
}

void ArpParserTests::deterministicMutationCorpus()
{
    const auto baseline = makeFrame(2, {{0x88a8, 0xb123}, {0x8100, 0x7123}});
    for (std::size_t offset = 0; offset < baseline.size(); ++offset) {
        for (unsigned value = 0; value <= 255; ++value) {
            auto bytes = baseline;
            bytes[offset] = static_cast<std::uint8_t>(value);
            const auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
            QVERIFY(validResultShape(result));
            if (result.record) {
                QVERIFY(result.record->operation == arp::ArpOperation::Request ||
                        result.record->operation == arp::ArpOperation::Reply);
                QVERIFY(result.record->vlanTags.size() <= 2);
            } else {
                QVERIFY(!result.reason.empty());
            }
        }
    }

    std::mt19937 random(5300);
    for (unsigned iteration = 0; iteration < 10000; ++iteration) {
        Bytes bytes(random() % 257);
        for (auto& byte : bytes) {
            byte = static_cast<std::uint8_t>(random() & 0xff);
        }
        const auto result = arp::parseEthernetArp(bytes, metadataFor(bytes));
        QVERIFY(validResultShape(result));
        if (!result.record) {
            QVERIFY(!result.reason.empty());
        }
    }
}

QTEST_APPLESS_MAIN(ArpParserTests)
#include "ArpParserTests.moc"
