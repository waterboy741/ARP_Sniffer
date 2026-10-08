#include "core/ArpParser.hpp"

#include <algorithm>
#include <utility>

namespace arp
{
namespace
{

std::uint16_t readNetworkUint16(std::span<const std::uint8_t> frame, std::size_t offset)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(frame[offset]) << 8U) |
                                      frame[offset + 1]);
}

bool isVlanType(std::uint16_t etherType) { return etherType == 0x8100 || etherType == 0x88a8; }

ParseResult failure(ParseStatus status, const char* reason)
{
    return {status, std::nullopt, reason};
}

} // namespace

ParseResult parseEthernetArp(std::span<const std::uint8_t> frame, const PacketMetadata& metadata)
{
    if (metadata.linkType != 1) {
        return failure(ParseStatus::Unsupported, "Unsupported link type; Ethernet is required");
    }
    if (metadata.capturedLength != frame.size() ||
        metadata.originalLength < metadata.capturedLength) {
        return failure(ParseStatus::Malformed, "Inconsistent captured/original packet lengths");
    }
    if (frame.size() < 14) {
        return failure(ParseStatus::Malformed, "Truncated Ethernet header");
    }

    ArpRecord record;
    record.metadata = metadata;
    std::copy_n(frame.begin(), 6, record.ethernetDestination.begin());
    std::copy_n(frame.begin() + 6, 6, record.ethernetSource.begin());
    auto etherType = readNetworkUint16(frame, 12);
    std::size_t payloadOffset = 14;
    while (isVlanType(etherType)) {
        if (frame.size() - payloadOffset < 4) {
            return failure(ParseStatus::Malformed, "Truncated VLAN header");
        }
        if (record.vlanTags.size() == 2) {
            return failure(ParseStatus::Unsupported, "More than two VLAN tags are unsupported");
        }
        record.vlanTags.push_back({etherType, readNetworkUint16(frame, payloadOffset)});
        etherType = readNetworkUint16(frame, payloadOffset + 2);
        payloadOffset += 4;
    }
    if (etherType != 0x0806) {
        return failure(ParseStatus::Unsupported, "Ethernet payload is not ARP");
    }
    if (frame.size() - payloadOffset < 8) {
        return failure(ParseStatus::Malformed, "Truncated ARP header");
    }
    const auto hardwareType = readNetworkUint16(frame, payloadOffset);
    const auto protocolType = readNetworkUint16(frame, payloadOffset + 2);
    const auto hardwareLength = frame[payloadOffset + 4];
    const auto protocolLength = frame[payloadOffset + 5];
    const auto operation = readNetworkUint16(frame, payloadOffset + 6);
    if (hardwareType != 1 || protocolType != 0x0800) {
        return failure(ParseStatus::Unsupported, "ARP hardware/protocol format is unsupported");
    }
    if (hardwareLength != 6 || protocolLength != 4) {
        return failure(ParseStatus::Malformed, "Invalid Ethernet/IPv4 ARP address lengths");
    }
    if (frame.size() - payloadOffset < 28) {
        return failure(ParseStatus::Malformed, "Truncated ARP addresses");
    }
    if (operation != 1 && operation != 2) {
        return failure(ParseStatus::Unsupported, "Unsupported ARP operation");
    }
    record.operation = static_cast<ArpOperation>(operation);
    const auto addresses = frame.subspan(payloadOffset + 8, 20);
    std::copy_n(addresses.begin(), 6, record.senderMac.begin());
    std::copy_n(addresses.begin() + 6, 4, record.senderIpv4.begin());
    std::copy_n(addresses.begin() + 10, 6, record.targetMac.begin());
    std::copy_n(addresses.begin() + 16, 4, record.targetIpv4.begin());
    return {ParseStatus::Valid, std::move(record), {}};
}

} // namespace arp
