#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace arp
{

using MacAddress = std::array<std::uint8_t, 6>;
using Ipv4Address = std::array<std::uint8_t, 4>;

struct PacketMetadata {
    std::uint64_t sequenceNumber = 0;
    // Nanoseconds since the Unix epoch, supplied by the capture source.
    std::chrono::nanoseconds captureTimestamp{};
    std::string interfaceName;
    std::uint32_t capturedLength = 0;
    std::uint32_t originalLength = 0;
    int linkType = 1; // DLT_EN10MB (Ethernet).
};

enum class ArpOperation : std::uint16_t { Request = 1, Reply = 2 };

struct VlanTag {
    std::uint16_t tpid = 0;
    std::uint16_t tci = 0;
};

struct ArpRecord {
    PacketMetadata metadata;
    ArpOperation operation = ArpOperation::Request;
    MacAddress ethernetSource{};
    MacAddress ethernetDestination{};
    MacAddress senderMac{};
    MacAddress targetMac{};
    Ipv4Address senderIpv4{};
    Ipv4Address targetIpv4{};
    std::vector<VlanTag> vlanTags;
};

} // namespace arp
