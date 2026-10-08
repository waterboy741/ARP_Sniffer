#pragma once

#include "core/ArpRecord.hpp"

#include <optional>
#include <span>

namespace arp
{

enum class ParseStatus { Valid, Malformed, Unsupported };

struct ParseResult {
    ParseStatus status = ParseStatus::Malformed;
    std::optional<ArpRecord> record;
    std::string reason;
};

// Does not retain references to frame. Padding beyond the ARP payload is allowed.
// A record is returned only for supported, fully captured Ethernet/IPv4 ARP.
ParseResult parseEthernetArp(std::span<const std::uint8_t> frame, const PacketMetadata& metadata);

} // namespace arp
