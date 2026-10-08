#pragma once
#include "core/ArpRecord.hpp"
#include <functional>
#include <memory>
#include <optional>
#include <vector>
namespace arp
{
struct CapturedPacket {
    PacketMetadata metadata;
    std::vector<std::uint8_t> bytes;
};
struct CaptureStatistics {
    std::optional<std::uint64_t> received, dropped, interfaceDropped;
};
enum class ReadStatus { Packet, Idle, End, Error };
struct BackendRead {
    ReadStatus status = ReadStatus::Idle;
    CapturedPacket packet;
    std::string error;
};
struct CaptureInterface {
    std::string name;
    std::string description;
    bool loopback = false;
};
class ICaptureBackend
{
  public:
    virtual ~ICaptureBackend() = default;
    virtual void open(const std::string& interfaceName) = 0;
    virtual BackendRead read() = 0;
    // Safe concurrently with open/read; must wake an idle reader promptly.
    virtual void interrupt() noexcept = 0;
    // Called after read has finished, including failed initialization.
    virtual void close() noexcept {}
    virtual CaptureStatistics statistics() = 0;
    virtual int linkType() const = 0;
};
std::vector<CaptureInterface> enumerateInterfaces();
std::unique_ptr<ICaptureBackend> makePcapBackend();
std::unique_ptr<ICaptureBackend> makeOfflineBackend(const std::string& path);
std::string captureFilter();
// Read buffered packets immediately; wait only when no packet is available.
BackendRead readAvailableThenWait(const std::function<BackendRead()>& readAvailable,
                                  const std::function<BackendRead()>& waitForReady);
} // namespace arp
