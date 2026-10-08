#pragma once
#include "capture/CaptureBackend.hpp"
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
namespace arp
{
class IRecordingSink
{
  public:
    virtual ~IRecordingSink() = default;
    virtual void open(const std::string& path, int linkType, bool overwrite) = 0;
    virtual void write(const CapturedPacket& packet) = 0;
    virtual void finish() = 0;
};
std::unique_ptr<IRecordingSink> makePcapRecordingSink();
class SessionWriter final
{
  public:
    explicit SessionWriter(std::unique_ptr<IRecordingSink> sink = makePcapRecordingSink());
    ~SessionWriter();
    void start(const std::string& path, int linkType = 1, bool overwrite = false);
    bool enqueue(CapturedPacket packet);
    void finish();
    std::string error() const;
    static constexpr std::size_t queueCapacity = 256;

  private:
    void run();
    std::unique_ptr<IRecordingSink> sink_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<CapturedPacket> queue_;
    std::thread worker_;
    bool finishing_ = false;
    std::string error_;
};
} // namespace arp
