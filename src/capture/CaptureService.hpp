#pragma once
#include "capture/CaptureBackend.hpp"
#include "storage/SessionWriter.hpp"
#include <QObject>
#include <deque>
#include <mutex>
#include <thread>
namespace arp
{
enum class CaptureState { Stopped, Starting, Running, Stopping, Error };
class CaptureService final : public QObject
{
    Q_OBJECT
  public:
    explicit CaptureService(std::unique_ptr<ICaptureBackend> backend, QObject* parent = nullptr);
    ~CaptureService() override;
    // Owner-thread lifecycle calls. Start accepts a request, not an initialization result.
    // Stop requests cancellation; Stopped is reported only after worker cleanup.
    bool start(const std::string& interfaceName);
    void stop();
    void setRecording(const std::string& path, bool overwrite = false,
                      std::unique_ptr<IRecordingSink> sink = makePcapRecordingSink());
    void setReplayMode(bool enabled);
    CaptureState state() const;
    std::vector<CapturedPacket> takeBatch(std::size_t maximum = 64);
    CaptureStatistics statistics() const;
    std::uint64_t applicationDrops() const;
    static constexpr std::size_t queueCapacity = 256;
  signals:
    void packetsAvailable();
    void stateChanged(arp::CaptureState state);
    void errorOccurred(const QString& message);

  private:
    void run(const std::string& interfaceName);
    void setState(CaptureState state);
    std::unique_ptr<ICaptureBackend> backend_;
    mutable std::mutex mutex_;
    std::thread worker_;
    CaptureState state_ = CaptureState::Stopped;
    bool stopping_ = false;
    bool replayMode_ = false;
    std::condition_variable queueSpace_;
    std::unique_ptr<SessionWriter> writer_;
    std::string recordingPath_;
    bool overwriteRecording_ = false;
    std::uint64_t generation_ = 0;
    bool notificationPending_ = false;
    std::deque<CapturedPacket> queue_;
    CaptureStatistics statistics_;
    std::uint64_t applicationDrops_ = 0;
};
} // namespace arp
Q_DECLARE_METATYPE(arp::CaptureState)
