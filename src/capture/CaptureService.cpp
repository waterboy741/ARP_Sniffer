#include "capture/CaptureService.hpp"
#include <QMetaObject>
#include <stdexcept>
namespace arp
{
CaptureService::CaptureService(std::unique_ptr<ICaptureBackend> backend, QObject* parent)
    : QObject(parent), backend_(std::move(backend))
{
    if (!backend_)
        throw std::invalid_argument("Capture backend is null");
    qRegisterMetaType<CaptureState>();
}
CaptureService::~CaptureService()
{
    stop();
    if (worker_.joinable())
        worker_.join();
}
CaptureState CaptureService::state() const
{
    std::lock_guard lock(mutex_);
    return state_;
}
void CaptureService::setState(CaptureState value)
{
    {
        std::lock_guard lock(mutex_);
        state_ = value;
    }
    const auto generation = generation_;
    QMetaObject::invokeMethod(
        this,
        [this, value, generation] {
            if (generation == generation_)
                emit stateChanged(value);
        },
        Qt::QueuedConnection);
}
void CaptureService::setRecording(const std::string& path, bool overwrite,
                                  std::unique_ptr<IRecordingSink> sink)
{
    if (state() == CaptureState::Starting || state() == CaptureState::Running ||
        state() == CaptureState::Stopping)
        throw std::logic_error("Cannot change recording while capturing");
    if (worker_.joinable())
        worker_.join();
    recordingPath_ = path;
    overwriteRecording_ = overwrite;
    writer_ = path.empty() ? nullptr : std::make_unique<SessionWriter>(std::move(sink));
}
void CaptureService::setReplayMode(bool enabled)
{
    if (state() == CaptureState::Starting || state() == CaptureState::Running ||
        state() == CaptureState::Stopping)
        throw std::logic_error("Cannot change replay mode while capturing");
    replayMode_ = enabled;
}
bool CaptureService::start(const std::string& interfaceName)
{
    // Lifecycle methods and takeBatch are called on the owning QObject thread.
    if (state() == CaptureState::Running || state() == CaptureState::Starting ||
        state() == CaptureState::Stopping)
        return false;
    if (worker_.joinable())
        worker_.join();
    ++generation_;
    setState(CaptureState::Starting);
    {
        std::lock_guard lock(mutex_);
        stopping_ = false;
        queue_.clear();
        statistics_ = {};
        applicationDrops_ = 0;
        notificationPending_ = false;
    }
    try {
        worker_ = std::thread([this, interfaceName] { run(interfaceName); });
    } catch (const std::exception& error) {
        setState(CaptureState::Error);
        const auto message = QString::fromUtf8(error.what());
        const auto generation = generation_;
        QMetaObject::invokeMethod(
            this,
            [this, message, generation] {
                if (generation == generation_)
                    emit errorOccurred(message);
            },
            Qt::QueuedConnection);
        return false;
    }
    return true;
}
void CaptureService::stop()
{
    {
        std::lock_guard lock(mutex_);
        if (state_ != CaptureState::Starting && state_ != CaptureState::Running)
            return;
        stopping_ = true;
        state_ = CaptureState::Stopping;
    }
    const auto generation = generation_;
    QMetaObject::invokeMethod(
        this,
        [this, generation] {
            if (generation == generation_)
                emit stateChanged(CaptureState::Stopping);
        },
        Qt::QueuedConnection);
    queueSpace_.notify_all();
    backend_->interrupt();
}
void CaptureService::run(const std::string& interfaceName)
{
    const auto generation = generation_;
    try {
        if (writer_)
            writer_->start(recordingPath_, 1, overwriteRecording_);
        backend_->open(interfaceName);
        if (backend_->linkType() != 1)
            throw std::runtime_error("Unsupported capture link type; Ethernet required");
        {
            std::lock_guard lock(mutex_);
            if (!stopping_) {
                state_ = CaptureState::Running;
                QMetaObject::invokeMethod(
                    this,
                    [this, generation] {
                        if (generation == generation_)
                            emit stateChanged(CaptureState::Running);
                    },
                    Qt::QueuedConnection);
            }
        }
        for (;;) {
            {
                std::lock_guard lock(mutex_);
                if (stopping_)
                    break;
            }
            if (writer_ && !writer_->error().empty())
                throw std::runtime_error(writer_->error());
            auto result = backend_->read();
            if (result.status == ReadStatus::Error)
                throw std::runtime_error(result.error);
            if (result.status == ReadStatus::End)
                break;
            if (result.status == ReadStatus::Packet) {
                if (result.packet.bytes.size() > 65535)
                    throw std::runtime_error("Backend returned oversized captured packet");
                if (writer_ && !writer_->enqueue(result.packet))
                    throw std::runtime_error(writer_->error().empty()
                                                 ? "Recording stopped unexpectedly"
                                                 : writer_->error());
                bool notify = false;
                {
                    std::unique_lock lock(mutex_);
                    if (replayMode_)
                        queueSpace_.wait(
                            lock, [this] { return stopping_ || queue_.size() < queueCapacity; });
                    if (stopping_)
                        break;
                    if (queue_.size() == queueCapacity)
                        ++applicationDrops_;
                    else
                        queue_.push_back(std::move(result.packet));
                    if (!notificationPending_) {
                        notificationPending_ = true;
                        notify = true;
                    }
                }
                if (notify)
                    QMetaObject::invokeMethod(
                        this,
                        [this, generation] {
                            if (generation != generation_)
                                return;
                            {
                                std::lock_guard lock(mutex_);
                                notificationPending_ = false;
                            }
                            emit packetsAvailable();
                        },
                        Qt::QueuedConnection);
            }
            {
                auto value = backend_->statistics();
                std::lock_guard lock(mutex_);
                statistics_ = value;
            }
        }
        {
            auto value = backend_->statistics();
            std::lock_guard lock(mutex_);
            statistics_ = value;
        }
        backend_->close();
        if (writer_)
            writer_->finish();
        setState(CaptureState::Stopped);
    } catch (const std::exception& error) {
        backend_->close();
        std::string messageText = error.what();
        if (writer_) {
            try {
                writer_->finish();
            } catch (const std::exception& failure) {
                messageText += std::string("; ") + failure.what();
            }
        }
        bool cancelled;
        {
            std::lock_guard lock(mutex_);
            cancelled = stopping_ && (!writer_ || writer_->error().empty());
        }
        setState(cancelled ? CaptureState::Stopped : CaptureState::Error);
        const auto message = QString::fromStdString(messageText);
        if (!cancelled)
            QMetaObject::invokeMethod(
                this,
                [this, message, generation] {
                    if (generation == generation_)
                        emit errorOccurred(message);
                },
                Qt::QueuedConnection);
    }
}
std::vector<CapturedPacket> CaptureService::takeBatch(std::size_t maximum)
{
    std::lock_guard lock(mutex_);
    std::vector<CapturedPacket> result;
    const auto count = std::min({maximum, std::size_t{64}, queue_.size()});
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    const auto generation = generation_;
    queueSpace_.notify_all();
    if (!queue_.empty() && !notificationPending_) {
        notificationPending_ = true;
        QMetaObject::invokeMethod(
            this,
            [this, generation] {
                if (generation != generation_)
                    return;
                {
                    std::lock_guard innerLock(mutex_);
                    notificationPending_ = false;
                }
                emit packetsAvailable();
            },
            Qt::QueuedConnection);
    }
    return result;
}
CaptureStatistics CaptureService::statistics() const
{
    std::lock_guard lock(mutex_);
    return statistics_;
}
std::uint64_t CaptureService::applicationDrops() const
{
    std::lock_guard lock(mutex_);
    return applicationDrops_;
}
} // namespace arp
