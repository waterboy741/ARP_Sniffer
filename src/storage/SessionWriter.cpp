#include "storage/SessionWriter.hpp"
#include <cstdio>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <stdexcept>
#include <unistd.h>
namespace arp
{
namespace
{
class PcapRecordingSink final : public IRecordingSink
{
  public:
    ~PcapRecordingSink() override
    {
        if (dumper_)
            pcap_dump_close(dumper_);
        if (handle_)
            pcap_close(handle_);
    }
    void open(const std::string& path, int linkType, bool overwrite) override
    {
        if (dumper_)
            throw std::runtime_error("Recording is already open");
        if (linkType != 1)
            throw std::runtime_error("Recording requires Ethernet link type");
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL), 0600);
        if (fd < 0)
            throw std::runtime_error("Cannot open recording destination (existing file requires "
                                     "overwrite confirmation or destination is unwritable)");
        FILE* stream = fdopen(fd, "wb");
        if (!stream) {
            ::close(fd);
            throw std::runtime_error("Cannot create recording stream");
        }
        handle_ = pcap_open_dead_with_tstamp_precision(linkType, 65535, PCAP_TSTAMP_PRECISION_NANO);
        if (!handle_) {
            fclose(stream);
            throw std::runtime_error("Cannot initialize PCAP writer");
        }
        dumper_ = pcap_dump_fopen(handle_, stream);
        if (!dumper_) {
            // For supported Ethernet link type, libpcap closes the supplied stream
            // when writing its file header fails.
            throw std::runtime_error(pcap_geterr(handle_));
        }
        if (pcap_dump_flush(dumper_) != 0)
            throw std::runtime_error("Cannot write PCAP header");
    }
    void write(const CapturedPacket& packet) override
    {
        const auto nanos = packet.metadata.captureTimestamp.count();
        if (packet.metadata.linkType != 1 || packet.bytes.size() > 65535 ||
            packet.bytes.size() != packet.metadata.capturedLength ||
            packet.metadata.originalLength < packet.metadata.capturedLength || nanos < 0 ||
            nanos / 1000000000LL > 0xffffffffLL)
            throw std::runtime_error("Invalid packet metadata for classic PCAP recording");
        pcap_pkthdr header{};
        header.caplen = packet.metadata.capturedLength;
        header.len = packet.metadata.originalLength;
        header.ts.tv_sec = static_cast<decltype(header.ts.tv_sec)>(nanos / 1000000000LL);
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>(nanos % 1000000000LL);
        pcap_dump(reinterpret_cast<u_char*>(dumper_), &header, packet.bytes.data());
        if (ferror(pcap_dump_file(dumper_)))
            throw std::runtime_error("Recording write failed; check disk space/device");
    }
    void finish() override
    {
        bool failed = dumper_ && pcap_dump_flush(dumper_) != 0;
        if (dumper_) {
            pcap_dump_close(dumper_);
            dumper_ = nullptr;
        }
        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
        if (failed)
            throw std::runtime_error("Recording flush failed; session may be incomplete");
    }

  private:
    pcap_t* handle_ = nullptr;
    pcap_dumper_t* dumper_ = nullptr;
};
} // namespace
std::unique_ptr<IRecordingSink> makePcapRecordingSink()
{
    return std::make_unique<PcapRecordingSink>();
}
SessionWriter::SessionWriter(std::unique_ptr<IRecordingSink> sink) : sink_(std::move(sink))
{
    if (!sink_)
        throw std::invalid_argument("Recording sink is null");
}
SessionWriter::~SessionWriter()
{
    try {
        finish();
    } catch (...) {
    }
}
void SessionWriter::start(const std::string& path, int linkType, bool overwrite)
{
    if (worker_.joinable())
        throw std::runtime_error("Recording already started");
    {
        std::lock_guard lock(mutex_);
        finishing_ = false;
        error_.clear();
        queue_.clear();
    }
    try {
        sink_->open(path, linkType, overwrite);
        worker_ = std::thread([this] { run(); });
    } catch (const std::exception& failure) {
        {
            std::lock_guard lock(mutex_);
            error_ = failure.what();
            finishing_ = true;
        }
        try {
            sink_->finish();
        } catch (...) {
        }
        throw;
    } catch (...) {
        {
            std::lock_guard lock(mutex_);
            error_ = "Recording initialization failed";
            finishing_ = true;
        }
        try {
            sink_->finish();
        } catch (...) {
        }
        throw;
    }
}
bool SessionWriter::enqueue(CapturedPacket packet)
{
    std::lock_guard lock(mutex_);
    if (!error_.empty() || finishing_ || !worker_.joinable())
        return false;
    if (packet.bytes.size() > 65535) {
        error_ = "Oversized recording packet";
        finishing_ = true;
        ready_.notify_one();
        return false;
    }
    if (queue_.size() == queueCapacity) {
        error_ = "Recording queue overflow; session is incomplete";
        finishing_ = true;
        ready_.notify_one();
        return false;
    }
    queue_.push_back(std::move(packet));
    ready_.notify_one();
    return true;
}
void SessionWriter::run()
{
    try {
        for (;;) {
            CapturedPacket packet;
            {
                std::unique_lock lock(mutex_);
                ready_.wait(lock, [this] { return finishing_ || !queue_.empty(); });
                if (queue_.empty())
                    break;
                packet = std::move(queue_.front());
                queue_.pop_front();
            }
            sink_->write(packet);
        }
        sink_->finish();
    } catch (const std::exception& error) {
        {
            std::lock_guard lock(mutex_);
            if (error_.empty())
                error_ = error.what();
            finishing_ = true;
            queue_.clear();
        }
        try {
            sink_->finish();
        } catch (...) {
        }
    }
}
void SessionWriter::finish()
{
    {
        std::lock_guard lock(mutex_);
        finishing_ = true;
        ready_.notify_one();
    }
    if (worker_.joinable())
        worker_.join();
    const auto message = error();
    if (!message.empty())
        throw std::runtime_error(message);
}
std::string SessionWriter::error() const
{
    std::lock_guard lock(mutex_);
    return error_;
}
} // namespace arp
