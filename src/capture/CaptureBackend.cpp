#include "capture/CaptureBackend.hpp"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <stdexcept>
#include <unistd.h>
namespace arp
{
namespace
{
struct PcapCloser {
    void operator()(pcap_t* value) const
    {
        if (value)
            pcap_close(value);
    }
};
using PcapHandle = std::unique_ptr<pcap_t, PcapCloser>;
struct Filter {
    bpf_program program{};
    ~Filter() { pcap_freecode(&program); }
};
class PcapBackend final : public ICaptureBackend
{
  public:
    explicit PcapBackend(std::string path = {}) : path_(std::move(path))
    {
        if (pipe(wake_) != 0)
            throw std::runtime_error("Cannot create capture wake pipe");
        for (int fd : wake_) {
            if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
                for (int cleanup : wake_)
                    ::close(cleanup);
                throw std::runtime_error("Cannot configure capture wake pipe");
            }
        }
    }
    ~PcapBackend() override
    {
        for (int fd : wake_)
            ::close(fd);
    }
    void open(const std::string& interfaceName) override
    {
        handle_.reset();
        char drain[64];
        while (::read(wake_[0], drain, sizeof drain) > 0) {
        }
        char error[PCAP_ERRBUF_SIZE]{};
        interfaceName_ = interfaceName;
        offline_ = !path_.empty();
        if (offline_)
            handle_.reset(pcap_open_offline_with_tstamp_precision(
                path_.c_str(), PCAP_TSTAMP_PRECISION_NANO, error));
        else {
            if (interfaceName.empty())
                throw std::runtime_error("Select a capture interface");
            handle_.reset(pcap_create(interfaceName.c_str(), error));
            if (!handle_)
                throw std::runtime_error(error);
            if (pcap_set_snaplen(handle_.get(), 65535) != 0 ||
                pcap_set_promisc(handle_.get(), 1) != 0 ||
                pcap_set_timeout(handle_.get(), 50) != 0 ||
                pcap_set_immediate_mode(handle_.get(), 1) != 0)
                throw std::runtime_error(pcap_geterr(handle_.get()));
            const int activated = pcap_activate(handle_.get());
            if (activated != 0)
                throw std::runtime_error(std::string("Cannot activate capture: ") +
                                         pcap_statustostr(activated) + ": " +
                                         pcap_geterr(handle_.get()));
            if (pcap_setnonblock(handle_.get(), 1, error) != 0)
                throw std::runtime_error(error);
        }
        if (!handle_)
            throw std::runtime_error(error);
        if (pcap_datalink(handle_.get()) != DLT_EN10MB)
            throw std::runtime_error("Unsupported capture link type; Ethernet required");
        Filter filter;
        if (pcap_compile(handle_.get(), &filter.program, captureFilter().c_str(), 1,
                         PCAP_NETMASK_UNKNOWN) != 0 ||
            pcap_setfilter(handle_.get(), &filter.program) != 0)
            throw std::runtime_error(pcap_geterr(handle_.get()));
        sequence_ = 0;
    }
    BackendRead read() override
    {
        auto wait = [this] {
            pollfd descriptors[2]{{wake_[0], POLLIN, 0},
                                  {pcap_get_selectable_fd(handle_.get()), POLLIN, 0}};
            const int ready = poll(descriptors, 2, 50);
            if (ready < 0 && errno != EINTR)
                return BackendRead{ReadStatus::Error, {}, std::strerror(errno)};
            if (descriptors[0].revents)
                return BackendRead{ReadStatus::End, {}, {}};
            if (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL))
                return BackendRead{ReadStatus::Error, {}, "Capture interface became unavailable"};
            return BackendRead{};
        };
        auto available = [this] {
            pollfd wake{wake_[0], POLLIN, 0};
            if (poll(&wake, 1, 0) > 0)
                return BackendRead{ReadStatus::End, {}, {}};
            return readPacket();
        };
        if (offline_)
            return available();
        return readAvailableThenWait(available, wait);
    }
    BackendRead readPacket()
    {
        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        int result = pcap_next_ex(handle_.get(), &header, &data);
        if (result == 0)
            return {};
        if (result == -2)
            return {ReadStatus::End, {}, {}};
        if (result < 0)
            return {ReadStatus::Error, {}, pcap_geterr(handle_.get())};
        if (header->caplen > 65535 || header->caplen > header->len)
            return {ReadStatus::Error, {}, "Invalid or oversized captured packet"};
        const auto units = pcap_get_tstamp_precision(handle_.get()) == PCAP_TSTAMP_PRECISION_NANO
                               ? 1000000000L
                               : 1000000L;
        if (header->ts.tv_sec < 0 || header->ts.tv_sec > 0xffffffffLL || header->ts.tv_usec < 0 ||
            header->ts.tv_usec >= units)
            return {ReadStatus::Error, {}, "Invalid PCAP packet timestamp"};
        CapturedPacket packet;
        packet.metadata.sequenceNumber = ++sequence_;
        packet.metadata.interfaceName = interfaceName_;
        packet.metadata.captureTimestamp =
            std::chrono::seconds(header->ts.tv_sec) +
            (pcap_get_tstamp_precision(handle_.get()) == PCAP_TSTAMP_PRECISION_NANO
                 ? std::chrono::nanoseconds(header->ts.tv_usec)
                 : std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::microseconds(header->ts.tv_usec)));
        packet.metadata.capturedLength = header->caplen;
        packet.metadata.originalLength = header->len;
        packet.metadata.linkType = linkType();
        packet.bytes.assign(data, data + header->caplen);
        return {ReadStatus::Packet, std::move(packet), {}};
    }
    void interrupt() noexcept override
    {
        char value = 1;
        (void)::write(wake_[1], &value, 1);
    }
    void close() noexcept override { handle_.reset(); }
    CaptureStatistics statistics() override
    {
        pcap_stat value{};
        if (offline_ || !handle_ || pcap_stats(handle_.get(), &value) != 0)
            return {};
        // libpcap's BPF backend does not supply interface drop counts on macOS.
#ifdef __APPLE__
        return {value.ps_recv, value.ps_drop, std::nullopt};
#else
        return {value.ps_recv, value.ps_drop, value.ps_ifdrop};
#endif
    }
    int linkType() const override { return handle_ ? pcap_datalink(handle_.get()) : -1; }

  private:
    PcapHandle handle_;
    std::string path_, interfaceName_;
    int wake_[2]{};
    bool offline_ = false;
    std::uint64_t sequence_ = 0;
};
} // namespace
BackendRead readAvailableThenWait(const std::function<BackendRead()>& readAvailable,
                                  const std::function<BackendRead()>& waitForReady)
{
    auto result = readAvailable();
    if (result.status != ReadStatus::Idle)
        return result;
    result = waitForReady();
    if (result.status != ReadStatus::Idle)
        return result;
    return readAvailable();
}
std::string captureFilter()
{
    // Explicit offsets avoid libpcap's stateful vlan keyword shifting later OR branches.
    return "ether[12:2] = 0x0806 or ((ether[12:2] = 0x8100 or ether[12:2] = 0x88a8) and "
           "(ether[16:2] = 0x0806 or ((ether[16:2] = 0x8100 or ether[16:2] = 0x88a8) and "
           "ether[20:2] = 0x0806)))";
}
std::vector<CaptureInterface> enumerateInterfaces()
{
    pcap_if_t* devices = nullptr;
    char error[PCAP_ERRBUF_SIZE]{};
    if (pcap_findalldevs(&devices, error) != 0)
        throw std::runtime_error(error);
    std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> owner(devices, pcap_freealldevs);
    std::vector<CaptureInterface> result;
    for (auto* device = devices; device; device = device->next)
        result.push_back({device->name, device->description ? device->description : "",
                          (device->flags & PCAP_IF_LOOPBACK) != 0});
    return result;
}
std::unique_ptr<ICaptureBackend> makePcapBackend() { return std::make_unique<PcapBackend>(); }
std::unique_ptr<ICaptureBackend> makeOfflineBackend(const std::string& path)
{
    if (path.empty())
        throw std::invalid_argument("Offline capture path is empty");
    return std::make_unique<PcapBackend>(path);
}
} // namespace arp
