#include "storage/CsvExport.hpp"
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
namespace arp
{
namespace
{
std::string quote(const std::string& value)
{
    std::string result = "\"";
    for (char c : value) {
        result += c;
        if (c == '\"')
            result += '\"';
    }
    return result + '\"';
}
template <std::size_t N> std::string address(const std::array<std::uint8_t, N>& bytes, bool mac)
{
    std::ostringstream out;
    for (std::size_t i = 0; i < N; ++i) {
        if (i)
            out << (mac ? ':' : '.');
        if (mac) {
            out << std::hex;
            if (bytes[i] < 16)
                out << '0';
        }
        out << static_cast<unsigned>(bytes[i]);
    }
    return out.str();
}
} // namespace
void exportCsv(const std::string& path, const std::vector<ArpRecord>& rows, bool overwrite)
{
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL), 0600);
    if (fd < 0)
        throw std::runtime_error(
            "Cannot open CSV destination; confirm overwrite or choose writable path");
    FILE* file = fdopen(fd, "wb");
    if (!file) {
        ::close(fd);
        throw std::runtime_error("Cannot open CSV stream");
    }
    std::unique_ptr<FILE, decltype(&fclose)> owner(file, &fclose);
    bool failed = false;
    auto write = [&](const std::string& text) {
        if (fwrite(text.data(), 1, text.size(), file) != text.size())
            failed = true;
    };
    write("sequence,timestamp_unix_nanoseconds,interface,operation,ethernet_source,ethernet_"
          "destination,sender_mac,sender_ipv4,target_mac,target_ipv4,vlan_tpid_tci,captured_length,"
          "original_length\r\n");
    for (const auto& row : rows) {
        std::string tags;
        for (const auto& tag : row.vlanTags) {
            if (!tags.empty())
                tags += ';';
            tags += std::to_string(tag.tpid) + ":" + std::to_string(tag.tci);
        }
        std::vector<std::string> fields{std::to_string(row.metadata.sequenceNumber),
                                        std::to_string(row.metadata.captureTimestamp.count()),
                                        row.metadata.interfaceName,
                                        row.operation == ArpOperation::Request ? "Request"
                                                                               : "Reply",
                                        address(row.ethernetSource, true),
                                        address(row.ethernetDestination, true),
                                        address(row.senderMac, true),
                                        address(row.senderIpv4, false),
                                        address(row.targetMac, true),
                                        address(row.targetIpv4, false),
                                        tags,
                                        std::to_string(row.metadata.capturedLength),
                                        std::to_string(row.metadata.originalLength)};
        std::string line;
        for (const auto& field : fields) {
            if (!line.empty())
                line += ',';
            line += quote(field);
        }
        write(line + "\r\n");
    }
    if (fflush(file) != 0)
        failed = true;
    if (fclose(owner.release()) != 0)
        failed = true;
    if (failed)
        throw std::runtime_error("CSV write/flush failed; export is incomplete");
}
} // namespace arp
