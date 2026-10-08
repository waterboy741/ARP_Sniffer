#include "gui/ArpTableModel.hpp"
#include <QDateTime>
#include <QStringList>
#include <QTimeZone>
#include <optional>
QString formatMac(const arp::MacAddress& address)
{
    QStringList parts;
    for (auto byte : address)
        parts << QStringLiteral("%1").arg(byte, 2, 16, QLatin1Char('0'));
    return parts.join(':');
}
QString formatIpv4(const arp::Ipv4Address& address)
{
    QStringList parts;
    for (auto byte : address)
        parts << QString::number(byte);
    return parts.join('.');
}
QString recordDetails(const arp::ArpRecord& record)
{
    QString text = QStringLiteral("Sequence: %1\nEthernet source: %2\nEthernet destination: "
                                  "%3\nCaptured/original bytes: %4/%5\nVLAN tags: %6")
                       .arg(record.metadata.sequenceNumber)
                       .arg(formatMac(record.ethernetSource))
                       .arg(formatMac(record.ethernetDestination))
                       .arg(record.metadata.capturedLength)
                       .arg(record.metadata.originalLength)
                       .arg(record.vlanTags.size());
    for (const auto& tag : record.vlanTags)
        text += QStringLiteral("\nTPID 0x%1, TCI 0x%2, VID %3, priority %4, DEI %5")
                    .arg(tag.tpid, 4, 16, QLatin1Char('0'))
                    .arg(tag.tci, 4, 16, QLatin1Char('0'))
                    .arg(tag.tci & 0xfff)
                    .arg(tag.tci >> 13)
                    .arg((tag.tci >> 12) & 1);
    return text;
}
ArpTableModel::ArpTableModel(QObject* parent) : QAbstractTableModel(parent) {}
int ArpTableModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(records_.size());
}
int ArpTableModel::columnCount(const QModelIndex& parent) const { return parent.isValid() ? 0 : 7; }
QVariant ArpTableModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || index.column() < 0 ||
        index.column() >= 7)
        return {};
    const auto& record = records_[static_cast<std::size_t>(index.row())];
    if (role == Qt::UserRole && index.column() == 0)
        return QVariant::fromValue<qlonglong>(record.metadata.captureTimestamp.count());
    if (role == Qt::UserRole && (index.column() == 2 || index.column() == 3)) {
        const auto& ip = index.column() == 2 ? record.senderIpv4 : record.targetIpv4;
        std::uint32_t value = 0;
        for (auto byte : ip)
            value = (value << 8U) | byte;
        return value;
    }
    if (role != Qt::DisplayRole && role != Qt::UserRole && role != Qt::ToolTipRole)
        return {};
    switch (index.column()) {
    case 0:
        return QDateTime::fromMSecsSinceEpoch(record.metadata.captureTimestamp.count() / 1000000,
                                              QTimeZone(QByteArrayLiteral("UTC")))
            .toString("yyyy-MM-dd HH:mm:ss.zzz 'UTC'");
    case 1:
        return record.operation == arp::ArpOperation::Request ? "Request" : "Reply";
    case 2:
        return formatIpv4(record.senderIpv4);
    case 3:
        return formatIpv4(record.targetIpv4);
    case 4:
        return formatMac(record.senderMac);
    case 5:
        return formatMac(record.targetMac);
    case 6:
        return QString::fromStdString(record.metadata.interfaceName);
    default:
        return {};
    }
}
QVariant ArpTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0 || section >= 7)
        return {};
    static const QStringList headers{"Timestamp",  "Operation",  "Sender IP", "Target IP",
                                     "Sender MAC", "Target MAC", "Interface"};
    return headers[section];
}
void ArpTableModel::appendRecords(const std::vector<arp::ArpRecord>& records)
{
    if (records.empty())
        return;
    const auto incoming = std::min(records.size(), retentionLimit);
    const auto removed = std::min(records_.size(), records_.size() + incoming > retentionLimit
                                                       ? records_.size() + incoming - retentionLimit
                                                       : std::size_t{0});
    if (removed) {
        beginRemoveRows({}, 0, static_cast<int>(removed) - 1);
        for (std::size_t i = 0; i < removed; ++i)
            records_.pop_front();
        endRemoveRows();
    }
    discarded_ += removed + records.size() - incoming;
    const auto start = static_cast<int>(records_.size());
    beginInsertRows({}, start, start + static_cast<int>(incoming) - 1);
    records_.insert(records_.end(), records.end() - static_cast<std::ptrdiff_t>(incoming),
                    records.end());
    endInsertRows();
}
void ArpTableModel::clear()
{
    beginResetModel();
    records_.clear();
    discarded_ = 0;
    endResetModel();
}
const arp::ArpRecord& ArpTableModel::recordAt(int row) const
{
    return records_.at(static_cast<std::size_t>(row));
}
std::uint64_t ArpTableModel::discardedCount() const { return discarded_; }
ArpFilterModel::ArpFilterModel(QObject* parent) : QSortFilterProxyModel(parent)
{
    setSortRole(Qt::UserRole);
}
void ArpFilterModel::setOperationFilter(std::optional<arp::ArpOperation> value)
{
    operation_ = value;
    invalidate();
}
void ArpFilterModel::setIpFilter(const QString& value)
{
    ip_ = value.trimmed();
    invalidate();
}
void ArpFilterModel::setMacFilter(const QString& value)
{
    mac_ = value.trimmed();
    invalidate();
}
bool ArpFilterModel::filterAcceptsRow(int row, const QModelIndex&) const
{
    const auto& record = static_cast<ArpTableModel*>(sourceModel())->recordAt(row);
    return (!operation_ || record.operation == *operation_) &&
           (ip_.isEmpty() || formatIpv4(record.senderIpv4).contains(ip_) ||
            formatIpv4(record.targetIpv4).contains(ip_)) &&
           (mac_.isEmpty() || formatMac(record.senderMac).contains(mac_, Qt::CaseInsensitive) ||
            formatMac(record.targetMac).contains(mac_, Qt::CaseInsensitive));
}
