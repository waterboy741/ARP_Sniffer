#pragma once
#include "core/ArpRecord.hpp"
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <deque>
#include <optional>
class ArpTableModel final : public QAbstractTableModel
{
  public:
    explicit ArpTableModel(QObject* parent = nullptr);
    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void appendRecords(const std::vector<arp::ArpRecord>& records);
    void clear();
    const arp::ArpRecord& recordAt(int row) const;
    std::uint64_t discardedCount() const;
    static constexpr std::size_t retentionLimit = 10000;

  private:
    std::deque<arp::ArpRecord> records_;
    std::uint64_t discarded_ = 0;
};
class ArpFilterModel final : public QSortFilterProxyModel
{
  public:
    explicit ArpFilterModel(QObject* parent = nullptr);
    void setOperationFilter(std::optional<arp::ArpOperation> operation);
    void setIpFilter(const QString& filter);
    void setMacFilter(const QString& filter);

  protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override;

  private:
    std::optional<arp::ArpOperation> operation_;
    QString ip_, mac_;
};
QString formatMac(const arp::MacAddress& address);
QString formatIpv4(const arp::Ipv4Address& address);
QString recordDetails(const arp::ArpRecord& record);
