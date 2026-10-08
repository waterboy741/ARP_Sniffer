#pragma once
#include "capture/CaptureService.hpp"
#include "gui/ArpTableModel.hpp"
#include <QElapsedTimer>
#include <QMainWindow>
class QComboBox;
class QPushButton;
class QLabel;
class QTableView;
class QPlainTextEdit;
class QTimer;
class QLineEdit;
class MainWindow final : public QMainWindow
{
  public:
    explicit MainWindow(QWidget* parent = nullptr);
    MainWindow(std::unique_ptr<arp::ICaptureBackend> backend,
               std::vector<arp::CaptureInterface> interfaces, QWidget* parent = nullptr);
    bool openRecording(const QString& path);
    bool exportRows(const QString& path, bool visibleOnly, bool overwrite = false);
    void setRecordingDestination(const QString& path, bool overwrite = false);
    void appendRecords(const std::vector<arp::ArpRecord>& records);
    ArpTableModel* packetModel() const;
    std::uint64_t requestCount() const;
    std::uint64_t replyCount() const;
    std::uint64_t errorCount() const;

  protected:
    void closeEvent(QCloseEvent* event) override;

  private:
    void initialize(const std::vector<arp::CaptureInterface>& interfaces);
    std::vector<arp::ArpRecord> snapshotRows(bool visibleOnly) const;
    void bindService();
    void updateState(arp::CaptureState state);
    void updateCounters();
    void drainPackets();
    void showDetails();
    arp::CaptureService* service_;
    ArpTableModel* model_;
    ArpFilterModel* proxy_;
    QComboBox* interfaces_;
    QLineEdit* recordingDestination_;
    QPushButton* openRecordingButton_;
    QPushButton* exportButton_;
    bool replaying_ = false;
    bool recordingOverwrite_ = false;
    QPushButton* start_;
    QPushButton* stop_;
    QLabel* status_;
    QLabel* counters_;
    QLabel* elapsed_;
    QLabel* retention_;
    QTableView* table_;
    QPlainTextEdit* details_;
    QTimer* timer_;
    QElapsedTimer clock_;
    bool closing_ = false;
    bool exporting_ = false;
    QString lastError_;
    std::uint64_t requests_ = 0, replies_ = 0, errors_ = 0;
};
