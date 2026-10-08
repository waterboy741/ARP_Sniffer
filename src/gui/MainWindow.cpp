#include "gui/MainWindow.hpp"
#include "core/ArpParser.hpp"
#include "storage/CsvExport.hpp"
#include <QCloseEvent>
#include <QComboBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>
namespace
{
QString optionalCount(std::optional<std::uint64_t> value)
{
    return value ? QString::number(*value) : QStringLiteral("unknown");
}
} // namespace
MainWindow::MainWindow(QWidget* parent) : MainWindow(arp::makePcapBackend(), {}, parent)
{
    try {
        for (const auto& interface : arp::enumerateInterfaces()) {
            interfaces_->addItem(
                QString::fromStdString(interface.name + (interface.description.empty()
                                                             ? ""
                                                             : " — " + interface.description)),
                QString::fromStdString(interface.name));
        }
        updateState(service_->state());
    } catch (const std::exception& error) {
        status_->setText("Interface discovery error: " + QString::fromUtf8(error.what()));
    }
}
MainWindow::MainWindow(std::unique_ptr<arp::ICaptureBackend> backend,
                       std::vector<arp::CaptureInterface> interfaces, QWidget* parent)
    : QMainWindow(parent)
{
    service_ = new arp::CaptureService(std::move(backend), this);
    initialize(interfaces);
}
void MainWindow::initialize(const std::vector<arp::CaptureInterface>& interfaces)
{
    setWindowTitle("ARP Sniffer");
    resize(1200, 760);
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);
    setCentralWidget(central);
    auto* controls = new QHBoxLayout;
    layout->addLayout(controls);
    interfaces_ = new QComboBox;
    interfaces_->setObjectName("interfaceCombo");
    interfaces_->addItem("Select interface", QString{});
    for (const auto& interface : interfaces)
        interfaces_->addItem(
            QString::fromStdString(interface.name + (interface.description.empty()
                                                         ? ""
                                                         : " — " + interface.description)),
            QString::fromStdString(interface.name));
    controls->addWidget(interfaces_);
    start_ = new QPushButton("Start");
    start_->setObjectName("startButton");
    controls->addWidget(start_);
    stop_ = new QPushButton("Stop");
    stop_->setObjectName("stopButton");
    controls->addWidget(stop_);
    recordingDestination_ = new QLineEdit;
    recordingDestination_->setObjectName("recordingDestination");
    recordingDestination_->setPlaceholderText(
        "Optional PCAP recording destination; empty means not saved");
    layout->addWidget(recordingDestination_);
    auto* files = new QHBoxLayout;
    layout->addLayout(files);
    openRecordingButton_ = new QPushButton("Open PCAP");
    openRecordingButton_->setObjectName("openRecordingButton");
    files->addWidget(openRecordingButton_);
    auto* scope = new QComboBox;
    scope->setObjectName("csvScope");
    scope->addItems({"All retained rows", "Displayed rows"});
    files->addWidget(scope);
    exportButton_ = new QPushButton("Export CSV");
    exportButton_->setObjectName("exportCsvButton");
    files->addWidget(exportButton_);
    connect(openRecordingButton_, &QPushButton::clicked, this, [this] {
        auto path = QFileDialog::getOpenFileName(this, "Open PCAP", {},
                                                 "PCAP files (*.pcap *.pcapng);;All files (*)");
        if (!path.isEmpty())
            openRecording(path);
    });
    connect(exportButton_, &QPushButton::clicked, this, [this, scope] {
        auto path = QFileDialog::getSaveFileName(this, "Export CSV", {}, "CSV files (*.csv)",
                                                 nullptr, QFileDialog::DontConfirmOverwrite);
        if (path.isEmpty())
            return;
        bool overwrite = false;
        if (QFileInfo::exists(path)) {
            overwrite = QMessageBox::question(this, "Overwrite CSV?",
                                              "Replace the existing CSV file?") == QMessageBox::Yes;
            if (!overwrite)
                return;
        }
        auto rows = snapshotRows(scope->currentIndex() == 1);
        exporting_ = true;
        exportButton_->setEnabled(false);
        auto* watcher = new QFutureWatcher<QString>(this);
        connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher] {
            const auto error = watcher->result();
            exporting_ = false;
            exportButton_->setEnabled(true);
            status_->setText(error.isEmpty() ? "CSV export complete" : "Export error: " + error);
            watcher->deleteLater();
            if (!error.isEmpty())
                closing_ = false;
            else if (closing_)
                close();
        });
        watcher->setFuture(QtConcurrent::run([path, rows = std::move(rows), overwrite] {
            try {
                arp::exportCsv(path.toStdString(), rows, overwrite);
                return QString{};
            } catch (const std::exception& error) {
                return QString::fromUtf8(error.what());
            }
        }));
    });
    status_ = new QLabel("Stopped — select an interface to begin");
    status_->setObjectName("statusLabel");
    layout->addWidget(status_);
    elapsed_ = new QLabel("Elapsed: 0.0 s");
    elapsed_->setObjectName("elapsedLabel");
    layout->addWidget(elapsed_);
    counters_ = new QLabel;
    counters_->setObjectName("countersLabel");
    layout->addWidget(counters_);
    auto* filters = new QHBoxLayout;
    layout->addLayout(filters);
    auto* operation = new QComboBox;
    operation->setObjectName("operationFilter");
    operation->addItems({"All operations", "Requests", "Replies"});
    filters->addWidget(operation);
    auto* ip = new QLineEdit;
    ip->setObjectName("ipFilter");
    ip->setPlaceholderText("Sender or target IP contains");
    filters->addWidget(ip);
    auto* mac = new QLineEdit;
    mac->setObjectName("macFilter");
    mac->setPlaceholderText("Sender or target MAC contains");
    filters->addWidget(mac);
    model_ = new ArpTableModel(this);
    proxy_ = new ArpFilterModel(this);
    proxy_->setSourceModel(model_);
    table_ = new QTableView;
    table_->setObjectName("packetTable");
    table_->setModel(proxy_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(0, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    table_->setColumnWidth(0, 260);
    layout->addWidget(table_, 1);
    retention_ = new QLabel;
    retention_->setObjectName("retentionLabel");
    layout->addWidget(retention_);
    details_ = new QPlainTextEdit;
    details_->setObjectName("detailsPane");
    details_->setReadOnly(true);
    details_->setPlaceholderText("Select a packet to inspect Ethernet and VLAN details");
    details_->setMaximumHeight(180);
    layout->addWidget(details_);
    connect(operation, &QComboBox::currentIndexChanged, this, [this](int index) {
        proxy_->setOperationFilter(
            index == 0 ? std::nullopt
                       : std::optional<arp::ArpOperation>(index == 1 ? arp::ArpOperation::Request
                                                                     : arp::ArpOperation::Reply));
    });
    connect(ip, &QLineEdit::textChanged, proxy_, &ArpFilterModel::setIpFilter);
    connect(mac, &QLineEdit::textChanged, proxy_, &ArpFilterModel::setMacFilter);
    connect(table_->selectionModel(), &QItemSelectionModel::currentChanged, this,
            [this] { showDetails(); });
    connect(model_, &QAbstractItemModel::rowsRemoved, this, [this] { showDetails(); });
    connect(interfaces_, &QComboBox::currentIndexChanged, this,
            [this] { updateState(service_->state()); });
    connect(start_, &QPushButton::clicked, this, [this] {
        bool overwrite = recordingOverwrite_;
        recordingOverwrite_ = false;
        const auto path = recordingDestination_->text();
        if (!path.isEmpty() && QFileInfo::exists(path) && !overwrite) {
            if (QMessageBox::question(this, "Overwrite recording?",
                                      "Replace the existing PCAP recording?") != QMessageBox::Yes)
                return;
            overwrite = true;
        }
        if (replaying_) {
            delete service_;
            service_ = new arp::CaptureService(arp::makePcapBackend(), this);
            bindService();
            replaying_ = false;
        }
        service_->setRecording(path.toStdString(), overwrite);
        model_->clear();
        lastError_.clear();
        requests_ = replies_ = errors_ = 0;
        details_->clear();
        updateCounters();
        clock_.start();
        service_->start(interfaces_->currentData().toString().toStdString());
        updateState(service_->state());
    });
    connect(stop_, &QPushButton::clicked, this, [this] { service_->stop(); });
    bindService();
    timer_ = new QTimer(this);
    timer_->setInterval(100);
    connect(timer_, &QTimer::timeout, this, [this] {
        if (clock_.isValid())
            elapsed_->setText(QStringLiteral("Elapsed: %1 s")
                                  .arg(static_cast<double>(clock_.elapsed()) / 1000.0, 0, 'f', 1));
        updateCounters();
    });
    updateState(arp::CaptureState::Stopped);
    updateCounters();
}
void MainWindow::bindService()
{
    connect(service_, &arp::CaptureService::stateChanged, this, &MainWindow::updateState);
    connect(service_, &arp::CaptureService::packetsAvailable, this, &MainWindow::drainPackets);
    connect(service_, &arp::CaptureService::errorOccurred, this, [this](const QString& message) {
        ++errors_;
        lastError_ = message;
        status_->setText((replaying_ ? "Replay error: " : "Capture error: ") + message);
        updateCounters();
    });
}
void MainWindow::setRecordingDestination(const QString& path, bool overwrite)
{
    recordingDestination_->setText(path);
    recordingOverwrite_ = overwrite;
}
bool MainWindow::openRecording(const QString& path)
{
    const auto state = service_->state();
    if (state == arp::CaptureState::Starting || state == arp::CaptureState::Running ||
        state == arp::CaptureState::Stopping || closing_)
        return false;
    try {
        auto* replacement =
            new arp::CaptureService(arp::makeOfflineBackend(path.toStdString()), this);
        delete service_;
        service_ = replacement;
        bindService();
        service_->setReplayMode(true);
        replaying_ = true;
        model_->clear();
        details_->clear();
        requests_ = replies_ = errors_ = 0;
        lastError_.clear();
        clock_.start();
        updateCounters();
        const auto accepted = service_->start("offline");
        updateState(service_->state());
        return accepted;
    } catch (const std::exception& error) {
        status_->setText("Replay error: " + QString::fromUtf8(error.what()));
        return false;
    }
}
std::vector<arp::ArpRecord> MainWindow::snapshotRows(bool visibleOnly) const
{
    std::vector<arp::ArpRecord> records;
    if (visibleOnly) {
        for (int row = 0; row < proxy_->rowCount(); ++row)
            records.push_back(model_->recordAt(proxy_->mapToSource(proxy_->index(row, 0)).row()));
    } else {
        for (int row = 0; row < model_->rowCount(); ++row)
            records.push_back(model_->recordAt(row));
    }
    return records;
}
bool MainWindow::exportRows(const QString& path, bool visibleOnly, bool overwrite)
{
    const auto records = snapshotRows(visibleOnly);
    try {
        arp::exportCsv(path.toStdString(), records, overwrite);
        return true;
    } catch (const std::exception& error) {
        status_->setText("Export error: " + QString::fromUtf8(error.what()));
        return false;
    }
}
void MainWindow::updateState(arp::CaptureState state)
{
    if (state == arp::CaptureState::Error)
        closing_ = false;
    const bool active = state == arp::CaptureState::Starting ||
                        state == arp::CaptureState::Running || state == arp::CaptureState::Stopping;
    interfaces_->setEnabled(!active && !closing_);
    recordingDestination_->setEnabled(!active && !closing_);
    openRecordingButton_->setEnabled(!active && !closing_);
    start_->setEnabled(!active && !closing_ && !interfaces_->currentData().toString().isEmpty());
    stop_->setEnabled(state == arp::CaptureState::Starting || state == arp::CaptureState::Running);
    switch (state) {
    case arp::CaptureState::Starting:
        status_->setText("Starting capture…");
        timer_->start();
        break;
    case arp::CaptureState::Running:
        status_->setText(replaying_ ? "Replaying PCAP"
                         : recordingDestination_->text().isEmpty()
                             ? "Capturing — packets are not saved"
                             : "Capturing and recording PCAP");
        break;
    case arp::CaptureState::Stopping:
        status_->setText("Stopping capture…");
        break;
    case arp::CaptureState::Stopped:
        status_->setText(interfaces_->count() == 1 ? "Stopped — no capture interfaces available"
                                                   : "Stopped");
        timer_->stop();
        break;
    case arp::CaptureState::Error:
        status_->setText(lastError_.isEmpty() ? "Capture error" : "Capture error: " + lastError_);
        timer_->stop();
        break;
    }
    if (!active) {
        drainPackets();
        if (closing_ && !exporting_)
            QTimer::singleShot(0, this, [this] { close(); });
    }
}
void MainWindow::drainPackets()
{
    const auto batch = service_->takeBatch();
    std::vector<arp::ArpRecord> records;
    for (const auto& packet : batch) {
        auto result = arp::parseEthernetArp(packet.bytes, packet.metadata);
        if (result.record)
            records.push_back(std::move(*result.record));
        else
            ++errors_;
    }
    appendRecords(records);
}
void MainWindow::appendRecords(const std::vector<arp::ArpRecord>& records)
{
    for (const auto& record : records) {
        if (record.operation == arp::ArpOperation::Request)
            ++requests_;
        else
            ++replies_;
    }
    model_->appendRecords(records);
    updateCounters();
}
void MainWindow::updateCounters()
{
    auto stats = service_->statistics();
    counters_->setText(QStringLiteral("Requests: %1   Replies: %2   Errors: %3   Kernel drops: %4  "
                                      " Interface drops: %5   Application drops: %6")
                           .arg(requests_)
                           .arg(replies_)
                           .arg(errors_)
                           .arg(optionalCount(stats.dropped))
                           .arg(optionalCount(stats.interfaceDropped))
                           .arg(service_->applicationDrops()));
    retention_->setText(
        QStringLiteral("Retained: %1 / 10000   Older packets removed: %2   Display "
                       "filters affect only this view; recording status is shown above")
            .arg(model_->rowCount())
            .arg(model_->discardedCount()));
}
void MainWindow::showDetails()
{
    const auto index = proxy_->mapToSource(table_->currentIndex());
    if (index.isValid())
        details_->setPlainText(recordDetails(model_->recordAt(index.row())));
    else
        details_->clear();
}
void MainWindow::closeEvent(QCloseEvent* event)
{
    const auto state = service_->state();
    const bool active = state == arp::CaptureState::Starting ||
                        state == arp::CaptureState::Running || state == arp::CaptureState::Stopping;
    if (active || exporting_) {
        closing_ = true;
        event->ignore();
        if (active) {
            service_->stop();
            updateState(service_->state());
        }
        return;
    }
    event->accept();
}
ArpTableModel* MainWindow::packetModel() const { return model_; }
std::uint64_t MainWindow::requestCount() const { return requests_; }
std::uint64_t MainWindow::replyCount() const { return replies_; }
std::uint64_t MainWindow::errorCount() const { return errors_; }
