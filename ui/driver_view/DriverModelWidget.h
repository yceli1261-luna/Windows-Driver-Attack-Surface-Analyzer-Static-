#pragma once

#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QTreeWidget;
class QTreeWidgetItem;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Content of the IRP Handlers dock: the driver model with its evidence,
/// the DriverEntry chain, and how the driver registers request handlers -
/// the MajorFunction[] table for WDM, WdfDriverCreate / WdfIoQueueCreate
/// callbacks for KMDF.
class DriverModelWidget : public QWidget {
    Q_OBJECT

public:
    explicit DriverModelWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

signals:
    /// A handler or callback was double-clicked.
    void functionActivated(std::uint64_t rva);

private:
    void onItemActivated(QTreeWidgetItem* item);
    QString functionLabel(std::uint64_t rva) const;

    std::shared_ptr<const analysis::AnalysisResult> m_result;
    QLabel* m_header = nullptr;
    QTreeWidget* m_tree = nullptr;
    QLabel* m_notes = nullptr;
};

} // namespace dasa::ui
