#pragma once

#include <QWidget>

#include <memory>

class QLabel;
class QTreeWidget;

namespace dasa::analysis {
struct AnalysisResult;
}

namespace dasa::ui {

/// Content of the Devices dock: the device objects the driver creates
/// (name, type, FILE_DEVICE_SECURE_OPEN, exclusivity, SDDL), its symbolic
/// links and device interfaces - how user mode can reach it.
class DevicesWidget : public QWidget {
    Q_OBJECT

public:
    explicit DevicesWidget(QWidget* parent = nullptr);

    void clear();
    void setResult(std::shared_ptr<const analysis::AnalysisResult> result);

private:
    QLabel* m_summary = nullptr;
    QTreeWidget* m_tree = nullptr;
    QLabel* m_notes = nullptr;
};

} // namespace dasa::ui
