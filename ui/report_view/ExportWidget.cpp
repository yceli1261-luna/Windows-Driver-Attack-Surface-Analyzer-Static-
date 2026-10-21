#include "ui/report_view/ExportWidget.h"

#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QUrl>
#include <QVBoxLayout>

#include "analysis/report/ReportWriter.h"
#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::ui {

ExportWidget::ExportWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(10);

    m_summary = new QLabel(this);
    m_summary->setMinimumWidth(1); // unwrapped; see HistoryWidget
    m_summary->setTextFormat(Qt::RichText);
    layout->addWidget(m_summary);

    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(8);
    m_html = new QPushButton(tr("Export HTML Report..."), this);
    m_json = new QPushButton(tr("Export JSON..."), this);
    m_html->setToolTip(tr("A single self-contained HTML file: findings with evidence, IOCTLs, devices, APIs"));
    m_json->setToolTip(tr("Everything DASA found, machine-readable (schema dasa-report/1)"));
    buttons->addWidget(m_html);
    buttons->addWidget(m_json);
    buttons->addStretch(1);
    layout->addLayout(buttons);

    m_status = new QLabel(this);
    m_status->setMinimumWidth(1);
    m_status->setTextFormat(Qt::RichText);
    m_status->setOpenExternalLinks(false);
    connect(m_status, &QLabel::linkActivated, this,
            [](const QString& link) { QDesktopServices::openUrl(QUrl(link)); });
    layout->addWidget(m_status);
    layout->addStretch(1);

    connect(m_html, &QPushButton::clicked, this, &ExportWidget::exportHtml);
    connect(m_json, &QPushButton::clicked, this, &ExportWidget::exportJson);
    clear();
}

void ExportWidget::clear() {
    m_result.reset();
    m_summary->setText(tr("Load a driver to export its analysis. Stored analyses can also be exported from "
                          "Analysis History."));
    m_status->clear();
    m_html->setEnabled(false);
    m_json->setEnabled(false);
}

void ExportWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_status->clear();
    m_html->setEnabled(true);
    m_json->setEnabled(true);
    const auto& risk = m_result->findings->risk;
    m_summary->setText(tr("<b>%1</b> &middot; risk %2/100 (%3) &middot; %4 findings &middot; %5 IOCTLs")
                           .arg(QString::fromStdString(m_result->image->fileName).toHtmlEscaped())
                           .arg(risk.score)
                           .arg(QString::fromStdString(risk.level))
                           .arg(m_result->findings->findings.size())
                           .arg(m_result->ioctls->ioctls.size()));
}

void ExportWidget::exportHtml() {
    save(tr("Export HTML Report"), QStringLiteral("html"), tr("HTML report (*.html)"), true);
}

void ExportWidget::exportJson() {
    save(tr("Export JSON"), QStringLiteral("json"), tr("JSON (*.json)"), false);
}

void ExportWidget::save(const QString& title, const QString& suffix, const QString& filter, bool html) {
    if (!m_result) {
        return;
    }
    QSettings settings;
    const QString dir = settings.value(QStringLiteral("lastExportDir"), QDir::homePath()).toString();
    const QString base = QFileInfo(QString::fromStdString(m_result->image->fileName)).completeBaseName();
    const QString path = QFileDialog::getSaveFileName(
        this, title, QDir(dir).filePath(QStringLiteral("%1-dasa.%2").arg(base, suffix)), filter);
    if (path.isEmpty()) {
        return;
    }
    settings.setValue(QStringLiteral("lastExportDir"), QFileInfo(path).absolutePath());

    std::string content;
    try {
        content = html ? analysis::reportHtml(*m_result) : analysis::reportJson(*m_result);
    } catch (const std::exception& ex) {
        m_status->setText(tr("<span style='color:#f1706b'>Could not build the report: %1</span>")
                              .arg(QString::fromStdString(ex.what()).toHtmlEscaped()));
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
        f.write(content.data(), static_cast<qint64>(content.size())) != static_cast<qint64>(content.size())) {
        m_status->setText(tr("<span style='color:#f1706b'>Could not write %1: %2</span>")
                              .arg(QDir::toNativeSeparators(path).toHtmlEscaped(), f.errorString().toHtmlEscaped()));
        return;
    }
    f.close();
    const QString url = QUrl::fromLocalFile(path).toString();
    m_status->setText(tr("Saved <a href=\"%1\">%2</a> (%3 KB) &middot; <a href=\"%4\">open folder</a>")
                          .arg(url.toHtmlEscaped(), QDir::toNativeSeparators(path).toHtmlEscaped())
                          .arg((content.size() + 1023) / 1024)
                          .arg(QUrl::fromLocalFile(QFileInfo(path).absolutePath()).toString().toHtmlEscaped()));
    emit exported(path);
}

} // namespace dasa::ui
