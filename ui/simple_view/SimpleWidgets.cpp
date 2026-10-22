#include "ui/simple_view/SimpleWidgets.h"

#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollBar>
#include <QTextBrowser>
#include <QUrl>
#include <QVBoxLayout>

#include "analysis/report/PlainLanguage.h"
#include "analysis/static/StaticAnalysisPipeline.h"
#include "ui/findings_view/SeverityColors.h"
#include "ui/report_view/Phase12Widgets.h"

namespace dasa::ui {

namespace fnd = core::findings;

namespace {

QString q(const std::string& s) {
    return QString::fromStdString(s).toHtmlEscaped();
}

QColor verdictColor(analysis::Verdict v) {
    switch (v) {
    case analysis::Verdict::Dangerous: return severityColor(fnd::Severity::Critical);
    case analysis::Verdict::Risky: return severityColor(fnd::Severity::High);
    case analysis::Verdict::WorthALook: return severityColor(fnd::Severity::Medium);
    case analysis::Verdict::Safe: break;
    }
    return QColor(0x6c, 0xc6, 0x8a);
}

QColor seriousnessColor(const std::string& s) {
    if (s == "Serious") return severityColor(fnd::Severity::Critical);
    if (s == "High") return severityColor(fnd::Severity::High);
    if (s == "Moderate") return severityColor(fnd::Severity::Medium);
    if (s == "Minor") return severityColor(fnd::Severity::Low);
    return QColor(0xb0, 0xb0, 0xb0);
}

QTextBrowser* makeBrowser(QWidget* parent) {
    auto* b = new QTextBrowser(parent);
    b->setOpenLinks(false);
    b->setFrameShape(QFrame::NoFrame);
    b->setMinimumHeight(60);
    QFont f = b->font();
    f.setPointSizeF(f.pointSizeF() + 1.0); // a little larger: this is the reading view
    b->setFont(f);
    return b;
}

QString bullets(const std::vector<std::string>& items) {
    QString html = QStringLiteral("<ul style='margin-top:4px'>");
    for (const auto& s : items) {
        html += QStringLiteral("<li style='margin-bottom:4px'>") + q(s) + QStringLiteral("</li>");
    }
    return html + QStringLiteral("</ul>");
}

} // namespace

// =============================================================== Overview ==

OverviewWidget::OverviewWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 16, 24, 16);
    layout->setSpacing(12);
    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(10);
    m_drivers = new QPushButton(tr("Choose a driver on this PC"), this);
    m_open = new QPushButton(tr("Open a driver file..."), this);
    m_export = new QPushButton(tr("Save a report..."), this);
    for (auto* b : {m_drivers, m_open, m_export}) {
        b->setMinimumHeight(34);
        buttons->addWidget(b);
    }
    buttons->addStretch(1);
    layout->addLayout(buttons);
    m_view = makeBrowser(this);
    layout->addWidget(m_view, 1);

    connect(m_drivers, &QPushButton::clicked, this, &OverviewWidget::driversRequested);
    connect(m_open, &QPushButton::clicked, this, &OverviewWidget::openFileRequested);
    connect(m_export, &QPushButton::clicked, this, &OverviewWidget::exportRequested);
    connect(m_view, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
        if (url.toString() == QLatin1String("action:problems")) emit problemsRequested();
        if (url.toString() == QLatin1String("action:drivers")) emit driversRequested();
    });
    showWelcome();
}

void OverviewWidget::showWelcome() {
    m_export->setEnabled(false);
    m_view->setHtml(tr(
        "<p style='font-size:20pt; font-weight:600'>Check a Windows driver for security problems</p>"
        "<p style='color:#b0b0b0'>Drivers run inside Windows with full control of the computer. A badly written "
        "driver can let any program - including malware - take over the PC. DASA reads a driver file and tells you, "
        "in plain words, whether that's possible. It never runs the driver.</p>"
        "<p style='font-size:13pt; font-weight:600; margin-top:18px'>How it works</p>"
        "<ol style='font-size:12pt'>"
        "<li style='margin-bottom:8px'><b>Pick a driver</b> - click <i>Choose a driver on this PC</i> to see the "
        "drivers installed on your computer, or drag a <b>.sys</b> file onto this window.</li>"
        "<li style='margin-bottom:8px'><b>Read the verdict</b> - a traffic light (Safe / Worth a look / Risky / "
        "Dangerous) and what it means for you.</li>"
        "<li style='margin-bottom:8px'><b>Save a report</b> to keep it or send it to the maker or your IT team.</li>"
        "</ol>"
        "<p style='color:#9a9a9a; margin-top:18px'>Tip: drivers made by Microsoft are rarely the problem - "
        "<i>Choose a driver on this PC</i> shows third-party drivers first. Experts can switch to "
        "<b>Expert mode</b> (bottom right) for the full technical analysis.</p>"));
}

void OverviewWidget::showLoading(const QString& fileName) {
    m_export->setEnabled(false);
    m_view->setHtml(tr("<p style='font-size:16pt; font-weight:600'>Checking %1 ...</p>"
                       "<p style='color:#9a9a9a'>This usually takes a few seconds.</p>")
                        .arg(fileName.toHtmlEscaped()));
}

void OverviewWidget::showError(const QString& fileName, const QString& error) {
    m_export->setEnabled(false);
    m_view->setHtml(tr("<p style='font-size:16pt; font-weight:600'>%1 couldn't be checked</p>"
                       "<p>It may not be a Windows driver, or the file may be damaged.</p>"
                       "<p style='color:#9a9a9a'>Details: %2</p>")
                        .arg(fileName.toHtmlEscaped(), error.toHtmlEscaped()));
}

void OverviewWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    const auto s = analysis::explain(*result);
    const auto info = fileVersionInfo(QString::fromStdString(result->image->path.string()));
    m_export->setEnabled(true);
    const QColor c = verdictColor(s.verdict);

    QString html;
    html += QStringLiteral("<p style='font-size:18pt; font-weight:600; margin-bottom:0'>%1</p>")
                .arg(q(result->image->fileName));
    QStringList about;
    if (!info.description.isEmpty()) about << info.description.toHtmlEscaped();
    if (!info.company.isEmpty()) about << tr("made by %1").arg(info.company.toHtmlEscaped());
    if (!info.version.isEmpty()) about << tr("version %1").arg(info.version.toHtmlEscaped());
    if (!about.isEmpty()) {
        html += QStringLiteral("<p style='color:#b0b0b0; margin-top:2px'>%1</p>").arg(about.join(QStringLiteral(" &middot; ")));
    }
    // Traffic light.
    html += QStringLiteral(
                "<table cellpadding='14' style='margin-top:8px'><tr>"
                "<td style='background-color:%1; color:#111111; font-size:20pt; font-weight:700'>&nbsp;%2&nbsp;</td>"
                "<td style='font-size:13pt'>%3</td></tr></table>")
                .arg(c.name(), QString::fromLatin1(analysis::verdictName(s.verdict)).toHtmlEscaped(), q(s.verdictLine));

    html += tr("<p style='font-size:14pt; font-weight:600; margin-top:16px'>What can this driver do?</p>") + bullets(s.canDo);
    html += tr("<p style='font-size:14pt; font-weight:600'>Who can use it?</p><p>%1</p>").arg(q(s.whoCanUse));
    html += tr("<p style='font-size:14pt; font-weight:600'>What should I do?</p>") + bullets(s.whatToDo);

    std::vector<const analysis::PlainProblem*> top;
    for (const auto& p : s.problems) {
        if (top.size() >= 3 || p.seriousness == "Note" || p.seriousness == "Minor") break;
        top.push_back(&p);
    }
    if (!top.empty()) {
        html += tr("<p style='font-size:14pt; font-weight:600'>Most important problems</p>");
        for (const auto* p : top) {
            html += QStringLiteral("<p><span style='color:%1; font-weight:600'>%2</span> &nbsp;<b>%3</b><br>"
                                   "<span style='color:#c8c8c8'>%4</span></p>")
                        .arg(seriousnessColor(p->seriousness).name(), q(p->seriousness), q(p->headline), q(p->consequence));
        }
    }
    html += tr("<p><a href='action:problems'>See all %n problem(s) explained &rarr;</a></p>", nullptr,
               static_cast<int>(s.problems.size()));
    html += tr("<p style='color:#9a9a9a'>DASA reads the driver without running it. It can miss things and it can't "
               "see every safety check a driver makes, so treat this as a strong hint, not a final judgment.</p>");
    m_view->setHtml(html);
}

// =============================================================== Problems ==

ProblemsWidget::ProblemsWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 16, 24, 16);
    m_view = makeBrowser(this);
    layout->addWidget(m_view, 1);
    connect(m_view, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
        const QString s = url.toString();
        if (s.startsWith(QLatin1String("toggle:"))) {
            const int i = s.mid(7).toInt();
            if (m_expanded.contains(i)) m_expanded.remove(i);
            else m_expanded.insert(i);
            const int scroll = m_view->verticalScrollBar()->value();
            render();
            m_view->verticalScrollBar()->setValue(scroll);
        }
    });
    clear();
}

void ProblemsWidget::clear() {
    m_result.reset();
    m_expanded.clear();
    m_view->setHtml(tr("<p style='color:#9a9a9a'>Pick a driver first - its problems are explained here.</p>"));
}

void ProblemsWidget::setResult(std::shared_ptr<const analysis::AnalysisResult> result) {
    m_result = std::move(result);
    m_expanded.clear();
    render();
}

void ProblemsWidget::render() {
    if (!m_result) {
        return;
    }
    const auto s = analysis::explain(*m_result);
    const auto& findings = m_result->findings->findings;
    QString html = tr("<p style='font-size:16pt; font-weight:600'>Problems found in %1</p>")
                       .arg(q(m_result->image->fileName));
    if (s.problems.empty()) {
        html += tr("<p>None - DASA found nothing to report.</p>");
    }
    for (std::size_t i = 0; i < s.problems.size(); ++i) {
        const auto& p = s.problems[i];
        const int idx = static_cast<int>(i);
        html += QStringLiteral("<p style='margin-top:14px; margin-bottom:2px'><span style='color:%1; font-weight:600'>"
                               "%2</span> &nbsp;<span style='font-size:13pt; font-weight:600'>%3</span></p>")
                    .arg(seriousnessColor(p.seriousness).name(), q(p.seriousness), q(p.headline));
        html += QStringLiteral("<p style='margin:2px 0'>%1</p>").arg(q(p.explanation));
        html += tr("<p style='margin:2px 0; color:#c8c8c8'><b>What could happen:</b> %1</p>").arg(q(p.consequence));
        const bool open = m_expanded.contains(idx);
        html += QStringLiteral("<p style='margin:2px 0'><a href='toggle:%1'>%2</a></p>")
                    .arg(idx)
                    .arg(open ? tr("Hide technical details") : tr("Show technical details"));
        if (open) {
            const auto& f = findings[p.findingIndex];
            html += QStringLiteral("<div style='margin-left:16px; color:#b8b8b8'>");
            html += QStringLiteral("<p><b>%1</b> <span style='color:#9a9a9a'>(%2, %3 confidence)</span></p>")
                        .arg(q(f.title), q(f.ruleId), QString::fromLatin1(fnd::confidenceName(f.confidence)));
            html += QStringLiteral("<p>%1</p>").arg(q(f.description));
            html += tr("<p><b>Fix (for the driver's maker):</b> %1</p>").arg(q(f.recommendation));
            if (!f.evidence.empty()) {
                html += tr("<p><b>Evidence:</b></p><ol>");
                for (const auto& step : f.evidence.front()) {
                    html += QStringLiteral("<li>%1 <span style='color:#9a9a9a'>%2</span></li>")
                                .arg(q(step.label), q(step.detail));
                }
                html += QStringLiteral("</ol>");
            }
            html += QStringLiteral("</div>");
        }
    }
    html += tr("<p style='color:#9a9a9a; margin-top:18px'>Words you don't know? See Help &gt; Glossary.</p>");
    m_view->setHtml(html);
}

// =============================================================== Glossary ==

void showGlossary(QWidget* parent) {
    QDialog dialog(parent);
    dialog.setWindowTitle(QObject::tr("Glossary"));
    dialog.resize(640, 560);
    auto* layout = new QVBoxLayout(&dialog);
    auto* view = new QTextBrowser(&dialog);
    view->setFrameShape(QFrame::NoFrame);
    QString html = QObject::tr("<p style='font-size:14pt; font-weight:600'>Words used in DASA</p>");
    for (const auto& e : analysis::glossary()) {
        html += QStringLiteral("<p><b>%1</b><br>%2</p>").arg(q(e.term), q(e.meaning));
    }
    view->setHtml(html);
    layout->addWidget(view);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    dialog.exec();
}

} // namespace dasa::ui
