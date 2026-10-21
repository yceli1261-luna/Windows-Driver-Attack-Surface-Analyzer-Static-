#include "ui/database_view/ComparisonHtml.h"

#include <QStringList>
#include <QTimeZone>

#include "ui/findings_view/SeverityColors.h"

namespace dasa::ui {

namespace db = core::database;

namespace {

QString q(const std::string& s) {
    return QString::fromStdString(s).toHtmlEscaped();
}

QColor severityTextColor(const std::string& severity) {
    return riskLevelColor(QString::fromStdString(severity));
}

QString findingList(const std::vector<db::StoredFinding>& findings) {
    if (findings.empty()) {
        return QStringLiteral("<p style='color:#9a9a9a'>none</p>");
    }
    QString html = QStringLiteral("<ul style='margin-top:2px'>");
    for (const auto& f : findings) {
        html += QStringLiteral("<li><span style='color:%1'>%2</span> &middot; %3 "
                               "<span style='color:#9a9a9a'>(%4)</span></li>")
                    .arg(severityTextColor(f.severity).name(), q(f.severity), q(f.title), q(f.ruleId));
    }
    return html + QStringLiteral("</ul>");
}

QString ioctlList(const std::vector<db::StoredIoctl>& ioctls) {
    QStringList items;
    for (const auto& x : ioctls) {
        items << QStringLiteral("<code>0x%1</code> %2").arg(x.code, 8, 16, QLatin1Char('0')).arg(q(x.method));
    }
    return items.isEmpty() ? QStringLiteral("<span style='color:#9a9a9a'>none</span>")
                           : items.join(QStringLiteral(", "));
}

QString apiList(const std::vector<db::StoredApi>& apis) {
    QStringList items;
    for (const auto& a : apis) {
        items << QStringLiteral("<code>%1</code> <span style='color:#9a9a9a'>%2</span>").arg(q(a.name), q(a.risk));
    }
    return items.isEmpty() ? QStringLiteral("<span style='color:#9a9a9a'>none</span>")
                           : items.join(QStringLiteral(", "));
}

} // namespace

QString localTime(const std::string& utc) {
    QDateTime t = QDateTime::fromString(QString::fromStdString(utc), QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    if (!t.isValid()) {
        return QString::fromStdString(utc);
    }
    t.setTimeZone(QTimeZone::UTC);
    return t.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

QString analysisLabel(const db::AnalysisSummary& s) {
    return QStringLiteral("#%1  %2  %3  risk %4")
        .arg(s.id)
        .arg(QString::fromStdString(s.fileName), localTime(s.analyzedAt))
        .arg(s.riskScore);
}

QString comparisonHtml(const db::Comparison& c, const QString& aName, const QString& bName) {
    const auto side = [](const db::AnalysisSummary& s, const QString& name) {
        return QStringLiteral("<td style='padding-right:24px'><b>%1</b><br>%2 &middot; %3<br>"
                              "<span style='color:%4'>%5/100 %6</span> &middot; %7 findings &middot; %8 IOCTLs"
                              "<br><span style='color:#9a9a9a'>SHA-256 %9</span></td>")
            .arg(name.toHtmlEscaped(), q(s.fileName), localTime(s.analyzedAt),
                 riskLevelColor(QString::fromStdString(s.riskLevel)).name())
            .arg(s.riskScore)
            .arg(q(s.riskLevel))
            .arg(s.findingCount)
            .arg(s.ioctlCount)
            .arg(q(s.sha256.substr(0, 16)) + QStringLiteral("..."));
    };
    QString html = QStringLiteral("<table><tr>") + side(c.a, aName) + side(c.b, bName) + QStringLiteral("</tr></table>");

    const QString delta = c.riskDelta > 0   ? QStringLiteral("<span style='color:#f1706b'>+%1</span>").arg(c.riskDelta)
                          : c.riskDelta < 0 ? QStringLiteral("<span style='color:#6cc68a'>%1</span>").arg(c.riskDelta)
                                            : QStringLiteral("unchanged");
    html += QStringLiteral("<p>Risk score %1. ").arg(delta);
    if (c.a.sha256 == c.b.sha256) {
        html += QStringLiteral("Same file (identical SHA-256): differences come from DASA's analysis, not the driver.");
    } else {
        html += QStringLiteral("Different files.");
    }
    html += QStringLiteral("</p>");

    html += QStringLiteral("<p style='margin-bottom:0'><b>New in %1</b> (%2)</p>")
                .arg(bName.toHtmlEscaped())
                .arg(c.onlyInB.size()) +
            findingList(c.onlyInB);
    html += QStringLiteral("<p style='margin-bottom:0'><b>Only in %1</b> (%2)</p>")
                .arg(aName.toHtmlEscaped())
                .arg(c.onlyInA.size()) +
            findingList(c.onlyInA);
    html += QStringLiteral("<p style='margin-bottom:0'><b>In both</b> (%1)</p>").arg(c.inBoth.size()) +
            findingList(c.inBoth);
    html += QStringLiteral("<p><b>IOCTLs only in %1:</b> %2<br><b>IOCTLs only in %3:</b> %4</p>")
                .arg(bName.toHtmlEscaped(), ioctlList(c.ioctlsOnlyInB), aName.toHtmlEscaped(), ioctlList(c.ioctlsOnlyInA));
    html += QStringLiteral("<p><b>Risky APIs only in %1:</b> %2<br><b>Risky APIs only in %3:</b> %4</p>")
                .arg(bName.toHtmlEscaped(), apiList(c.apisOnlyInB), aName.toHtmlEscaped(), apiList(c.apisOnlyInA));
    html += QStringLiteral("<p style='color:#9a9a9a'>Findings are matched on rule and title, IOCTLs on code, APIs "
                           "(medium risk and above) on name.</p>");
    return html;
}

} // namespace dasa::ui
