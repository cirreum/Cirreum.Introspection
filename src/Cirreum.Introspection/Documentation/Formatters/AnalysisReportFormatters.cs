namespace Cirreum.Introspection.Documentation.Formatters;

using Cirreum.Introspection;
using System.Text;

/// <summary>
/// Report formatters that leverage analysis features like metric categories and extension methods.
/// </summary>
public static class AnalysisReportFormatters {

	/// <summary>
	/// Generates a comprehensive Markdown report with better organization.
	/// </summary>
	public static string ToMarkdown(this AnalysisReport report) {
		var sb = new StringBuilder();

		// Use the summary extension
		var summary = report.GetSummary();

		sb.AppendLine("# Authorization Analysis Report");
		sb.AppendLine();
		sb.AppendLine($"**Generated**: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
		sb.AppendLine($"**Analyzers Run**: {summary.AnalyzerCount}");
		sb.AppendLine();

		// Executive Summary using extension methods
		sb.AppendLine("## Executive Summary");
		sb.AppendLine();
		sb.AppendLine($"| Status | Count |");
		sb.AppendLine("|--------|-------|");
		sb.AppendLine($"| 🔴 Errors | {summary.ErrorCount} |");
		sb.AppendLine($"| 🟡 Warnings | {summary.WarningCount} |");
		sb.AppendLine($"| 🟢 Info | {summary.InfoCount} |");
		sb.AppendLine($"| **Total Issues** | **{summary.TotalIssues}** |");
		sb.AppendLine();
		sb.AppendLine($"**Overall Result**: {(summary.Passed ? "✅ PASSED" : "❌ FAILED")}");
		if (summary.HighestSeverity.HasValue) {
			sb.AppendLine($"**Highest Severity**: {summary.HighestSeverity.Value}");
		}
		sb.AppendLine();

		// Metrics grouped by category
		if (report.Metrics.Count > 0) {
			sb.AppendLine("## Metrics by Category");
			sb.AppendLine();

			var metricsByCategory = report.Metrics
				.GroupBy(m => MetricCategories.GetMetricCategoryDisplayName(m.Key))
				.OrderBy(g => g.Key);

			foreach (var categoryGroup in metricsByCategory) {
				sb.AppendLine($"### {categoryGroup.Key}");
				sb.AppendLine();
				sb.AppendLine("| Metric | Value |");
				sb.AppendLine("|--------|-------|");

				foreach (var metric in categoryGroup.OrderBy(m => m.Key)) {
					var metricName = MetricCategories.GetMetricName(metric.Key);
					sb.AppendLine($"| {metricName} | {metric.Value:N0} |");
				}
				sb.AppendLine();
			}
		}

		// Issues by severity using extension method
		var issuesBySeverity = report.GetIssuesBySeverity();
		if (issuesBySeverity.Count > 0) {
			sb.AppendLine("## Issues by Severity");
			sb.AppendLine();

			foreach (var severityLevel in new[] { IssueSeverity.Error, IssueSeverity.Warning, IssueSeverity.Info }) {
				if (issuesBySeverity.TryGetValue(severityLevel, out var severityIssues)) {
					sb.AppendLine($"### {GetSeverityIcon(severityLevel)} {severityLevel} Issues ({severityIssues.Count})");
					sb.AppendLine();

					// Group by category within severity
					var byCategory = severityIssues.GroupBy(i => i.Category).OrderBy(g => g.Key);
					foreach (var categoryGroup in byCategory) {
						sb.AppendLine($"#### {categoryGroup.Key}");
						sb.AppendLine();

						foreach (var issue in categoryGroup) {
							sb.AppendLine($"- {issue.Description}");
							if (issue.RelatedTypeNames.Count > 0) {
								sb.AppendLine($"  - **Affected Types**: `{string.Join("`, `", issue.RelatedTypeNames)}`");
							}
						}
						sb.AppendLine();
					}
				}
			}
		}

		// Analyzer coverage
		sb.AppendLine("## Analyzer Coverage");
		sb.AppendLine();
		sb.AppendLine("| Analyzer Category | Issues Found |");
		sb.AppendLine("|-------------------|--------------|");

		var issuesByCategory = report.GetIssuesByCategory();
		foreach (var category in report.AnalyzerCategories.OrderBy(c => c)) {
			var issueCount = issuesByCategory.TryGetValue(category, out var issues) ? issues.Count : 0;
			sb.AppendLine($"| {category} | {issueCount} |");
		}

		// Runtime signals & compliance pointer
		sb.AppendLine();
		sb.AppendLine("## Runtime Signals & Compliance");
		sb.AppendLine();
		sb.AppendLine("This report covers the **static** authorization graph — types, registrations, analyzer findings. For **runtime** security posture, observe these OTel activity tags emitted on every operation:");
		sb.AppendLine();
		sb.AppendLine("| OTel Activity Tag | Surfaces |");
		sb.AppendLine("|-------------------|----------|");
		sb.AppendLine("| `cirreum.authz.decision` | Per-phase pass/deny telemetry across the three-phase pipeline |");
		sb.AppendLine("| `cirreum.authz.grant.owner_auto_stamped` | Phase 1 inferred OwnerId from a single-owner grant rather than the caller supplying it |");
		sb.AppendLine("| `cirreum.authz.grant.pattern_c_bypass` | A Pattern C lookup completed without the handler reading `IOperationGrantAccessor.Current` — possible bypass |");
		sb.AppendLine();
		sb.AppendLine("For the framework's compliance model (NIST SP 800-53 AC-3 / AC-6 / AU-2, NIST SP 800-162 ABAC, OWASP ASVS V4, OWASP Top 10 #1, ISO/IEC 27001 A.9.4.1), see the **Compliance Boundary** section in `Authorization/README.md`.");
		sb.AppendLine();
		sb.AppendLine("Boot-time enforcement: call `app.Services.ValidateAuthorizationConfiguration()` after host build to convert Error-severity findings in this report into a startup failure.");

		return sb.ToString();
	}

	/// <summary>
	/// Generates a simple text report.
	/// </summary>
	public static string ToText(this AnalysisReport report) {
		var sb = new StringBuilder();
		var summary = report.GetSummary();

		sb.AppendLine("AUTHORIZATION ANALYSIS REPORT");
		sb.AppendLine("================================");
		sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
		sb.AppendLine($"Analyzers: {summary.AnalyzerCount}");
		sb.AppendLine();

		sb.AppendLine("EXECUTIVE SUMMARY");
		sb.AppendLine("-----------------");
		sb.AppendLine($"Errors:   {summary.ErrorCount}");
		sb.AppendLine($"Warnings: {summary.WarningCount}");
		sb.AppendLine($"Info:     {summary.InfoCount}");
		sb.AppendLine($"Total:    {summary.TotalIssues}");
		sb.AppendLine($"Result:   {(summary.Passed ? "PASSED" : "FAILED")}");
		sb.AppendLine();

		if (report.Issues.Count > 0) {
			sb.AppendLine("ISSUES");
			sb.AppendLine("------");
			var issuesByCategory = report.GetIssuesByCategory();
			foreach (var category in report.AnalyzerCategories.OrderBy(c => c)) {
				if (issuesByCategory.TryGetValue(category, out var issues) && issues.Count > 0) {
					sb.AppendLine($"\n{category}:");
					foreach (var issue in issues.OrderBy(i => i.Severity)) {
						sb.AppendLine($"  [{issue.Severity}] {issue.Description}");
					}
				}
			}
		}

		sb.AppendLine();
		sb.AppendLine("RUNTIME SIGNALS & COMPLIANCE");
		sb.AppendLine("----------------------------");
		sb.AppendLine("This report covers the static authorization graph. For runtime posture,");
		sb.AppendLine("observe these OTel activity tags on every operation:");
		sb.AppendLine("  - cirreum.authz.decision                     Per-phase pass/deny telemetry");
		sb.AppendLine("  - cirreum.authz.grant.owner_auto_stamped     Framework auto-inferred OwnerId");
		sb.AppendLine("  - cirreum.authz.grant.pattern_c_bypass       Pattern C bypass detected at runtime");
		sb.AppendLine();
		sb.AppendLine("Compliance model: see Authorization/README.md (NIST 800-53 AC-3/AC-6/AU-2,");
		sb.AppendLine("NIST 800-162 ABAC, OWASP ASVS V4, OWASP Top 10 #1, ISO/IEC 27001 A.9.4.1).");
		sb.AppendLine();
		sb.AppendLine("Boot-time enforcement: call app.Services.ValidateAuthorizationConfiguration()");
		sb.AppendLine("after host build to throw on Error-severity findings in this report.");

		return sb.ToString();
	}

	/// <summary>
	/// Generates an HTML report with interactive features.
	/// </summary>
	public static string ToHtml(this AnalysisReport report) {
		var sb = new StringBuilder();
		var summary = report.GetSummary();

		// HTML header with enhanced styling
		sb.AppendLine("<!DOCTYPE html>");
		sb.AppendLine("<html>");
		sb.AppendLine("<head>");
		sb.AppendLine("  <title>Authorization Analysis Report</title>");
		sb.AppendLine("  <style>");
		sb.AppendLine(@"
	body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }
	.container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
	h1, h2, h3 { color: #333; }
	.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
	.summary-card { background: #f8f9fa; padding: 20px; border-radius: 6px; text-align: center; border-left: 4px solid #007bff; }
	.summary-card.error { border-color: #dc3545; }
	.summary-card.warning { border-color: #ffc107; }
	.summary-card.info { border-color: #28a745; }
	.summary-card.pass { border-color: #28a745; background: #d4edda; }
	.summary-card.fail { border-color: #dc3545; background: #f8d7da; }
	.metric-category { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 6px; }
	.metric-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; }
	.metric-item { display: flex; justify-content: space-between; padding: 8px; background: white; border-radius: 4px; }
	.issue-card { margin: 10px 0; padding: 15px; border-radius: 6px; border-left: 4px solid; }
	.issue-error { border-color: #dc3545; background: #f8d7da; }
	.issue-warning { border-color: #ffc107; background: #fff3cd; }
	.issue-info { border-color: #17a2b8; background: #d1ecf1; }
	.related-types { margin-top: 5px; font-family: monospace; font-size: 0.9em; color: #666; }
	.filter-buttons { margin: 20px 0; }
	.filter-button { padding: 8px 16px; margin: 0 5px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; }
	.filter-button.active { background: #007bff; color: white; }
	table { width: 100%; border-collapse: collapse; margin: 10px 0; }
	th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
	th { background: #f8f9fa; font-weight: 600; }
  </style>");
		sb.AppendLine("</head>");
		sb.AppendLine("<body>");
		sb.AppendLine("<div class=\"container\">");

		// Header
		sb.AppendLine($"<h1>Authorization Analysis Report</h1>");
		sb.AppendLine($"<p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | Analyzers: {summary.AnalyzerCount}</p>");

		// Summary cards
		sb.AppendLine("<div class=\"summary-grid\">");
		sb.AppendLine($"  <div class=\"summary-card {(summary.Passed ? "pass" : "fail")}\">");
		sb.AppendLine($"    <h2>{(summary.Passed ? "✅ PASSED" : "❌ FAILED")}</h2>");
		sb.AppendLine($"    <p>{summary.TotalIssues} Total Issues</p>");
		sb.AppendLine("  </div>");
		sb.AppendLine($"  <div class=\"summary-card error\">");
		sb.AppendLine($"    <h3>🔴 {summary.ErrorCount}</h3>");
		sb.AppendLine("    <p>Errors</p>");
		sb.AppendLine("  </div>");
		sb.AppendLine($"  <div class=\"summary-card warning\">");
		sb.AppendLine($"    <h3>🟡 {summary.WarningCount}</h3>");
		sb.AppendLine("    <p>Warnings</p>");
		sb.AppendLine("  </div>");
		sb.AppendLine($"  <div class=\"summary-card info\">");
		sb.AppendLine($"    <h3>🟢 {summary.InfoCount}</h3>");
		sb.AppendLine("    <p>Info</p>");
		sb.AppendLine("  </div>");
		sb.AppendLine("</div>");

		// Metrics by category
		if (report.Metrics.Count > 0) {
			sb.AppendLine("<h2>Metrics</h2>");

			var metricsByCategory = report.Metrics
				.GroupBy(m => MetricCategories.GetMetricCategoryDisplayName(m.Key))
				.OrderBy(g => g.Key);

			foreach (var category in metricsByCategory) {
				sb.AppendLine($"<div class=\"metric-category\">");
				sb.AppendLine($"  <h3>{category.Key}</h3>");
				sb.AppendLine("  <div class=\"metric-grid\">");

				foreach (var metric in category.OrderBy(m => m.Key)) {
					var name = MetricCategories.GetMetricName(metric.Key);
					sb.AppendLine($"    <div class=\"metric-item\">");
					sb.AppendLine($"      <span>{name}</span>");
					sb.AppendLine($"      <strong>{metric.Value:N0}</strong>");
					sb.AppendLine("    </div>");
				}

				sb.AppendLine("  </div>");
				sb.AppendLine("</div>");
			}
		}

		// Issues with filtering
		var issuesBySeverity = report.GetIssuesBySeverity();
		if (issuesBySeverity.Count > 0) {
			sb.AppendLine("<h2>Issues</h2>");

			// Filter buttons
			sb.AppendLine("<div class=\"filter-buttons\">");
			sb.AppendLine("  <button class=\"filter-button active\" onclick=\"filterIssues('all')\">All</button>");
			sb.AppendLine("  <button class=\"filter-button\" onclick=\"filterIssues('error')\">Errors</button>");
			sb.AppendLine("  <button class=\"filter-button\" onclick=\"filterIssues('warning')\">Warnings</button>");
			sb.AppendLine("  <button class=\"filter-button\" onclick=\"filterIssues('info')\">Info</button>");
			sb.AppendLine("</div>");

			sb.AppendLine("<div id=\"issues-container\">");

			foreach (var (severity, issues) in issuesBySeverity.OrderBy(kvp => kvp.Key)) {
				var severityClass = severity.ToString().ToLower();
				var icon = GetSeverityIcon(severity);

				foreach (var issue in issues) {
					sb.AppendLine($"<div class=\"issue-card issue-{severityClass}\" data-severity=\"{severityClass}\">");
					sb.AppendLine($"  <strong>{icon} [{issue.Category}]</strong> {issue.Description}");

					if (issue.RelatedTypeNames.Count > 0) {
						sb.AppendLine($"  <div class=\"related-types\">Types: {string.Join(", ", issue.RelatedTypeNames)}</div>");
					}

					sb.AppendLine("</div>");
				}
			}

			sb.AppendLine("</div>");
		}

		// Analyzer coverage table
		sb.AppendLine("<h2>Analyzer Coverage</h2>");
		sb.AppendLine("<table>");
		sb.AppendLine("  <thead>");
		sb.AppendLine("    <tr><th>Analyzer</th><th>Issues Found</th><th>Status</th></tr>");
		sb.AppendLine("  </thead>");
		sb.AppendLine("  <tbody>");

		var issuesByCategory = report.GetIssuesByCategory();
		foreach (var analyzer in report.AnalyzerCategories.OrderBy(a => a)) {
			var count = issuesByCategory.TryGetValue(analyzer, out var issues) ? issues.Count : 0;
			var status = count == 0 ? "✅ Clean" : "⚠️ Issues Found";
			sb.AppendLine($"    <tr><td>{analyzer}</td><td>{count}</td><td>{status}</td></tr>");
		}

		sb.AppendLine("  </tbody>");
		sb.AppendLine("</table>");

		// Runtime Signals & Compliance appendix
		sb.AppendLine();
		sb.AppendLine("<h2>Runtime Signals &amp; Compliance</h2>");
		sb.AppendLine("<p>This report covers the <strong>static</strong> authorization graph &mdash; types, registrations, analyzer findings. For <strong>runtime</strong> security posture, observe these OTel activity tags emitted on every operation:</p>");
		sb.AppendLine("<table>");
		sb.AppendLine("  <thead><tr><th>OTel Activity Tag</th><th>Surfaces</th></tr></thead>");
		sb.AppendLine("  <tbody>");
		sb.AppendLine("    <tr><td><code>cirreum.authz.decision</code></td><td>Per-phase pass/deny telemetry across the three-phase pipeline</td></tr>");
		sb.AppendLine("    <tr><td><code>cirreum.authz.grant.owner_auto_stamped</code></td><td>Phase 1 inferred OwnerId from a single-owner grant rather than the caller supplying it</td></tr>");
		sb.AppendLine("    <tr><td><code>cirreum.authz.grant.pattern_c_bypass</code></td><td>A Pattern C lookup completed without the handler reading <code>IOperationGrantAccessor.Current</code> &mdash; possible bypass</td></tr>");
		sb.AppendLine("  </tbody>");
		sb.AppendLine("</table>");
		sb.AppendLine("<p>For the framework's compliance model (NIST SP 800-53 AC-3 / AC-6 / AU-2, NIST SP 800-162 ABAC, OWASP ASVS V4, OWASP Top 10 #1, ISO/IEC 27001 A.9.4.1), see the <strong>Compliance Boundary</strong> section in <code>Authorization/README.md</code>.</p>");
		sb.AppendLine("<p><strong>Boot-time enforcement:</strong> call <code>app.Services.ValidateAuthorizationConfiguration()</code> after host build to convert Error-severity findings in this report into a startup failure.</p>");

		// JavaScript for filtering
		sb.AppendLine(@"
<script>
function filterIssues(severity) {
  const buttons = document.querySelectorAll('.filter-button');
  buttons.forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');

  const issues = document.querySelectorAll('.issue-card');
  issues.forEach(issue => {
	if (severity === 'all' || issue.dataset.severity === severity) {
	  issue.style.display = 'block';
	} else {
	  issue.style.display = 'none';
	}
  });
}
</script>");

		sb.AppendLine("</div>");
		sb.AppendLine("</body>");
		sb.AppendLine("</html>");

		return sb.ToString();
	}

	/// <summary>
	/// Generates an enhanced CSV report with better structure.
	/// </summary>
	public static string ToCsv(this AnalysisReport report) {
		var sb = new StringBuilder();
		var summary = report.GetSummary();

		// Summary section
		sb.AppendLine("# AUTHORIZATION ANALYSIS REPORT");
		sb.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
		sb.AppendLine($"# Status: {(summary.Passed ? "PASSED" : "FAILED")}");
		sb.AppendLine($"# Total Issues: {summary.TotalIssues} (Errors: {summary.ErrorCount}, Warnings: {summary.WarningCount}, Info: {summary.InfoCount})");
		sb.AppendLine();

		// Issues by severity and category
		sb.AppendLine("## ISSUES");
		sb.AppendLine("Severity,Category,Description,RelatedTypes,TypeCount");

		var issuesBySeverity = report.GetIssuesBySeverity();
		foreach (var severity in new[] { IssueSeverity.Error, IssueSeverity.Warning, IssueSeverity.Info }) {
			if (issuesBySeverity.TryGetValue(severity, out var issues)) {
				foreach (var issue in issues.OrderBy(i => i.Category)) {
					sb.AppendLine(
						$"{EscapeCsv(severity)}," +
						$"{EscapeCsv(issue.Category)}," +
						$"{EscapeCsv(issue.Description)}," +
						$"{EscapeCsv(string.Join("; ", issue.RelatedTypeNames))}," +
						$"{issue.RelatedTypeNames.Count}"
					);
				}
			}
		}
		sb.AppendLine();

		// Metrics grouped by category
		sb.AppendLine("## METRICS BY CATEGORY");
		sb.AppendLine("Category,MetricName,Value");

		var metricsByCategory = report.Metrics
			.GroupBy(m => MetricCategories.GetMetricCategoryDisplayName(m.Key))
			.OrderBy(g => g.Key);

		foreach (var category in metricsByCategory) {
			foreach (var metric in category.OrderBy(m => m.Key)) {
				var name = MetricCategories.GetMetricName(metric.Key);
				sb.AppendLine($"{EscapeCsv(category.Key)},{EscapeCsv(name)},{metric.Value}");
			}
		}
		sb.AppendLine();

		// Analyzer summary
		sb.AppendLine("## ANALYZER SUMMARY");
		sb.AppendLine("AnalyzerCategory,IssueCount,ErrorCount,WarningCount,InfoCount");

		var issuesByCategory = report.GetIssuesByCategory();
		foreach (var analyzer in report.AnalyzerCategories.OrderBy(a => a)) {
			if (issuesByCategory.TryGetValue(analyzer, out var issues)) {
				var errors = issues.Count(i => i.Severity == IssueSeverity.Error);
				var warnings = issues.Count(i => i.Severity == IssueSeverity.Warning);
				var infos = issues.Count(i => i.Severity == IssueSeverity.Info);
				sb.AppendLine($"{EscapeCsv(analyzer)},{issues.Count},{errors},{warnings},{infos}");
			} else {
				sb.AppendLine($"{EscapeCsv(analyzer)},0,0,0,0");
			}
		}

		return sb.ToString();
	}

	// Helper methods

	private static string GetSeverityIcon(IssueSeverity severity) {
		return severity switch {
			IssueSeverity.Error => "🔴",
			IssueSeverity.Warning => "🟡",
			IssueSeverity.Info => "🟢",
			_ => "⚪"
		};
	}

	private static string EscapeCsv(object value) {
		if (value == null) {
			return string.Empty;
		}

		var str = value.ToString() ?? string.Empty;
		if (str.Contains('"') || str.Contains(',') || str.Contains('\n')) {
			return $"\"{str.Replace("\"", "\"\"")}\"";
		}
		return str;
	}
}
