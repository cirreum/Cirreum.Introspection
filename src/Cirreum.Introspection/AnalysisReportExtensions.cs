namespace Cirreum.Introspection;

/// <summary>
/// Extension methods for AnalysisReport.
/// </summary>
public static class AnalysisReportExtensions {

	/// <summary>
	/// Gets a summary of the analysis report.
	/// </summary>
	public static AnalysisSummary GetSummary(this AnalysisReport report) {
		return new AnalysisSummary(
			TotalIssues: report.Issues.Count,
			ErrorCount: report.Issues.Count(i => i.Severity == IssueSeverity.Error),
			WarningCount: report.Issues.Count(i => i.Severity == IssueSeverity.Warning),
			InfoCount: report.Issues.Count(i => i.Severity == IssueSeverity.Info),
			AnalyzerCount: report.AnalyzerCategories.Count,
			MetricCount: report.Metrics.Count
		);
	}

	/// <summary>
	/// Gets issues grouped by severity.
	/// </summary>
	public static IReadOnlyDictionary<IssueSeverity, List<AnalysisIssue>> GetIssuesBySeverity(
		this AnalysisReport report) {
		return report.Issues
			.GroupBy(i => i.Severity)
			.ToDictionary(g => g.Key, g => g.ToList());
	}

	/// <summary>
	/// Gets issues grouped by category.
	/// </summary>
	public static IReadOnlyDictionary<string, List<AnalysisIssue>> GetIssuesByCategory(
		this AnalysisReport report) {
		return report.Issues
			.GroupBy(i => i.Category)
			.ToDictionary(g => g.Key, g => g.ToList());
	}

	/// <summary>
	/// Filters the report to only include issues of specified severities.
	/// </summary>
	public static AnalysisReport FilterBySeverity(
		this AnalysisReport report,
		params IssueSeverity[] severities) {
		var severitySet = severities.ToHashSet();
		return report with {
			Issues = [.. report.Issues.Where(i => severitySet.Contains(i.Severity))]
		};
	}
}
