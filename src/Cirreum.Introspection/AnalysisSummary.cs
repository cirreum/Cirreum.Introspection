namespace Cirreum.Introspection;

/// <summary>
/// Summary information about an analysis report.
/// </summary>
public record AnalysisSummary(
	int TotalIssues,
	int ErrorCount,
	int WarningCount,
	int InfoCount,
	int AnalyzerCount,
	int MetricCount
) {
	/// <summary>
	/// Gets whether the analysis passed (no errors).
	/// </summary>
	public bool Passed => this.ErrorCount == 0;

	/// <summary>
	/// Gets the highest severity found.
	/// </summary>
	public IssueSeverity? HighestSeverity =>
		this.ErrorCount > 0 ? IssueSeverity.Error :
		this.WarningCount > 0 ? IssueSeverity.Warning :
		this.InfoCount > 0 ? IssueSeverity.Info :
		null;
}
