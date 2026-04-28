namespace Cirreum.Introspection;

using System.Text.Json.Serialization;

/// <summary>
/// Represents a complete analysis report containing issues, metrics, and analyzed categories.
/// </summary>
public record AnalysisReport {

	/// <summary>
	/// Creates an empty analysis report. For programmatic creation, prefer using
	/// <see cref="ForCategory(string, List{AnalysisIssue}?, Dictionary{string, int}?)"/>
	/// or <see cref="Combine(List{AnalysisReport})"/>.
	/// </summary>
	[JsonConstructor]
	public AnalysisReport() {

	}

	/// <summary>
	/// Gets whether the analysis found any issues.
	/// </summary>
	public bool HasIssues => this.Issues.Count > 0;

	/// <summary>
	/// Gets the list of issues found during analysis.
	/// </summary>
	public List<AnalysisIssue> Issues { get; init; } = [];

	/// <summary>
	/// Gets additional metrics collected during analysis.
	/// </summary>
	public Dictionary<string, int> Metrics { get; init; } = [];

	/// <summary>
	/// Gets the set of analyzer categories that were run.
	/// </summary>
	public HashSet<string> AnalyzerCategories { get; init; } = [];

	/// <summary>
	/// Creates a new AnalysisReport for a single analyzer category.
	/// </summary>
	public static AnalysisReport ForCategory(
		string category,
		List<AnalysisIssue>? issues = null,
		Dictionary<string, int>? metrics = null) {
		return new AnalysisReport {
			Issues = issues ?? [],
			Metrics = metrics ?? [],
			AnalyzerCategories = [category]
		};
	}

	/// <summary>
	/// Combines multiple analysis reports into a single report.
	/// </summary>
	public static AnalysisReport Combine(List<AnalysisReport> reports) {
		return new AnalysisReport {
			Issues = [.. reports.SelectMany(r => r.Issues)],
			Metrics = reports
				.SelectMany(r => r.Metrics)
				.GroupBy(kvp => kvp.Key)
				.ToDictionary(g => g.Key, g => g.Last().Value),
			AnalyzerCategories = [.. reports.SelectMany(r => r.AnalyzerCategories)]
		};
	}

}
