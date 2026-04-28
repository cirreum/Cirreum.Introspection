namespace Cirreum.Introspection;

/// <summary>
/// Provides a composite authorization analyzer that aggregates the results of multiple underlying analyzers.
/// </summary>
/// <remarks>Use this class to perform authorization analysis across multiple analyzers in a single operation. The
/// composite analyzer executes each underlying analyzer and combines their reports into a single aggregated result.
/// Analyzers that support options will receive the specified options; others will use their default behavior.</remarks>
/// <param name="analyzers">The collection of authorization analyzers to be executed as part of the composite analysis. Cannot be null.</param>
/// <param name="options">Optional analysis options to be used by analyzers that support configurable options. If null, default options are
/// used.</param>
public class CompositeAnalyzer(IEnumerable<IDomainAnalyzer> analyzers, AnalysisOptions? options = null) {

	private readonly AnalysisOptions _options = options ?? AnalysisOptions.Default;

	/// <summary>
	/// Performs analysis using all configured analyzers and returns a combined analysis report.
	/// </summary>
	/// <remarks>This method executes each analyzer in sequence and combines their results into a single report. The
	/// behavior may differ depending on the runtime environment; for example, in browser environments, analysis is
	/// performed asynchronously to avoid blocking the UI thread.</remarks>
	/// <returns>An <see cref="AnalysisReport"/> representing the combined results of all analyzers. The report aggregates findings
	/// from each analyzer; if no analyzers are configured, the report will be empty.</returns>
	public AnalysisReport AnalyzeAll() {
		List<AnalysisReport> reports = [];
		foreach (var analyzer in analyzers) {
			var report = analyzer switch {
				IDomainAnalyzerWithOptions withOptions => withOptions.Analyze(this._options),
				_ => analyzer.Analyze()
			};
			reports.Add(report);
		}
		return AnalysisReport.Combine(reports);
	}

}
