namespace Cirreum.Introspection;

/// <summary>
/// Defines interface for authorization analyzers that support configuration options.
/// </summary>
public interface IDomainAnalyzerWithOptions : IDomainAnalyzer {
	/// <summary>
	/// Analyzes for potential issues using the provided options.
	/// </summary>
	/// <param name="options">The analysis options to use.</param>
	/// <returns>A report containing any found issues and metrics.</returns>
	AnalysisReport Analyze(AnalysisOptions options);
}
