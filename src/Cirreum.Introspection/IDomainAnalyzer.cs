namespace Cirreum.Introspection;

/// <summary>
/// Defines interface of an authorization analyzers.
/// </summary>
public interface IDomainAnalyzer {
	/// <summary>
	/// Analyzes for potential issues.
	/// </summary>
	/// <returns>A report containing any found issues and metrics.</returns>
	AnalysisReport Analyze();
}
