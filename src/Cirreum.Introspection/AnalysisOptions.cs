namespace Cirreum.Introspection;

/// <summary>
/// Configuration options for authorization analysis.
/// </summary>
public record AnalysisOptions {

	/// <summary>
	/// Creates an empty analysis options instance with default values.
	/// </summary>
	public AnalysisOptions() {

	}

	/// <summary>
	/// Maximum recommended role hierarchy depth.
	/// </summary>
	public int MaxHierarchyDepth { get; init; } = 10;

	/// <summary>
	/// Analyzer categories to exclude from analysis.
	/// </summary>
	public HashSet<string> ExcludedCategories { get; init; } = [];

	/// <summary>
	/// Gets the default analysis options.
	/// </summary>
	public static AnalysisOptions Default { get; } = new();
}
