namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Aggregate metrics for the entire operation catalog.
/// </summary>
public record CatalogMetrics {
	/// <summary>
	/// Total number of domain areas.
	/// </summary>
	public int TotalDomains { get; init; }

	/// <summary>
	/// Total number of distinct operation kinds.
	/// </summary>
	public int TotalKinds { get; init; }

	/// <summary>
	/// Total number of operations.
	/// </summary>
	public int TotalOperations { get; init; }

	/// <summary>
	/// Number of protected operations.
	/// </summary>
	public int ProtectedOperations { get; init; }

	/// <summary>
	/// Number of anonymous operations.
	/// </summary>
	public int AnonymousOperations { get; init; }

	/// <summary>
	/// Overall authorization coverage percentage.
	/// </summary>
	public int OverallCoveragePercentage { get; init; }
}
