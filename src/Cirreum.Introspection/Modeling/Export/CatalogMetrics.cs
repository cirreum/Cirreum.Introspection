namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Aggregate metrics for the entire resource catalog.
/// </summary>
public record CatalogMetrics {
	/// <summary>
	/// Total number of domain areas.
	/// </summary>
	public int TotalDomains { get; init; }

	/// <summary>
	/// Total number of distinct resource kinds.
	/// </summary>
	public int TotalKinds { get; init; }

	/// <summary>
	/// Total number of resources.
	/// </summary>
	public int TotalResources { get; init; }

	/// <summary>
	/// Number of protected resources.
	/// </summary>
	public int ProtectedResources { get; init; }

	/// <summary>
	/// Number of anonymous resources.
	/// </summary>
	public int AnonymousResources { get; init; }

	/// <summary>
	/// Overall authorization coverage percentage.
	/// </summary>
	public int OverallCoveragePercentage { get; init; }
}
