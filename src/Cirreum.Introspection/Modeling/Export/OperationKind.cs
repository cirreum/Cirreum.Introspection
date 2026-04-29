namespace Cirreum.Introspection.Modeling.Export;
/// <summary>
/// A resource kind within a domain (e.g., "Commands", "Queries").
/// </summary>
public record ResourceKind {
	/// <summary>
	/// The name of the resource kind.
	/// </summary>
	public string Name { get; init; } = string.Empty;

	/// <summary>
	/// All resources of this kind.
	/// </summary>
	public IReadOnlyList<ResourceInfo> Resources { get; init; } = [];

	/// <summary>
	/// Total resources of this kind.
	/// </summary>
	public int TotalCount { get; init; }

	/// <summary>
	/// Protected resources of this kind.
	/// </summary>
	public int ProtectedCount { get; init; }

	/// <summary>
	/// Anonymous resources of this kind.
	/// </summary>
	public int AnonymousCount { get; init; }

	/// <summary>
	/// Coverage percentage for this kind.
	/// </summary>
	public int CoveragePercentage { get; init; }
}
