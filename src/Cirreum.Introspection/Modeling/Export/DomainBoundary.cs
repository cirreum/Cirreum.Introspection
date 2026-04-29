namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// A domain boundary (e.g., "Customers") containing the domain operations (aka Commands/Queries).
/// </summary>
public record DomainBoundary {

	/// <summary>
	/// The name of the domain boundary.
	/// </summary>
	public string Name { get; init; } = string.Empty;

	/// <summary>
	/// Operation kinds within this domain (e.g., "Commands", "Queries").
	/// </summary>
	public IReadOnlyDictionary<string, OperationKind> Kinds { get; init; } = new Dictionary<string, OperationKind>();

	/// <summary>
	/// Total operations in this domain.
	/// </summary>
	public int TotalCount { get; init; }

	/// <summary>
	/// Protected operations in this domain.
	/// </summary>
	public int ProtectedCount { get; init; }

	/// <summary>
	/// Anonymous operations in this domain.
	/// </summary>
	public int AnonymousCount { get; init; }

	/// <summary>
	/// Coverage percentage for this domain.
	/// </summary>
	public int CoveragePercentage { get; init; }

}
