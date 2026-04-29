namespace Cirreum.Introspection.Modeling.Export;
/// <summary>
/// An operation kind within a domain (e.g., "Commands", "Queries").
/// </summary>
public record OperationKind {
	/// <summary>
	/// The name of the operation kind.
	/// </summary>
	public string Name { get; init; } = string.Empty;

	/// <summary>
	/// All operations of this kind.
	/// </summary>
	public IReadOnlyList<OperationInfo> Operations { get; init; } = [];

	/// <summary>
	/// Total operations of this kind.
	/// </summary>
	public int TotalCount { get; init; }

	/// <summary>
	/// Protected operations of this kind.
	/// </summary>
	public int ProtectedCount { get; init; }

	/// <summary>
	/// Anonymous operations of this kind.
	/// </summary>
	public int AnonymousCount { get; init; }

	/// <summary>
	/// Coverage percentage for this kind.
	/// </summary>
	public int CoveragePercentage { get; init; }
}
