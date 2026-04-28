namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Serializable summary of a single grant domain — its namespace, the distinct permissions
/// declared across all granted resources in that domain, and the resource count.
/// </summary>
/// <remarks>
/// Built by <see cref="DomainSnapshot.Capture"/> from the <see cref="DomainCatalog"/>.
/// Admin UIs use this to populate permission-picker dropdowns without reflection.
/// </remarks>
public sealed record GrantDomainInfo(
	string Domain,
	IReadOnlyList<string> Permissions,
	int GrantedResourceCount
);
