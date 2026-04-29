namespace Cirreum.Introspection.Modeling.Types;

using Cirreum.Authorization;
using Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Internal type used during analysis that includes CLR Type references.
/// Use ResourceInfo for serialization/public API.
/// </summary>
public sealed record ResourceTypeInfo(
	Type ResourceType,
	string DomainBoundary,
	string ResourceKind,
	bool IsAnonymous,
	bool IsCacheableQuery,
	bool IsProtected,
	bool RequiresAuthorization,
	Type? AuthorizerType,
	IReadOnlyList<AuthorizationRuleTypeInfo> Rules,
	bool IsGranted = false,
	string? GrantDomain = null,
	string? GrantableKind = null,
	bool IsSelfScoped = false,
	PermissionSet Permissions = null!
) {
	/// <summary>
	/// Converts to the serializable ResourceInfo type.
	/// </summary>
	public ResourceInfo ToResourceInfo() => new(
		ResourceName: this.ResourceType.Name,
		ResourceFullName: this.ResourceType.FullName ?? this.ResourceType.Name,
		DomainBoundary: this.DomainBoundary,
		ResourceKind: this.ResourceKind,
		IsAnonymous: this.IsAnonymous,
		IsCacheableQuery: this.IsCacheableQuery,
		IsProtected: this.IsProtected,
		RequiresAuthorization: this.RequiresAuthorization,
		AuthorizerName: this.AuthorizerType?.Name,
		AuthorizerFullName: this.AuthorizerType?.FullName,
		Rules: [.. this.Rules.Select(r => r.ToRuleInfo())],
		IsGranted: this.IsGranted,
		GrantDomain: this.GrantDomain,
		GrantableKind: this.GrantableKind,
		IsSelfScoped: this.IsSelfScoped,
		Permissions: [.. this.Permissions.Select(p => p.ToString())]
	);
}
