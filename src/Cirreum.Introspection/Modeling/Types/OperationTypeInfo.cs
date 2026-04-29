namespace Cirreum.Introspection.Modeling.Types;

using Cirreum.Authorization;
using Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Internal type used during analysis that includes CLR Type references.
/// Use OperationInfo for serialization/public API.
/// </summary>
public sealed record OperationTypeInfo(
	Type OperationType,
	string DomainBoundary,
	string OperationKind,
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
	/// Converts to the serializable OperationInfo type.
	/// </summary>
	public OperationInfo ToOperationInfo() => new(
		OperationName: this.OperationType.Name,
		OperationFullName: this.OperationType.FullName ?? this.OperationType.Name,
		DomainBoundary: this.DomainBoundary,
		OperationKind: this.OperationKind,
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
