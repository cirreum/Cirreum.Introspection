namespace Cirreum.Introspection.Modeling.Export;
/// <summary>
/// Represents a domain resource with its authorization information.
/// This is the serializable view of a resource - whether protected or anonymous.
/// </summary>
public sealed record ResourceInfo(
	string ResourceName,
	string ResourceFullName,
	string DomainBoundary,
	string ResourceKind,
	bool IsAnonymous,
	bool IsCacheableQuery,
	bool IsProtected,
	bool RequiresAuthorization,
	string? AuthorizerName,
	string? AuthorizerFullName,
	IReadOnlyList<AuthorizationRuleInfo> Rules,
	bool IsGranted = false,
	string? GrantDomain = null,
	string? GrantableKind = null,
	bool IsSelfScoped = false,
	IReadOnlyList<string> Permissions = null!
);
