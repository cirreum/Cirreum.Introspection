namespace Cirreum.Introspection.Modeling.Export;
/// <summary>
/// Represents a domain operation with its authorization information.
/// This is the serializable view of a domain operation - whether protected or anonymous.
/// </summary>
public sealed record OperationInfo(
	string OperationName,
	string OperationFullName,
	string DomainBoundary,
	string OperationKind,
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
