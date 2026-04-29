namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Represents detailed information about an authorization rule.
/// This is the serializable view for visualization or inspection.
/// </summary>
public sealed record AuthorizationRuleInfo(
	string OperationTypeName,
	string OperationTypeFullName,
	string AuthorizerTypeName,
	string AuthorizerTypeFullName,
	string PropertyPath,
	string ValidationLogic,
	string Message
);
