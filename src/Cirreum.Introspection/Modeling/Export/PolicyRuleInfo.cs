namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Represents serializable metadata about a policy rule for visualization or inspection.
/// This is the public API type - use PolicyRuleTypeInfo internally for analysis with CLR Type references.
/// </summary>
public sealed record PolicyRuleInfo(
	string PolicyName,
	string PolicyTypeName,
	string PolicyTypeFullName,
	int Order,
	DomainRuntimeType[] SupportedRuntimeTypes,
	bool IsAttributeBased,
	string? TargetAttributeName,
	string? TargetAttributeFullName,
	string Description
);
