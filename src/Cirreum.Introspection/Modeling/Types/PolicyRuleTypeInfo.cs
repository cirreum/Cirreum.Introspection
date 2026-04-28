namespace Cirreum.Introspection.Modeling.Types;

using Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Internal type used during analysis that includes CLR Type references.
/// Use PolicyRuleInfo for serialization/public API.
/// </summary>
public sealed record PolicyRuleTypeInfo(
	string PolicyName,
	Type PolicyType,
	int Order,
	DomainRuntimeType[] SupportedRuntimeTypes,
	bool IsAttributeBased,
	Type? TargetAttributeType,
	string Description
) {

	/// <summary>
	/// Converts to the serializable PolicyRuleInfo type.
	/// </summary>
	public PolicyRuleInfo ToRuleInfo() => new(
		PolicyName: this.PolicyName,
		PolicyTypeName: this.PolicyType.Name,
		PolicyTypeFullName: this.PolicyType.FullName ?? this.PolicyType.Name,
		Order: this.Order,
		SupportedRuntimeTypes: this.SupportedRuntimeTypes,
		IsAttributeBased: this.IsAttributeBased,
		TargetAttributeName: this.TargetAttributeType?.Name,
		TargetAttributeFullName: this.TargetAttributeType?.FullName,
		Description: this.Description
	);

}
