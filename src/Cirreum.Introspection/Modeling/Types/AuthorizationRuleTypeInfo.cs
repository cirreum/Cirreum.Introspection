namespace Cirreum.Introspection.Modeling.Types;

using Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Internal type used during analysis that includes CLR Type references.
/// Use AuthorizationRuleInfo for serialization/public API.
/// </summary>
public sealed record AuthorizationRuleTypeInfo(
	Type ResourceType,
	Type AuthorizerType,
	string PropertyPath,
	string ValidationLogic,
	string Message
) {
	/// <summary>
	/// Converts to the serializable AuthorizationRuleInfo type.
	/// </summary>
	public AuthorizationRuleInfo ToRuleInfo() => new(
		ResourceTypeName: this.ResourceType.Name,
		ResourceTypeFullName: this.ResourceType.FullName ?? this.ResourceType.Name,
		AuthorizerTypeName: this.AuthorizerType.Name,
		AuthorizerTypeFullName: this.AuthorizerType.FullName ?? this.AuthorizerType.Name,
		PropertyPath: this.PropertyPath,
		ValidationLogic: this.ValidationLogic,
		Message: this.Message
	);
}
