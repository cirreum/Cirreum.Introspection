namespace Cirreum.Introspection.Modeling.Types;

public record CombinedRuleTypeInfo(
	IReadOnlyList<AuthorizationRuleTypeInfo> OperationRules,
	IReadOnlyList<PolicyRuleTypeInfo> PolicyRules,
	int TotalRules
);
