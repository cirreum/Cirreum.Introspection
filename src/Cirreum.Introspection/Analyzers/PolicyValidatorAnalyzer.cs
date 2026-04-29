namespace Cirreum.Introspection.Analyzers;

using Cirreum.Authorization;
using Cirreum.Introspection.Modeling;
using Cirreum.Introspection.Modeling.Types;

/// <summary>
/// Analyzes policy validators for coverage, conflicts, and configuration issues.
/// </summary>
public class PolicyValidatorAnalyzer(
	IDomainModel domainModel,
	IDomainEnvironment domainEnvironment
) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Policy Validators";

	private static class Issues {

		public static IssueDefinition DuplicateOrderValues(int order, IEnumerable<string> policyNames) {
			var names = policyNames.ToList();
			var recommendation = names.Count == 2
				? $"Assign different order values to '{names[0]}' and '{names[1]}' to ensure predictable execution."
				: "Assign unique order values to each policy validator to ensure predictable execution sequence.";

			return new(
				$"Multiple policy validators have the same order ({order}): {string.Join(", ", names)}",
				recommendation);
		}

		public static IssueDefinition LargeOrderingGap(int before, int after) => new(
			$"Large gap in policy ordering between {before} and {after}",
			"Consider consolidating order values for easier maintenance. Large gaps aren't harmful but may indicate removed policies.");

		public static IssueDefinition NoRuntimeTypeSupport(string policyName) => new(
			$"Policy '{policyName}' doesn't support any runtime types",
			"Specify supported runtime types for this policy validator, or remove it if no longer needed.");

		public static IssueDefinition NoCurrentRuntimeCoverage(DomainRuntimeType runtimeType) => new(
			$"Current runtime type '{runtimeType}' has no policy validator coverage",
			"Register policy validators that support the current runtime type to ensure policies are enforced.");

		public static IssueDefinition PolicyNotForCurrentRuntime(string policyName, DomainRuntimeType currentRuntime, DomainRuntimeType[] supportedRuntimes) => new(
			$"Policy '{policyName}' doesn't support current runtime type '{currentRuntime}' (supports: {string.Join(", ", supportedRuntimes)})",
			"This policy won't execute in the current runtime. Verify this is intentional or add support for the current runtime type.");

		public static IssueDefinition MultiplePolicesForSameAttribute(string attributeName, IEnumerable<string> policyNames) => new(
			$"Multiple policies target the same attribute type '{attributeName}': {string.Join(", ", policyNames)}",
			"Consider consolidating these policies or ensure they have different order values for predictable behavior.");

		public static IssueDefinition UnusedAttributePolicy(string policyName, string attributeName) => new(
			$"Attribute policy '{policyName}' targets attribute '{attributeName}' but no operations use this attribute",
			"Either apply this attribute to operations that need this policy, or remove the unused policy validator.");
	}

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var policyRules = domainModel.GetPolicyRules();

		metrics[$"{MetricCategories.PolicyValidation}PolicyCount"] = policyRules.Count;
		metrics[$"{MetricCategories.PolicyValidation}AttributePolicyCount"] = policyRules.Count(p => p.IsAttributeBased);
		metrics[$"{MetricCategories.PolicyValidation}GlobalPolicyCount"] = policyRules.Count(p => !p.IsAttributeBased);

		issues.AddRange(AnalyzePolicyOrdering(policyRules));
		issues.AddRange(AnalyzeRuntimeTypeCoverage(policyRules, domainEnvironment.RuntimeType));
		issues.AddRange(AnalyzePolicyOverlap(policyRules));
		issues.AddRange(AnalyzeAttributeUsage(policyRules, domainModel));

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

	private static List<AnalysisIssue> AnalyzePolicyOrdering(IReadOnlyList<PolicyRuleTypeInfo> policyRules) {
		var issues = new List<AnalysisIssue>();

		var orderGroups = policyRules.GroupBy(p => p.Order).Where(g => g.Count() > 1);
		foreach (var group in orderGroups) {
			var issue = Issues.DuplicateOrderValues(group.Key, group.Select(g => g.PolicyName));
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. group.Select(g => g.PolicyType.FullName ?? g.PolicyType.Name)],
				Recommendation: issue.Recommendation));
		}

		var orders = policyRules.Select(p => p.Order).OrderBy(o => o).ToList();
		for (var i = 1; i < orders.Count; i++) {
			if (orders[i] - orders[i - 1] > 100) {
				var issue = Issues.LargeOrderingGap(orders[i - 1], orders[i]);
				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: IssueSeverity.Info,
					Description: issue.Description,
					RelatedTypeNames: [orders[i - 1].ToString(), orders[i].ToString()],
					Recommendation: issue.Recommendation));
			}
		}

		return issues;
	}

	private static List<AnalysisIssue> AnalyzeRuntimeTypeCoverage(
		IReadOnlyList<PolicyRuleTypeInfo> policyRules,
		DomainRuntimeType currentRuntimeType) {
		var issues = new List<AnalysisIssue>();

		foreach (var policy in policyRules.Where(p => p.SupportedRuntimeTypes.Length == 0)) {
			var issue = Issues.NoRuntimeTypeSupport(policy.PolicyName);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [policy.PolicyType.FullName ?? policy.PolicyType.Name],
				Recommendation: issue.Recommendation));
		}

		var policiesForCurrentRuntime = policyRules
			.Where(p => p.SupportedRuntimeTypes.Contains(currentRuntimeType))
			.ToList();

		if (policiesForCurrentRuntime.Count == 0 && policyRules.Count > 0) {
			var issue = Issues.NoCurrentRuntimeCoverage(currentRuntimeType);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [currentRuntimeType.ToString()],
				Recommendation: issue.Recommendation));
		}

		var irrelevantPolicies = policyRules
			.Where(p => p.SupportedRuntimeTypes.Length > 0 &&
						!p.SupportedRuntimeTypes.Contains(currentRuntimeType));

		foreach (var policy in irrelevantPolicies) {
			var issue = Issues.PolicyNotForCurrentRuntime(policy.PolicyName, currentRuntimeType, policy.SupportedRuntimeTypes);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [policy.PolicyType.FullName ?? policy.PolicyType.Name],
				Recommendation: issue.Recommendation));
		}

		return issues;
	}

	private static List<AnalysisIssue> AnalyzePolicyOverlap(IReadOnlyList<PolicyRuleTypeInfo> policyRules) {
		var issues = new List<AnalysisIssue>();

		var attributePolicies = policyRules.Where(p => p.IsAttributeBased && p.TargetAttributeType is not null).ToList();

		var attributeTypes = new Dictionary<Type, List<PolicyRuleTypeInfo>>();
		foreach (var policy in attributePolicies) {
			if (!attributeTypes.TryGetValue(policy.TargetAttributeType!, out var value)) {
				value = [];
				attributeTypes[policy.TargetAttributeType!] = value;
			}
			value.Add(policy);
		}

		foreach (var kvp in attributeTypes.Where(kvp => kvp.Value.Count > 1)) {
			var issue = Issues.MultiplePolicesForSameAttribute(kvp.Key.Name, kvp.Value.Select(p => p.PolicyName));
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. kvp.Value.Select(p => p.PolicyType.FullName ?? p.PolicyType.Name)],
				Recommendation: issue.Recommendation));
		}

		return issues;
	}

	private static List<AnalysisIssue> AnalyzeAttributeUsage(
		IReadOnlyList<PolicyRuleTypeInfo> policyRules,
		IDomainModel domainModel) {

		var issues = new List<AnalysisIssue>();

		var attributePolicies = policyRules.Where(p => p.IsAttributeBased && p.TargetAttributeType is not null);
		var authorizableOperations = domainModel.GetAuthorizableOperations();

		foreach (var policy in attributePolicies) {
			var attributeType = policy.TargetAttributeType!;
			var anyOperationUsesAttribute = authorizableOperations
				.Any(r => r.OperationType.GetCustomAttributes(attributeType, false).Length != 0);

			if (!anyOperationUsesAttribute) {
				var issue = Issues.UnusedAttributePolicy(policy.PolicyName, attributeType.Name);
				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: IssueSeverity.Warning,
					Description: issue.Description,
					RelatedTypeNames: [policy.PolicyType.FullName ?? policy.PolicyType.Name, attributeType.FullName ?? attributeType.Name],
					Recommendation: issue.Recommendation));
			}
		}

		return issues;
	}
}
