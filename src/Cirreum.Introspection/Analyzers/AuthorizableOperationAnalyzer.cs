namespace Cirreum.Introspection.Analyzers;

using Cirreum.Introspection.Modeling;
using Cirreum.Introspection.Modeling.Types;

/// <summary>
/// Analyzes authorizable resources for authorization quality issues.
/// </summary>
public class AuthorizableResourceAnalyzer(IDomainModel domainModel) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Authorizable Resources";

	private static class Issues {

		public static IssueDefinition OperationsWithNoAuthorizer(int count) {
			var recommendation = count == 1
				? "Critical: This operation will fail authorization. Create an authorizer for it or mark it as anonymous if public access is intended."
				: "Critical: These operations will fail authorization. Create an authorizer for each resource or mark them as anonymous if public access is intended.";
			return new(
				$"Found {count} resource(s) that implement IAuthorizableOperationBase but have no authorizer defined",
				recommendation);
		}

		public static IssueDefinition ResourcesWithNoProtection(int count, bool hasGlobalPolicies) {
			if (hasGlobalPolicies) {
				var recommendation = count == 1
					? "Verify this resource is covered by a registered global policy, or add an authorizer if dedicated protection is needed."
					: "Verify these resources are covered by registered global policies, or add authorizers if dedicated protection is needed.";
				return new(
					$"Found {count} IAuthorizableObject type(s) without an authorizer or attribute-based policy (may be covered by global policies)",
					recommendation);
			}

			var defaultRecommendation = count == 1
				? "Add an authorizer or apply a policy attribute to protect this resource, or convert to anonymous if public access is intended."
				: "Add an authorizer or apply a policy attribute to protect these resources, or convert to anonymous if public access is intended.";

			return new(
				$"Found {count} IAuthorizableObject type(s) without an authorizer or attribute-based policy protection",
				defaultRecommendation);
		}

		public static IssueDefinition ResourcesWithOnlyPolicyProtection(int count) => new(
			$"Found {count} IAuthorizableObject type(s) protected only by attribute-based policies (no dedicated authorizer)",
			"This is valid but consider dedicated authorizers for complex authorization logic or fine-grained control.");

		public static IssueDefinition ResourcesWithOnlyRoleChecks(int count) => new(
			$"Found {count} resource(s) with only role-based authorization (consider attribute-based policies for additional security)",
			"Role-based checks are valid. Consider attribute-based policies for cross-cutting concerns like tenant isolation or audit requirements.");

		public static IssueDefinition HighPolicyToAuthorizerRatio(int policyCount, int authorizerCount) => new(
			$"High ratio of authorization policies ({policyCount}) to resource-specific authorizers ({authorizerCount}) - consider if this is intentional",
			"Many policies relative to authorizers may indicate over-reliance on global policies. Verify this architecture is intentional.");

		public static IssueDefinition AuthorizersWithNoRules(int count) {
			var recommendation = count == 1
				? "This authorizer may be empty or use patterns the analyzer doesn't recognize. Verify it contains authorization logic."
				: "These authorizers may be empty or use patterns the analyzer doesn't recognize. Verify they contain authorization logic.";
			return new(
				$"Found {count} resource(s) with authorizers that have no extracted rules (authorizers may be empty or use unsupported patterns)",
				recommendation);
		}
	}

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var authorizableResources = domainModel.GetAuthorizableResources();
		var protectedResources = authorizableResources.Where(r => r.IsProtected).ToList();
		var unprotectedResources = authorizableResources.Where(r => !r.IsProtected).ToList();
		var policyRules = domainModel.GetPolicyRules();

		metrics[$"{MetricCategories.AuthorizableResources}ResourceCount"] = authorizableResources.Count;
		metrics[$"{MetricCategories.AuthorizableResources}ProtectedCount"] = protectedResources.Count;
		metrics[$"{MetricCategories.AuthorizableResources}UnprotectedCount"] = unprotectedResources.Count;
		metrics[$"{MetricCategories.AuthorizableResources}PolicyCount"] = policyRules.Count;
		metrics[$"{MetricCategories.AuthorizableResources}RuleCount"] = authorizableResources.Sum(r => r.Rules.Count);

		AnalyzeUnprotectedResources(issues, unprotectedResources, policyRules);
		AnalyzeRoleOnlyResources(issues, protectedResources, policyRules);
		AnalyzeAuthorizationBalance(issues, protectedResources, policyRules);
		AnalyzeEmptyValidators(issues, protectedResources);

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

	private static void AnalyzeUnprotectedResources(
		List<AnalysisIssue> issues,
		List<ResourceTypeInfo> unprotectedResources,
		IReadOnlyList<PolicyRuleTypeInfo> policyRules) {

		if (unprotectedResources.Count == 0) {
			return;
		}

		var operationResources = unprotectedResources.Where(r => r.RequiresAuthorization).ToList();
		var nonOperationResources = unprotectedResources.Where(r => !r.RequiresAuthorization).ToList();

		if (operationResources.Count > 0) {
			var issue = Issues.OperationsWithNoAuthorizer(operationResources.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: issue.Description,
				RelatedTypeNames: [.. operationResources.Select(r => r.ResourceType.FullName ?? r.ResourceType.Name)],
				Recommendation: issue.Recommendation));
		}

		if (nonOperationResources.Count > 0) {

			var withPolicyProtection = nonOperationResources
				.Where(r => HasAttributeBasedPolicyProtection(r.ResourceType, policyRules))
				.ToList();

			var withoutPolicyProtection = nonOperationResources
				.Where(r => !HasAttributeBasedPolicyProtection(r.ResourceType, policyRules))
				.ToList();

			if (withoutPolicyProtection.Count > 0) {
				var globalPolicyCount = policyRules.Count(p => !p.IsAttributeBased);
				var issue = Issues.ResourcesWithNoProtection(withoutPolicyProtection.Count, globalPolicyCount > 0);

				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: globalPolicyCount > 0 ? IssueSeverity.Info : IssueSeverity.Warning,
					Description: issue.Description,
					RelatedTypeNames: [.. withoutPolicyProtection.Select(r => r.ResourceType.FullName ?? r.ResourceType.Name)],
					Recommendation: issue.Recommendation));
			}

			if (withPolicyProtection.Count > 0) {
				var issue = Issues.ResourcesWithOnlyPolicyProtection(withPolicyProtection.Count);
				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: IssueSeverity.Info,
					Description: issue.Description,
					RelatedTypeNames: [.. withPolicyProtection.Select(r => r.ResourceType.FullName ?? r.ResourceType.Name)],
					Recommendation: issue.Recommendation));
			}
		}
	}

	private static void AnalyzeRoleOnlyResources(
		List<AnalysisIssue> issues,
		List<ResourceTypeInfo> protectedResources,
		IReadOnlyList<PolicyRuleTypeInfo> policyRules) {

		var resourcesWithOnlyRoleChecks = protectedResources
			.Where(r => r.Rules.Count > 0 &&
						r.Rules.All(rule => rule.ValidationLogic.Contains("HasRole") || rule.ValidationLogic.Contains("HasAnyRole")))
			.Where(r => !HasAttributeBasedPolicyProtection(r.ResourceType, policyRules))
			.ToList();

		if (resourcesWithOnlyRoleChecks.Count != 0) {
			var issue = Issues.ResourcesWithOnlyRoleChecks(resourcesWithOnlyRoleChecks.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [.. resourcesWithOnlyRoleChecks.Select(r => r.ResourceType.FullName ?? r.ResourceType.Name)],
				Recommendation: issue.Recommendation));
		}
	}

	private static void AnalyzeAuthorizationBalance(
		List<AnalysisIssue> issues,
		List<ResourceTypeInfo> protectedResources,
		IReadOnlyList<PolicyRuleTypeInfo> policyRules) {

		var policyCount = policyRules.Count;

		if (policyCount > protectedResources.Count * 0.5 && protectedResources.Count > 0) {
			var issue = Issues.HighPolicyToAuthorizerRatio(policyCount, protectedResources.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [],
				Recommendation: issue.Recommendation));
		}
	}

	private static void AnalyzeEmptyValidators(
		List<AnalysisIssue> issues,
		IReadOnlyList<ResourceTypeInfo> protectedResources) {

		var resourcesWithEmptyAuthorizers = protectedResources
			.Where(r => r.AuthorizerType != null && r.Rules.Count == 0)
			.ToList();

		if (resourcesWithEmptyAuthorizers.Count > 0) {
			var issue = Issues.AuthorizersWithNoRules(resourcesWithEmptyAuthorizers.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. resourcesWithEmptyAuthorizers.Select(r => r.ResourceType.FullName ?? r.ResourceType.Name)],
				Recommendation: issue.Recommendation));
		}
	}

	private static bool HasAttributeBasedPolicyProtection(Type resourceType, IReadOnlyList<PolicyRuleTypeInfo> policyRules) {
		foreach (var policy in policyRules) {
			if (!policy.IsAttributeBased || policy.TargetAttributeType is null) {
				continue;
			}
			if (resourceType.GetCustomAttributes(policy.TargetAttributeType, false).Length != 0) {
				return true;
			}
		}
		return false;
	}
}
