namespace Cirreum.Introspection.Analyzers;

using Cirreum.Introspection.Modeling;
using Cirreum.Introspection.Modeling.Types;

/// <summary>
/// Analyzes authorizable operations for authorization quality issues.
/// </summary>
public class AuthorizableOperationAnalyzer(IDomainModel domainModel) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Authorizable Operations";

	private static class Issues {

		public static IssueDefinition OperationsWithNoAuthorizer(int count) {
			var recommendation = count == 1
				? "Critical: This operation will fail authorization. Create an authorizer for it or mark it as anonymous if public access is intended."
				: "Critical: These operations will fail authorization. Create an authorizer for each operation or mark them as anonymous if public access is intended.";
			return new(
				$"Found {count} operation(s) that implement IAuthorizableOperationBase but have no authorizer defined",
				recommendation);
		}

		public static IssueDefinition OperationsWithNoProtection(int count, bool hasGlobalPolicies) {
			if (hasGlobalPolicies) {
				var recommendation = count == 1
					? "Verify this operation is covered by a registered global policy, or add an authorizer if dedicated protection is needed."
					: "Verify these operations are covered by registered global policies, or add authorizers if dedicated protection is needed.";
				return new(
					$"Found {count} IAuthorizableObject type(s) without an authorizer or attribute-based policy (may be covered by global policies)",
					recommendation);
			}

			var defaultRecommendation = count == 1
				? "Add an authorizer or apply a policy attribute to protect this operation, or convert to anonymous if public access is intended."
				: "Add an authorizer or apply a policy attribute to protect these operations, or convert to anonymous if public access is intended.";

			return new(
				$"Found {count} IAuthorizableObject type(s) without an authorizer or attribute-based policy protection",
				defaultRecommendation);
		}

		public static IssueDefinition OperationsWithOnlyPolicyProtection(int count) => new(
			$"Found {count} IAuthorizableObject type(s) protected only by attribute-based policies (no dedicated authorizer)",
			"This is valid but consider dedicated authorizers for complex authorization logic or fine-grained control.");

		public static IssueDefinition OperationsWithOnlyRoleChecks(int count) => new(
			$"Found {count} operation(s) with only role-based authorization (consider attribute-based policies for additional security)",
			"Role-based checks are valid. Consider attribute-based policies for cross-cutting concerns like tenant isolation or audit requirements.");

		public static IssueDefinition HighPolicyToAuthorizerRatio(int policyCount, int authorizerCount) => new(
			$"High ratio of authorization policies ({policyCount}) to operation-specific authorizers ({authorizerCount}) - consider if this is intentional",
			"Many policies relative to authorizers may indicate over-reliance on global policies. Verify this architecture is intentional.");

		public static IssueDefinition AuthorizersWithNoRules(int count) {
			var recommendation = count == 1
				? "This authorizer may be empty or use patterns the analyzer doesn't recognize. Verify it contains authorization logic."
				: "These authorizers may be empty or use patterns the analyzer doesn't recognize. Verify they contain authorization logic.";
			return new(
				$"Found {count} operation(s) with authorizers that have no extracted rules (authorizers may be empty or use unsupported patterns)",
				recommendation);
		}
	}

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var authorizableOperations = domainModel.GetAuthorizableOperations();
		var protectedOperations = authorizableOperations.Where(r => r.IsProtected).ToList();
		var unprotectedOperations = authorizableOperations.Where(r => !r.IsProtected).ToList();
		var policyRules = domainModel.GetPolicyRules();

		metrics[$"{MetricCategories.AuthorizableOperations}OperationCount"] = authorizableOperations.Count;
		metrics[$"{MetricCategories.AuthorizableOperations}ProtectedCount"] = protectedOperations.Count;
		metrics[$"{MetricCategories.AuthorizableOperations}UnprotectedCount"] = unprotectedOperations.Count;
		metrics[$"{MetricCategories.AuthorizableOperations}PolicyCount"] = policyRules.Count;
		metrics[$"{MetricCategories.AuthorizableOperations}RuleCount"] = authorizableOperations.Sum(r => r.Rules.Count);

		AnalyzeUnprotectedOperations(issues, unprotectedOperations, policyRules);
		AnalyzeRoleOnlyOperations(issues, protectedOperations, policyRules);
		AnalyzeAuthorizationBalance(issues, protectedOperations, policyRules);
		AnalyzeEmptyValidators(issues, protectedOperations);

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

	private static void AnalyzeUnprotectedOperations(
		List<AnalysisIssue> issues,
		List<OperationTypeInfo> unprotectedOperations,
		IReadOnlyList<PolicyRuleTypeInfo> policyRules) {

		if (unprotectedOperations.Count == 0) {
			return;
		}

		var operations = unprotectedOperations.Where(r => r.RequiresAuthorization).ToList();
		var nonOperations = unprotectedOperations.Where(r => !r.RequiresAuthorization).ToList();

		if (operations.Count > 0) {
			var issue = Issues.OperationsWithNoAuthorizer(operations.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: issue.Description,
				RelatedTypeNames: [.. operations.Select(r => r.OperationType.FullName ?? r.OperationType.Name)],
				Recommendation: issue.Recommendation));
		}

		if (nonOperations.Count > 0) {

			var withPolicyProtection = nonOperations
				.Where(r => HasAttributeBasedPolicyProtection(r.OperationType, policyRules))
				.ToList();

			var withoutPolicyProtection = nonOperations
				.Where(r => !HasAttributeBasedPolicyProtection(r.OperationType, policyRules))
				.ToList();

			if (withoutPolicyProtection.Count > 0) {
				var globalPolicyCount = policyRules.Count(p => !p.IsAttributeBased);
				var issue = Issues.OperationsWithNoProtection(withoutPolicyProtection.Count, globalPolicyCount > 0);

				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: globalPolicyCount > 0 ? IssueSeverity.Info : IssueSeverity.Warning,
					Description: issue.Description,
					RelatedTypeNames: [.. withoutPolicyProtection.Select(r => r.OperationType.FullName ?? r.OperationType.Name)],
					Recommendation: issue.Recommendation));
			}

			if (withPolicyProtection.Count > 0) {
				var issue = Issues.OperationsWithOnlyPolicyProtection(withPolicyProtection.Count);
				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: IssueSeverity.Info,
					Description: issue.Description,
					RelatedTypeNames: [.. withPolicyProtection.Select(r => r.OperationType.FullName ?? r.OperationType.Name)],
					Recommendation: issue.Recommendation));
			}
		}
	}

	private static void AnalyzeRoleOnlyOperations(
		List<AnalysisIssue> issues,
		List<OperationTypeInfo> protectedOperations,
		IReadOnlyList<PolicyRuleTypeInfo> policyRules) {

		var operationsWithOnlyRoleChecks = protectedOperations
			.Where(r => r.Rules.Count > 0 &&
						r.Rules.All(rule => rule.ValidationLogic.Contains("HasRole") || rule.ValidationLogic.Contains("HasAnyRole")))
			.Where(r => !HasAttributeBasedPolicyProtection(r.OperationType, policyRules))
			.ToList();

		if (operationsWithOnlyRoleChecks.Count != 0) {
			var issue = Issues.OperationsWithOnlyRoleChecks(operationsWithOnlyRoleChecks.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [.. operationsWithOnlyRoleChecks.Select(r => r.OperationType.FullName ?? r.OperationType.Name)],
				Recommendation: issue.Recommendation));
		}
	}

	private static void AnalyzeAuthorizationBalance(
		List<AnalysisIssue> issues,
		List<OperationTypeInfo> protectedOperations,
		IReadOnlyList<PolicyRuleTypeInfo> policyRules) {

		var policyCount = policyRules.Count;

		if (policyCount > protectedOperations.Count * 0.5 && protectedOperations.Count > 0) {
			var issue = Issues.HighPolicyToAuthorizerRatio(policyCount, protectedOperations.Count);
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
		IReadOnlyList<OperationTypeInfo> protectedOperations) {

		var operationsWithEmptyAuthorizers = protectedOperations
			.Where(r => r.AuthorizerType != null && r.Rules.Count == 0)
			.ToList();

		if (operationsWithEmptyAuthorizers.Count > 0) {
			var issue = Issues.AuthorizersWithNoRules(operationsWithEmptyAuthorizers.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. operationsWithEmptyAuthorizers.Select(r => r.OperationType.FullName ?? r.OperationType.Name)],
				Recommendation: issue.Recommendation));
		}
	}

	private static bool HasAttributeBasedPolicyProtection(Type operationType, IReadOnlyList<PolicyRuleTypeInfo> policyRules) {
		foreach (var policy in policyRules) {
			if (!policy.IsAttributeBased || policy.TargetAttributeType is null) {
				continue;
			}
			if (operationType.GetCustomAttributes(policy.TargetAttributeType, false).Length != 0) {
				return true;
			}
		}
		return false;
	}
}
