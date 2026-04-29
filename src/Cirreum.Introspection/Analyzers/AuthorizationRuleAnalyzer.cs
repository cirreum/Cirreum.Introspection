namespace Cirreum.Introspection.Analyzers;

using Cirreum.Introspection.Modeling;

/// <summary>
/// Analyzes authorization rules for security implications and consistency.
/// </summary>
public class AuthorizationRuleAnalyzer(IDomainModel domainModel) : IDomainAnalyzerWithOptions {

	public const string AnalyzerCategory = "Authorization Rules";

	#region Issue Definitions

	private static class Issues {

		public static IssueDefinition OrphanedAuthorizers(int count) {
			var recommendation = count == 1
				? "This authorizer references a operation that doesn't exist. Remove it or fix the operation type reference."
				: "These authorizers reference operations that don't exist. Remove them or fix the operation type references.";

			return new(
				$"Found {count} authorizer(s) with no matching operation type (orphaned authorizers)",
				recommendation);
		}

		public static IssueDefinition OperationsWithOnlyRoleChecks(int count) => new(
			$"Found {count} operation(s) with only role-based authorization checks",
			"Role-based authorization is valid. Consider adding operation-specific checks if finer-grained control is needed.");

	}

	#endregion

	public AnalysisReport Analyze() => this.Analyze(AnalysisOptions.Default);

	public AnalysisReport Analyze(AnalysisOptions options) {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();
		var rules = domainModel.GetAuthorizationRules();
		var rulesByOperation = rules.GroupBy(r => r.OperationType).ToList();
		var rulesWithMissingOperation = rules.Where(r => r.OperationType == typeof(MissingResource)).ToList();

		// Capture metrics for this analyzer
		metrics[$"{MetricCategories.AuthorizationRules}AuthorizerCount"] = rules.Select(r => r.AuthorizerType).Distinct().Count();
		metrics[$"{MetricCategories.AuthorizationRules}OperationCount"] = rulesByOperation.Count(g => g.Key != typeof(MissingResource));
		metrics[$"{MetricCategories.AuthorizationRules}OrphanedAuthorizerCount"] = rulesWithMissingOperation.Select(r => r.AuthorizerType).Distinct().Count();
		metrics[$"{MetricCategories.AuthorizationRules}RuleCount"] = rules.Count;

		// Check for authorizers with a missing/orphaned operation (critical error)
		if (rulesWithMissingOperation.Count > 0) {
			var orphanedAuthorizers = rulesWithMissingOperation
				.Select(r => r.AuthorizerType)
				.Distinct()
				.ToList();
			var issue = Issues.OrphanedAuthorizers(orphanedAuthorizers.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: issue.Description,
				RelatedTypeNames: [.. orphanedAuthorizers.Select(t => t.FullName ?? t.Name)],
				Recommendation: issue.Recommendation));
		}

		// Check for operations with only role-based checks (informational)
		var operationsWithOnlyRoleChecks = rulesByOperation
				.Where(g => g.Key != typeof(MissingResource))
				.Where(g => g.All(r =>
					r.ValidationLogic.Contains("HasRole") ||
					r.ValidationLogic.Contains("HasAnyRole") ||
					r.ValidationLogic.Contains("HasAllRoles")))
				.ToList();

		if (operationsWithOnlyRoleChecks.Count != 0) {
			var issue = Issues.OperationsWithOnlyRoleChecks(operationsWithOnlyRoleChecks.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [.. operationsWithOnlyRoleChecks.Select(g => g.Key.FullName ?? g.Key.Name)],
				Recommendation: issue.Recommendation));
		}

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

}
