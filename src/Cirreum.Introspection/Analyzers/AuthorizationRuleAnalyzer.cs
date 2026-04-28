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
				? "This authorizer references a resource that doesn't exist. Remove it or fix the resource type reference."
				: "These authorizers reference resources that don't exist. Remove them or fix the resource type references.";

			return new(
				$"Found {count} authorizer(s) with no matching resource type (orphaned authorizers)",
				recommendation);
		}

		public static IssueDefinition ResourcesWithOnlyRoleChecks(int count) => new(
			$"Found {count} resource(s) with only role-based authorization checks",
			"Role-based authorization is valid. Consider adding resource-specific checks if finer-grained control is needed.");

	}

	#endregion

	public AnalysisReport Analyze() => this.Analyze(AnalysisOptions.Default);

	public AnalysisReport Analyze(AnalysisOptions options) {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();
		var rules = domainModel.GetAuthorizationRules();
		var rulesByResource = rules.GroupBy(r => r.ResourceType).ToList();
		var rulesWithMissingResource = rules.Where(r => r.ResourceType == typeof(MissingResource)).ToList();

		// Capture metrics for this analyzer
		metrics[$"{MetricCategories.AuthorizationRules}AuthorizerCount"] = rules.Select(r => r.AuthorizerType).Distinct().Count();
		metrics[$"{MetricCategories.AuthorizationRules}ResourceCount"] = rulesByResource.Count(g => g.Key != typeof(MissingResource));
		metrics[$"{MetricCategories.AuthorizationRules}OrphanedAuthorizerCount"] = rulesWithMissingResource.Select(r => r.AuthorizerType).Distinct().Count();
		metrics[$"{MetricCategories.AuthorizationRules}RuleCount"] = rules.Count;

		// Check for authorizers with a missing/orphaned resource (critical error)
		if (rulesWithMissingResource.Count > 0) {
			var orphanedAuthorizers = rulesWithMissingResource
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

		// Check for resources with only role-based checks (informational)
		var resourcesWithOnlyRoleChecks = rulesByResource
				.Where(g => g.Key != typeof(MissingResource))
				.Where(g => g.All(r =>
					r.ValidationLogic.Contains("HasRole") ||
					r.ValidationLogic.Contains("HasAnyRole") ||
					r.ValidationLogic.Contains("HasAllRoles")))
				.ToList();

		if (resourcesWithOnlyRoleChecks.Count != 0) {
			var issue = Issues.ResourcesWithOnlyRoleChecks(resourcesWithOnlyRoleChecks.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [.. resourcesWithOnlyRoleChecks.Select(g => g.Key.FullName ?? g.Key.Name)],
				Recommendation: issue.Recommendation));
		}

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

}
