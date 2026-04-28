namespace Cirreum.Introspection.Analyzers;

using Cirreum.Introspection.Modeling;

/// <summary>
/// Analyzes authorization constraint registrations.
/// </summary>
public class AuthorizationConstraintAnalyzer(IDomainModel domainModel) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Authorization Constraints";

	private static class Issues {

		public static IssueDefinition ConstraintSummary(int count) => new(
			$"{count} authorization constraint(s) registered. These run in registration order " +
			"as Stage 1, Step 1 of the authorization pipeline.",
			null);
	}

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var constraintTypes = domainModel.GetAuthorizationConstraintTypes();
		var authorizableResources = domainModel.GetAuthorizableResources();
		var authorizableCount = authorizableResources.Count(r => r.RequiresAuthorization);

		metrics[$"{MetricCategories.AuthorizationConstraints}ConstraintCount"] = constraintTypes.Count;
		metrics[$"{MetricCategories.AuthorizationConstraints}AuthorizableOperationCount"] = authorizableCount;

		if (constraintTypes.Count > 0) {
			var issue = Issues.ConstraintSummary(constraintTypes.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: [.. constraintTypes.Select(t => t.FullName ?? t.Name)],
				Recommendation: issue.Recommendation));
		}

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}
}
