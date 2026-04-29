namespace Cirreum.Introspection.Analyzers;

using Cirreum.Introspection.Modeling;

/// <summary>
/// Analyzes anonymous operations and detects security gaps.
/// </summary>
public class AnonymousOperationAnalyzer(IDomainModel domainModel) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Anonymous Operations";

	private static readonly string[] SuspiciousWords = [
		"delete", "remove", "admin", "update", "modify", "create", "getall",
		"grant", "revoke", "permission", "role", "user", "account",
		"password", "secret", "key", "token", "auth", "logout", "signout"
	];

	private static class Issues {

		public static IssueDefinition AnonymousOperationsFound(int count, int maxShown) {
			var description = count > maxShown
				? $"Found {count} anonymous operations (don't require authorization). Showing first {maxShown}."
				: $"Found {count} anonymous operation(s) (don't require authorization).";

			var recommendation = count == 1
				? "Review this operation to confirm it should be publicly accessible without authentication."
				: "Review these operations to confirm they should be publicly accessible without authentication.";

			return new(description, recommendation);
		}

		public static IssueDefinition SuspiciousAnonymousOperations(int count) {
			var recommendation = count == 1
				? "This operation has a name suggesting it may need protection. Review it and add authorization if it performs sensitive actions."
				: "These operations have names suggesting they may need protection (Delete, Admin, Update, etc.). Review each one and add authorization if they perform sensitive actions.";

			return new(
				$"Found {count} anonymous operation(s) with sensitive-sounding names (Delete, Admin, Update, etc.)",
				recommendation);
		}
	}

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var anonymousOperations = domainModel.GetAnonymousOperations();

		var suspiciousAnonymous = anonymousOperations
			.Where(r => IsPotentiallySecuritySensitive(r.OperationType.Name))
			.ToList();

		metrics[$"{MetricCategories.AnonymousOperations}AnonymousOperationCount"] = anonymousOperations.Count;
		metrics[$"{MetricCategories.AnonymousOperations}SuspiciousOperationCount"] = suspiciousAnonymous.Count;

		if (anonymousOperations.Count > 0) {
			const int maxTypesToInclude = 5;

			var typeSample = anonymousOperations
				.Take(maxTypesToInclude)
				.Select(r => r.OperationType.FullName ?? r.OperationType.Name)
				.ToList();

			var issue = Issues.AnonymousOperationsFound(anonymousOperations.Count, maxTypesToInclude);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: issue.Description,
				RelatedTypeNames: typeSample,
				Recommendation: issue.Recommendation));
		}

		if (suspiciousAnonymous.Count > 0) {
			var issue = Issues.SuspiciousAnonymousOperations(suspiciousAnonymous.Count);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. suspiciousAnonymous.Select(r => r.OperationType.FullName ?? r.OperationType.Name)],
				Recommendation: issue.Recommendation));
		}

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

	private static bool IsPotentiallySecuritySensitive(string typeName) {
		var lowerName = typeName.ToLowerInvariant();
		return SuspiciousWords.Any(word => lowerName.Contains(word));
	}
}
