namespace Cirreum.Introspection;

/// <summary>
/// Represents a single issue found during analysis.
/// </summary>
/// <param name="Category">The category of the issue (e.g., "Circular Inheritance", "Orphaned Role").</param>
/// <param name="Severity">The severity level of the issue.</param>
/// <param name="Description">A detailed description of the issue.</param>
/// <param name="RelatedTypeNames">The full names of any types (roles, permissions) related to this issue.</param>
/// <param name="Recommendation">A recommendation for how to resolve the issue, or null if no recommendation is available.</param>
public record AnalysisIssue(
	string Category,
	IssueSeverity Severity,
	string Description,
	IReadOnlyList<string> RelatedTypeNames,
	string? Recommendation = null);
