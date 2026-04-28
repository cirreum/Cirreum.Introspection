namespace Cirreum.Introspection;

/// <summary>
/// Represents a definition for an analysis issue, containing both the description and recommendation.
/// Used by analyzers to create issues with contextual recommendations.
/// </summary>
/// <param name="Description">A detailed description of the issue.</param>
/// <param name="Recommendation">A recommendation for how to resolve the issue, or null if no recommendation is available.</param>
public record IssueDefinition(string Description, string? Recommendation);
