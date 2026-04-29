namespace Cirreum.Introspection;

/// <summary>
/// Standard metric category prefixes for consistent naming.
/// </summary>
public static class MetricCategories {

	public const string AnonymousOperations = "AnonymousOperations.";
	public const string AuthorizableOperations = "AuthorizableOperations.";
	public const string AuthorizationConstraints = "AuthorizationConstraints.";
	public const string AuthorizationRules = "AuthorizationRules.";
	public const string GrantedOperations = "GrantedOperations.";
	public const string ObjectLevelAcl = "ObjectLevelACL.";
	public const string PolicyValidation = "PolicyValidation.";
	public const string RoleHierarchy = "RoleHierarchy.";

	/// <summary>
	/// Returns a user-friendly display name for the category associated with the specified metric key.
	/// </summary>
	/// <param name="metricKey">The metric key for which to retrieve the category display name. Must not be null or empty.</param>
	/// <returns>A string containing the display name of the metric category. Returns "Anonymous Operations", "Authorization Rules",
	/// "Policy Validation", "Protected Operations", or "Role Hierarchy" if the metric key matches a known category;
	/// otherwise, returns "General".</returns>
	public static string GetMetricCategoryDisplayName(string metricKey) {

		if (metricKey.StartsWith(AnonymousOperations)) {
			return "Anonymous Operations";
		}

		if (metricKey.StartsWith(AuthorizableOperations)) {
			return "Authorizable Operations";
		}

		if (metricKey.StartsWith(AuthorizationConstraints)) {
			return "Authorization Constraints";
		}

		if (metricKey.StartsWith(AuthorizationRules)) {
			return "Authorization Rules";
		}

		if (metricKey.StartsWith(GrantedOperations)) {
			return "Granted Operations";
		}

		if (metricKey.StartsWith(ObjectLevelAcl)) {
			return "Object-Level ACL";
		}

		if (metricKey.StartsWith(PolicyValidation)) {
			return "Policy Validation";
		}

		if (metricKey.StartsWith(RoleHierarchy)) {
			return "Role Hierarchy";
		}

		return "General";

	}

	/// <summary>
	/// Extracts the metric name from a fully qualified metric key.
	/// </summary>
	/// <param name="metricKey">The fully qualified metric key, typically containing one or more period ('.') separators.</param>
	/// <returns>The substring after the last period in the metric key. If the key does not contain a period, returns the original
	/// key.</returns>
	public static string GetMetricName(string metricKey) {
		var lastDot = metricKey.LastIndexOf('.');
		return lastDot >= 0 ? metricKey[(lastDot + 1)..] : metricKey;
	}

}
