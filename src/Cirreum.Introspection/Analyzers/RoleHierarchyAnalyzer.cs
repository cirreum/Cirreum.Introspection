namespace Cirreum.Introspection.Analyzers;

using Cirreum.Authorization;
using System.Collections.Immutable;

/// <summary>
/// Analyzes role hierarchy for structural issues, inheritance patterns, and security implications.
/// </summary>
public class RoleHierarchyAnalyzer(
	IAuthorizationRoleRegistry registry
) : IDomainAnalyzerWithOptions {

	public const string AnalyzerCategory = "Role Hierarchy";

	#region Issue Definitions

	private static class Issues {

		public static IssueDefinition HierarchyTooDeep(int actual, int max) => new(
			$"Role hierarchy depth of {actual} exceeds recommended maximum of {max}",
			"Flatten the role hierarchy to reduce complexity. Deep hierarchies can impact performance and make authorization harder to reason about.");

		public static IssueDefinition IsolatedRoles(List<Role> isolated) {
			var recommendation = isolated.Count == 1
				? $"Connect '{isolated[0]}' to the main hierarchy or remove it if no longer needed."
				: "Connect these isolated roles to the main hierarchy or remove them if no longer needed. Isolated roles may indicate incomplete configuration.";

			return new(
				$"Found {isolated.Count} isolated role(s) not connected to main hierarchy",
				recommendation);
		}

		public static IssueDefinition CircularReference(List<Role> cycle) {
			var recommendation = cycle.Count == 2
				? "Remove the direct circular inheritance between these two roles."
				: "Review the inheritance chain and break the cycle at the most logical point. Circular references can cause infinite loops and unpredictable authorization behavior.";

			return new(
				$"Circular reference detected in role hierarchy: {string.Join(" -> ", cycle)}",
				recommendation);
		}

	}

	#endregion

	public AnalysisReport Analyze() => this.Analyze(AnalysisOptions.Default);

	public AnalysisReport Analyze(AnalysisOptions options) {
		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		// Analyze basic hierarchy structure
		var (structureIssues, structureMetrics) = AnalyzeHierarchyStructure(registry, options);
		issues.AddRange(structureIssues);
		foreach (var metric in structureMetrics) {
			metrics[metric.Key] = metric.Value;
		}

		// Find possible circular references
		var circularIssues = AnalyzeCircularReferences(registry);
		issues.AddRange(circularIssues);

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);
	}

	private static (List<AnalysisIssue>, Dictionary<string, int>) AnalyzeHierarchyStructure(
		IAuthorizationRoleRegistry registry,
		AnalysisOptions options) {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();
		var allRoles = registry.GetRegisteredRoles();

		// Find top-level roles (not inherited by any other role)
		var topRoles = allRoles.Where(r => registry.GetInheritingRoles(r).Count == 0).ToList();
		metrics[$"{MetricCategories.RoleHierarchy}TopLevelRolesCount"] = topRoles.Count;

		// Find leaf roles (don't inherit from any other role)
		var leafRoles = allRoles.Where(r => registry.GetInheritedRoles(r).Count == 0).ToList();
		metrics[$"{MetricCategories.RoleHierarchy}LeafRolesCount"] = leafRoles.Count;

		// Calculate hierarchy depth
		var (maxDepth, longestPath) = FindLongestPath(registry);
		metrics[$"{MetricCategories.RoleHierarchy}MaxDepth"] = maxDepth;

		if (maxDepth > options.MaxHierarchyDepth) {
			var issue = Issues.HierarchyTooDeep(maxDepth, options.MaxHierarchyDepth);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. longestPath.Select(r => r.ToString())],
				Recommendation: issue.Recommendation));
		}

		// Detect isolated roles (not part of main hierarchy)
		var isolatedRoles = FindIsolatedRoles(registry, allRoles);
		if (isolatedRoles.Count > 0) {
			var issue = Issues.IsolatedRoles(isolatedRoles);
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: issue.Description,
				RelatedTypeNames: [.. isolatedRoles.Select(r => r.ToString())],
				Recommendation: issue.Recommendation));
		}

		return (issues, metrics);
	}

	private static List<AnalysisIssue> AnalyzeCircularReferences(IAuthorizationRoleRegistry registry) {
		var issues = new List<AnalysisIssue>();
		var allRoles = registry.GetRegisteredRoles();

		foreach (var role in allRoles) {
			var visited = new HashSet<Role>();
			var path = new Stack<Role>();

			if (HasCycle(registry, role, visited, path)) {
				var cycle = path.Reverse().ToList();
				var issue = Issues.CircularReference(cycle);
				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: IssueSeverity.Error,
					Description: issue.Description,
					RelatedTypeNames: [.. cycle.Select(r => r.ToString())],
					Recommendation: issue.Recommendation));
			}
		}

		return issues;
	}

	private static bool HasCycle(
		IAuthorizationRoleRegistry registry,
		Role current,
		HashSet<Role> visited,
		Stack<Role> path) {

		if (path.Contains(current)) {
			// Found a cycle
			while (path.Peek() != current) {
				path.Pop();
			}
			return true;
		}

		if (visited.Contains(current)) {
			return false;
		}

		visited.Add(current);
		path.Push(current);

		foreach (var child in registry.GetInheritedRoles(current)) {
			if (HasCycle(registry, child, visited, path)) {
				return true;
			}
		}

		path.Pop();
		return false;
	}

	//private static List<AnalysisIssue> AnalyzeSecurityBoundaries(IAuthorizationRoleRegistry registry) {
	//	var issues = new List<AnalysisIssue>();
	//	var appRoles = registry.GetRegisteredRoles().Where(r => r.IsApplicationRole).ToList();

	//	// Check that system role only inherits from admin
	//	var systemRole = ApplicationRoles.AppSystemRole;
	//	var systemInherits = registry.GetInheritedRoles(systemRole);

	//	if (systemInherits.Count > 1 || (systemInherits.Count == 1 && !systemInherits.Contains(ApplicationRoles.AppAdminRole))) {
	//		issues.Add(new AnalysisIssue(
	//			Category: AnalyzerCategory,
	//			Severity: IssueSeverity.Error,
	//			Description: $"Security boundary violation: System role should only inherit from Admin role",
	//			RelatedObjects: [systemRole, .. systemInherits.Cast<object>()]));
	//	}

	//	// Check that admin role only inherits from manager and agent
	//	var adminRole = ApplicationRoles.AppAdminRole;
	//	var adminInherits = registry.GetInheritedRoles(adminRole);
	//	var expectedAdminInherits = new HashSet<Role> {
	//		ApplicationRoles.AppManagerRole,
	//		ApplicationRoles.AppAgentRole
	//	};

	//	if (!adminInherits.SetEquals(expectedAdminInherits)) {
	//		var unexpected = adminInherits.Except(expectedAdminInherits).ToList();
	//		var missing = expectedAdminInherits.Except(adminInherits).ToList();

	//		if (unexpected.Count > 0) {
	//			issues.Add(new AnalysisIssue(
	//				Category: AnalyzerCategory,
	//				Severity: IssueSeverity.Warning,
	//				Description: $"Admin role has unexpected inheritance from: {string.Join(", ", unexpected)}",
	//				RelatedObjects: [.. unexpected.Cast<object>()]));
	//		}

	//		if (missing.Count > 0) {
	//			issues.Add(new AnalysisIssue(
	//				Category: AnalyzerCategory,
	//				Severity: IssueSeverity.Warning,
	//				Description: $"Admin role is missing expected inheritance from: {string.Join(", ", missing)}",
	//				RelatedObjects: [.. missing.Cast<object>()]));
	//		}
	//	}

	//	return issues;
	//}

	//private static List<AnalysisIssue> AnalyzeInvalidInheritance(IAuthorizationRoleRegistry registry) {
	//	var issues = new List<AnalysisIssue>();
	//	var allRoles = registry.GetRegisteredRoles();

	//	foreach (var role in allRoles) {
	//		var inheritedRoles = registry.GetInheritedRoles(role);

	//		// Check for custom roles inheriting from app:system or app:admin
	//		if (!role.IsApplicationRole ||
	//			(role != ApplicationRoles.AppSystemRole && role != ApplicationRoles.AppAdminRole)) {

	//			var restrictedInheritance = inheritedRoles.Where(r =>
	//				r == ApplicationRoles.AppSystemRole ||
	//				r == ApplicationRoles.AppAdminRole).ToList();

	//			if (restrictedInheritance.Count > 0) {
	//				issues.Add(new AnalysisIssue(
	//					Category: AnalyzerCategory,
	//					Severity: IssueSeverity.Error,
	//					Description: $"Security violation: Role '{role}' inherits from restricted role(s): {string.Join(", ", restrictedInheritance)}",
	//					RelatedObjects: [role, .. restrictedInheritance.Cast<object>()]));
	//			}
	//		}

	//		// Check if app namespace roles inherit from custom namespace roles
	//		if (role.IsApplicationRole) {
	//			var customNamespaceInheritance = inheritedRoles.Where(r => !r.IsApplicationRole).ToList();

	//			if (customNamespaceInheritance.Count > 0) {
	//				issues.Add(new AnalysisIssue(
	//					Category: AnalyzerCategory,
	//					Severity: IssueSeverity.Warning,
	//					Description: $"Application role '{role}' inherits from custom namespace role(s): {string.Join(", ", customNamespaceInheritance)}",
	//					RelatedObjects: [role, .. customNamespaceInheritance.Cast<object>()]));
	//			}
	//		}
	//	}

	//	return issues;
	//}

	private static (int Depth, List<Role> Path) FindLongestPath(IAuthorizationRoleRegistry registry) {
		var allRoles = registry.GetRegisteredRoles();
		var maxDepth = 0;
		var longestPath = new List<Role>();

		foreach (var role in allRoles) {
			var (depth, path) = FindLongestPathFromRole(registry, role);
			if (depth > maxDepth) {
				maxDepth = depth;
				longestPath = path;
			}
		}

		return (maxDepth, longestPath);
	}

	private static (int Depth, List<Role> Path) FindLongestPathFromRole(
		IAuthorizationRoleRegistry registry,
		Role role,
		HashSet<Role>? visited = null) {

		visited ??= [];

		if (visited.Contains(role)) {
			return (0, new List<Role>());
		}

		visited.Add(role);

		var inheritedRoles = registry.GetInheritedRoles(role);
		if (inheritedRoles.Count == 0) {
			return (1, new List<Role> { role });
		}

		var maxDepth = 0;
		var longestPath = new List<Role>();

		foreach (var child in inheritedRoles) {
			var visitedCopy = new HashSet<Role>(visited);
			var (childDepth, childPath) = FindLongestPathFromRole(registry, child, visitedCopy);

			if (childDepth > maxDepth) {
				maxDepth = childDepth;
				longestPath = childPath;
			}
		}

		longestPath.Insert(0, role);
		return (maxDepth + 1, longestPath);
	}

	private static List<Role> FindIsolatedRoles(IAuthorizationRoleRegistry registry, IImmutableSet<Role> allRoles) {
		// Build a graph of all connected roles
		var connected = new HashSet<Role>();
		var queue = new Queue<Role>();

		// Start with app:system role as it should be at the top of hierarchy
		queue.Enqueue(ApplicationRoles.AppSystemRole);
		connected.Add(ApplicationRoles.AppSystemRole);

		while (queue.Count > 0) {
			var current = queue.Dequeue();

			// Add roles that inherit from current role
			foreach (var parent in registry.GetInheritingRoles(current)) {
				if (connected.Add(parent)) {
					queue.Enqueue(parent);
				}
			}

			// Add roles that current role inherits from
			foreach (var child in registry.GetInheritedRoles(current)) {
				if (connected.Add(child)) {
					queue.Enqueue(child);
				}
			}
		}

		// Return roles not in the connected set
		return [.. allRoles.Except(connected)];
	}
}
