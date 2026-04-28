namespace Cirreum.Introspection.Documentation.Formatters;

using Cirreum.Authorization;
using System.Data;
using System.Text;

/// <summary>
/// Provides methods to render role hierarchy diagrams and visualizations.
/// </summary>
/// <remarks>
/// <para>
/// This renderer provides multiple visualization formats for role hierarchies, making it easy to understand
/// the inheritance relationships between different roles in the system.
/// </para>
/// <para>
/// Available visualization formats:
/// <list type="bullet">
/// <item><description>Text-based tree view using ASCII characters for console or log output</description></item>
/// <item><description>Mermaid diagram markup for visual representation in documentation</description></item>
/// </list>
/// </para>
/// <para>
/// The visualizations show:
/// <list type="bullet">
/// <item><description>Direct inheritance relationships between roles</description></item>
/// <item><description>Multiple inheritance paths where they exist</description></item>
/// <item><description>Role namespaces when roles exist in different contexts</description></item>
/// </list>
/// </para>
/// </remarks>
public static class RoleHierarchyRenderer {

	/// <summary>
	/// Generates a textual tree representation of the role hierarchy.
	/// </summary>
	/// <param name="registry">The permission registry containing role relationships.</param>
	/// <returns>A string containing the tree representation.</returns>
	/// <remarks>
	/// <para>
	/// The tree visualization uses ASCII characters to show the hierarchy:
	/// <list type="bullet">
	/// <item><description>├── for non-last children</description></item>
	/// <item><description>└── for the last child</description></item>
	/// <item><description>│   for vertical lines showing depth</description></item>
	/// </list>
	/// </para>
	/// <para>
	/// Example output:
	/// <code>
	/// app:admin
	/// └── app:manager
	///     ├── app:staff
	///     │   ├── app:user
	///     │   └── external:coordinator
	///     └── external:manager
	/// </code>
	/// </para>
	/// <para>
	/// The tree shows roles with their full namespace when needed for clarity, and handles
	/// circular references by marking them explicitly.
	/// </para>
	/// </remarks>
	public static string ToTextTree(IAuthorizationRoleRegistry registry) {
		var sb = new StringBuilder();
		var processedRoles = new HashSet<Role>();
		var roles = registry.GetRegisteredRoles();

		// Find top-level roles (roles that no one inherits from)
		var topRoles = roles.Where(role =>
			registry.GetInheritingRoles(role).Count == 0)
			.OrderBy(r => r.Namespace)
			.ThenBy(r => r.Name);

		foreach (var topRole in topRoles) {
			BuildRoleTree(registry, topRole, "", true, sb, processedRoles, roles);
		}

		return sb.ToString();
	}

	/// <summary>
	/// Recursively builds the text tree representation of the role hierarchy.
	/// </summary>
	/// <param name="registry">The permission registry containing role relationships.</param>
	/// <param name="currentRole">The current role being processed.</param>
	/// <param name="indent">The current level of indentation.</param>
	/// <param name="isLast">Whether this is the last item in its group.</param>
	/// <param name="sb">StringBuilder for constructing the output.</param>
	/// <param name="processedRoles">Set of roles already processed to detect cycles.</param>
	/// <param name="allRoles">All roles in the system for reference.</param>
	/// <remarks>
	/// <para>
	/// This method handles:
	/// <list type="bullet">
	/// <item><description>Proper indentation at each level</description></item>
	/// <item><description>Detection and marking of circular references</description></item>
	/// <item><description>Consistent ordering of child roles</description></item>
	/// </list>
	/// </para>
	/// </remarks>
	private static void BuildRoleTree(
		IAuthorizationRoleRegistry registry,
		Role currentRole,
		string indent,
		bool isLast,
		StringBuilder sb,
		HashSet<Role> processedRoles,
		IEnumerable<Role> allRoles) {

		if (processedRoles.Contains(currentRole)) {
			sb.AppendLine($"{indent}{(isLast ? "└── " : "├── ")}{currentRole} (circular reference)");
			return;
		}

		processedRoles.Add(currentRole);
		sb.AppendLine($"{indent}{(isLast ? "└── " : "├── ")}{currentRole}");

		// Get roles that inherit from this role (child roles)
		var childRoles = registry.GetInheritedRoles(currentRole)
			.OrderBy(r => r.Namespace)
			.ThenBy(r => r.Name)
			.ToList();

		var newIndent = indent + (isLast ? "    " : "│   ");
		for (var i = 0; i < childRoles.Count; i++) {
			BuildRoleTree(
				registry,
				childRoles[i],
				newIndent,
				i == childRoles.Count - 1,
				sb,
				processedRoles,
				allRoles);
		}

		processedRoles.Remove(currentRole);

	}

	/// <summary>
	/// Generates a Mermaid diagram showing the role inheritance hierarchy.
	/// </summary>
	/// <param name="registry">The permission registry containing role relationships.</param>
	/// <returns>A string containing the Mermaid diagram markup.</returns>
	/// <remarks>
	/// <para>
	/// The Mermaid diagram provides a visual representation with:
	/// <list type="bullet">
	/// <item><description>Boxes for each role showing namespace and name</description></item>
	/// <item><description>Arrows showing inheritance relationships (parent to child)</description></item>
	/// <item><description>Different styles for different types of roles</description></item>
	/// </list>
	/// </para>
	/// <para>
	/// Role styling categories:
	/// <list type="bullet">
	/// <item><description>root - Top-level parent role(s) that only inherit from other roles (such as Admin)</description></item>
	/// <item><description>multi - Roles that have multiple (2 or more) child roles</description></item>
	/// <item><description>default - Standard roles within the hierarchy</description></item>
	/// <item><description>extent - Final leaf child role(s) that other roles inherit from (such as User)</description></item>
	/// </list>
	/// </para>
	/// <para>
	/// The output includes Markdown formatting and can be rendered by any Mermaid-compatible viewer.
	/// </para>
	/// </remarks>
	public static string ToMermaidDiagram(IAuthorizationRoleRegistry registry) {
		var sb = new StringBuilder();
		var processedEdges = new HashSet<string>();
		var roles = registry.GetRegisteredRoles();

		// Start Mermaid graph definition
		sb.AppendLine("graph TD");
		sb.AppendLine("    %% Role Hierarchy Diagram");

		// Add relationships
		sb.AppendLine("\n    %% Inheritance Relationships");
		foreach (var role in roles) {
			var childNodeId = GetSafeNodeId(role.Name, role.Namespace);

			var parentRoles = registry.GetInheritingRoles(role);
			foreach (var parentRole in parentRoles) {
				var parentNodeId = GetSafeNodeId(parentRole.Name, parentRole.Namespace);
				// Arrow direction is from parent to child to show inheritance flowing down
				var edge = $"{parentNodeId}-->{childNodeId}";

				if (processedEdges.Add(edge)) {
					sb.AppendLine($"    {edge}");
				}
			}
		}

		return sb.ToString();

	}

	private static string GetSafeNodeId(string name, string ns) {
		var prefix = ns == Role.AppNamespace ? "app" : ns.ToLower();
		return $"{prefix}_{name.ToLower()}"
			.Replace(" ", "_")
			.Replace("-", "_")
			.Replace(".", "_")
			.Replace(":", "_")
			.Replace("(", "")
			.Replace(")", "");
	}

}
