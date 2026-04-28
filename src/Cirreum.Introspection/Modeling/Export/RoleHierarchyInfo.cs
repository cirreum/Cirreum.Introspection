namespace Cirreum.Introspection.Modeling.Export;

/// <summary>
/// Contains hierarchy information for a single role, including its relationships
/// with other roles in the inheritance hierarchy.
/// </summary>
/// <remarks>
/// This record is designed to be serializable for transport across API boundaries,
/// allowing clients to display role hierarchy information from remote authorization systems.
/// </remarks>
/// <param name="RoleString">The role identifier in "namespace:name" format.</param>
/// <param name="IsApplicationRole">Whether this is a built-in application role.</param>
/// <param name="ChildRoleStrings">Roles that this role inherits from (child roles in the hierarchy).</param>
/// <param name="ParentRoleStrings">Roles that inherit from this role (parent roles in the hierarchy).</param>
/// <param name="InheritsFromCount">The number of roles this role directly inherits from.</param>
/// <param name="InheritedByCount">The number of roles that directly inherit from this role.</param>
/// <param name="HierarchyDepth">The depth of this role in the inheritance hierarchy (0 = leaf role).</param>
public record RoleHierarchyInfo(
	string RoleString,
	bool IsApplicationRole,
	IReadOnlyList<string> ChildRoleStrings,
	IReadOnlyList<string> ParentRoleStrings,
	int InheritsFromCount,
	int InheritedByCount,
	int HierarchyDepth
);
