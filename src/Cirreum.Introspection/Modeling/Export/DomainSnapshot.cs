namespace Cirreum.Introspection.Modeling.Export;

using Cirreum.Authorization;
using Cirreum.Introspection;
using Cirreum.Introspection.Documentation.Formatters;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// A complete, serializable snapshot of an authorization system's current state.
/// </summary>
/// <remarks>
/// <para>
/// This record serves as the single entry point for extracting all authorization
/// information from a runtime environment. It is designed to be:
/// </para>
/// <list type="bullet">
/// <item><description>Fully serializable for API transport (JSON-friendly types only)</description></item>
/// <item><description>Self-contained with all data needed for visualization</description></item>
/// <item><description>Comparable across different runtime hosts (e.g., WASM vs Server)</description></item>
/// </list>
/// <para>
/// Typical usage scenarios:
/// </para>
/// <list type="bullet">
/// <item><description>WASM client interrogating its own runtime</description></item>
/// <item><description>Server API endpoint returning its authorization model to clients</description></item>
/// <item><description>Admin dashboard displaying both client and server authorization models</description></item>
/// </list>
/// </remarks>
public record DomainSnapshot {

	/// <summary>
	/// UTC timestamp when this snapshot was captured.
	/// </summary>
	public required DateTime CapturedAtUtc { get; init; }

	/// <summary>
	/// The runtime environment where this snapshot was captured.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This identifies whether the snapshot originated from a Server, SPA (Blazor WASM),
	/// Azure Function, or other supported runtime. Useful for comparing authorization
	/// configurations across different deployment targets.
	/// </para>
	/// <para>
	/// For example, an admin dashboard might display side-by-side snapshots from both
	/// the WASM client and server API to verify consistent authorization coverage.
	/// </para>
	/// </remarks>
	public required DomainRuntimeType Runtime { get; init; }

	/// <summary>
	/// The complete domain catalog containing all resources organized by domain and kind.
	/// </summary>
	public required DomainCatalog Catalog { get; init; }

	/// <summary>
	/// Security analysis report with issues, metrics, and recommendations.
	/// </summary>
	public required AnalysisReport AnalysisReport { get; init; }

	/// <summary>
	/// Analysis summary with aggregated counts and pass/fail status.
	/// </summary>
	public required AnalysisSummary AnalysisSummary { get; init; }

	/// <summary>
	/// Role hierarchy information for all registered roles.
	/// </summary>
	public required IReadOnlyList<RoleHierarchyInfo> RoleHierarchy { get; init; }

	/// <summary>
	/// Mermaid diagram markup showing the authorization flow pipeline.
	/// </summary>
	public required string AuthorizationFlowDiagram { get; init; }

	/// <summary>
	/// Mermaid diagram markup showing the role inheritance hierarchy.
	/// </summary>
	public required string RoleHierarchyDiagram { get; init; }

	/// <summary>
	/// Summary of registered grant domains with their permissions and resource counts.
	/// Empty when no granted resources exist.
	/// </summary>
	public required IReadOnlyList<GrantDomainInfo> GrantDomains { get; init; }

	/// <summary>
	/// Total number of registered roles.
	/// </summary>
	public int TotalRoles => this.RoleHierarchy.Count;

	/// <summary>
	/// Creates a snapshot of the current authorization system state.
	/// </summary>
	/// <param name="roleRegistry">The role registry containing role definitions and hierarchy.</param>
	/// <param name="serviceProvider">Service provider for resolving validators and analyzers.</param>
	/// <param name="options">Optional analysis options. If null, defaults are used.</param>
	/// <returns>A complete authorization snapshot.</returns>
	public static DomainSnapshot Capture(
		IAuthorizationRoleRegistry roleRegistry,
		IServiceProvider serviceProvider,
		AnalysisOptions? options = null) {

		ArgumentNullException.ThrowIfNull(serviceProvider);

		// Open a defensive scope so any scoped service in the introspection graph
		// resolves correctly under .NET's default scope-validation mode. The
		// scope is consumed eagerly; nothing in the returned snapshot retains it.
		using var scope = serviceProvider.CreateScope();
		var sp = scope.ServiceProvider;

		var domainModel = sp.GetRequiredService<IDomainModel>();
		var domainEnvironment = sp.GetRequiredService<IDomainEnvironment>();

		var analysisOptions = options ?? new AnalysisOptions {
			MaxHierarchyDepth = 10,
			ExcludedCategories = []
		};

		var analyzer = DomainAnalyzerProvider.CreateAnalyzer(roleRegistry, domainModel, sp, analysisOptions);
		var analysisReport = analyzer.AnalyzeAll();

		var roleHierarchy = BuildRoleHierarchy(roleRegistry);
		var catalog = domainModel.GetCatalog();
		var grantDomains = BuildGrantDomains(catalog);

		return new DomainSnapshot {
			Runtime = domainEnvironment.RuntimeType,
			CapturedAtUtc = DateTime.UtcNow,
			Catalog = catalog,
			AnalysisReport = analysisReport,
			AnalysisSummary = analysisReport.GetSummary(),
			RoleHierarchy = roleHierarchy,
			AuthorizationFlowDiagram = AuthorizationFlowRenderer.ToMermaidDiagram(),
			RoleHierarchyDiagram = RoleHierarchyRenderer.ToMermaidDiagram(roleRegistry),
			GrantDomains = grantDomains
		};
	}

	private static List<GrantDomainInfo> BuildGrantDomains(DomainCatalog catalog) {
		var grantedResources = catalog.AllResources
			.Where(r => r.IsGranted && r.GrantDomain is not null);

		var byDomain = grantedResources
			.GroupBy(r => r.GrantDomain!)
			.OrderBy(g => g.Key, StringComparer.Ordinal);

		var result = new List<GrantDomainInfo>();
		foreach (var group in byDomain) {
			var permissions = group
				.SelectMany(r => r.Permissions)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.OrderBy(p => p, StringComparer.Ordinal)
				.ToList();

			result.Add(new GrantDomainInfo(
				Domain: group.Key,
				Permissions: permissions,
				GrantedResourceCount: group.Count()
			));
		}
		return result;
	}

	private static List<RoleHierarchyInfo> BuildRoleHierarchy(IAuthorizationRoleRegistry roleRegistry) {
		var allRoles = roleRegistry.GetRegisteredRoles();
		var result = new List<RoleHierarchyInfo>();

		foreach (var role in allRoles) {
			var childRoles = roleRegistry.GetInheritedRoles(role);
			var parentRoles = roleRegistry.GetInheritingRoles(role);
			var depth = CalculateHierarchyDepth(role, [], roleRegistry);

			result.Add(new RoleHierarchyInfo(
				RoleString: role.ToString(),
				IsApplicationRole: role.IsApplicationRole,
				ChildRoleStrings: [.. childRoles.Select(r => r.ToString())],
				ParentRoleStrings: [.. parentRoles.Select(r => r.ToString())],
				InheritsFromCount: childRoles.Count,
				InheritedByCount: parentRoles.Count,
				HierarchyDepth: depth
			));
		}

		return [.. result
			.OrderBy(r => r.HierarchyDepth)
			.ThenBy(r => r.RoleString)];
	}

	private static int CalculateHierarchyDepth(Role role, HashSet<Role> visited, IAuthorizationRoleRegistry registry) {
		if (visited.Contains(role)) {
			return 0;
		}

		visited.Add(role);

		var inheritedRoles = registry.GetInheritedRoles(role);
		if (inheritedRoles.Count == 0) {
			return 0;
		}

		return inheritedRoles.Max(inherited =>
			CalculateHierarchyDepth(inherited, [.. visited], registry)) + 1;
	}

}
