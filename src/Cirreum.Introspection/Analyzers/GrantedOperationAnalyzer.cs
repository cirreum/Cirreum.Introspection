namespace Cirreum.Introspection.Analyzers;

using Cirreum.Authorization.Operations;
using Cirreum.Authorization.Operations.Grants;
using Cirreum.Conductor;
using Cirreum.Introspection.Modeling;
using Cirreum.Introspection.Modeling.Types;

/// <summary>
/// Analyzes granted resources and grant domain hygiene.
/// </summary>
public class GrantedResourceAnalyzer(IDomainModel domainModel) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Granted Resources";

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var allResources = domainModel.GetAllResources();

		var grantedResources = allResources.Where(r => r.IsGranted).ToList();
		var grantDomains = grantedResources
			.Where(r => r.GrantDomain is not null)
			.Select(r => r.GrantDomain!)
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.ToList();

		// ──────────────────────────────────────────────
		// 1. Granted resources without [RequiresGrant]
		// ──────────────────────────────────────────────

		var missingPermissions = grantedResources
			.Where(r => r.Permissions.Count == 0)
			.ToList();

		if (missingPermissions.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: $"Found {missingPermissions.Count} granted resource(s) without [RequiresGrant]. " +
					"These resources participate in the grant pipeline but have no permission gate, " +
					"so grant evaluation cannot enforce access control.",
				RelatedTypeNames: [.. missingPermissions.Select(TypeName)],
				Recommendation: "Add [RequiresGrant(\"name\")] to each granted resource to define " +
					"the grant permission(s) required for access."));
		}

		// ──────────────────────────────────────────────
		// 2. [RequiresGrant] on non-granted resources
		// ──────────────────────────────────────────────

		var permissionsWithoutGrants = allResources
			.Where(r => !r.IsGranted && r.Permissions.Count > 0)
			.ToList();

		if (permissionsWithoutGrants.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Found {permissionsWithoutGrants.Count} resource(s) with [RequiresGrant] " +
					"that do not implement a Granted interface. The declared permissions are available on " +
					"AuthorizationContext.RequiredGrants for inspection in resource authorizers.",
				RelatedTypeNames: [.. permissionsWithoutGrants.Select(TypeName)],
				Recommendation: "If grant-based access control is intended, add the appropriate Granted " +
					"interface (e.g., IOwnerMutateOperation). Otherwise, ensure the resource authorizer " +
					"consumes RequiredGrants for authorization decisions."));
		}

		// ──────────────────────────────────────────────
		// 3. Granted resources without a resource authorizer
		// ──────────────────────────────────────────────

		var grantedWithoutAuthorizer = grantedResources
			.Where(r => !r.IsProtected)
			.ToList();

		if (grantedWithoutAuthorizer.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Found {grantedWithoutAuthorizer.Count} granted resource(s) without a " +
					"resource authorizer (Stage 2). Grant evaluation (Stage 1) runs, but no " +
					"resource-level authorization rules are applied.",
				RelatedTypeNames: [.. grantedWithoutAuthorizer.Select(TypeName)],
				Recommendation: "If these resources require resource-level authorization beyond grant " +
					"evaluation, add a AuthorizerBase<T> implementation. If grants-only " +
					"authorization is intentional, this can be safely ignored."));
		}

		// ──────────────────────────────────────────────
		// 4. Mixed authorization within a domain
		// ──────────────────────────────────────────────

		DetectMixedAuthorizationDomains(allResources, grantDomains, issues);

		// ──────────────────────────────────────────────
		// 5. No IOperationGrantProvider registered
		// ──────────────────────────────────────────────

		var grantProviderRegistered = domainModel.IsOperationGrantProviderRegistered;

		if (grantedResources.Count > 0 && !grantProviderRegistered) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: $"Found {grantedResources.Count} granted resource(s) but no IOperationGrantProvider " +
					"is registered. Grant evaluation (Stage 1) cannot run without a grant resolver.",
				RelatedTypeNames: [],
				Recommendation: "Register an IOperationGrantProvider implementation via " +
					"services.AddOperationGrants<TResolver>() to enable grant-based access control."));
		}

		// ──────────────────────────────────────────────
		// 6. Self-scoped operations summary
		// ──────────────────────────────────────────────

		var selfScoped = grantedResources.Where(r => r.IsSelfScoped).ToList();

		if (selfScoped.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"{selfScoped.Count} self-scoped operation(s) detected. These use identity " +
					"matching (ExternalId == UserId) instead of owner-scope grant resolution.",
				RelatedTypeNames: [.. selfScoped.Select(TypeName)],
				Recommendation: null));
		}

		// ──────────────────────────────────────────────
		// 7. Self-scoped operations without permissions
		// ──────────────────────────────────────────────

		var selfScopedNoPermissions = selfScoped
			.Where(r => r.Permissions.Count == 0)
			.ToList();

		if (selfScopedNoPermissions.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Found {selfScopedNoPermissions.Count} self-scoped operation(s) without " +
					"[RequiresGrant]. Self-scoped operations rely on identity matching; " +
					"permissions are optional but enable permission-gated self-access.",
				RelatedTypeNames: [.. selfScopedNoPermissions.Select(TypeName)],
				Recommendation: "Add [RequiresGrant] if you need the grant system to verify specific " +
					"permissions before allowing self-access. Otherwise, identity matching alone is sufficient."));
		}

		// ──────────────────────────────────────────────
		// 8. Cross-feature permissions
		// ──────────────────────────────────────────────

		var crossFeature = grantedResources
			.Where(r => r.Permissions.Count >= 2)
			.Where(r => r.Permissions.Select(p => p.Feature).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
			.ToList();

		if (crossFeature.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: $"Found {crossFeature.Count} resource(s) with [RequiresGrant] attributes " +
					"spanning multiple features.",
				RelatedTypeNames: [.. crossFeature.Select(TypeName)],
				Recommendation: "All permissions on a granted resource should use the same feature. " +
					"Cross-cutting concerns belong in Stage 2 resource authorizers or Stage 3 policies."));
		}

		// ──────────────────────────────────────────────
		// 9. Unsafe ICacheableOperation + grant interface combinations
		// ──────────────────────────────────────────────
		//
		// SAFE:   IOwnerCacheableLookupOperation<T> — designed for this combination;
		//         framework composes {owner}:{boundary}:{CacheKey}, adding tenant scope.
		// UNSAFE: any other IGrantable*Base + ICacheableOperation — shared cache entry
		//         spans callers with potentially different grant scopes, causing leaks.

		var unsafeCacheableGrants = allResources
			.Where(r => r.IsGranted && r.IsCacheableQuery)
			.Where(r => !typeof(IOwnerCacheableLookupOperation<>)
				.IsAssignableFromGenericInterface(r.ResourceType))
			.ToList();

		if (unsafeCacheableGrants.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: $"Found {unsafeCacheableGrants.Count} resource(s) combining ICacheableOperation " +
					"with a grant-aware interface other than IOwnerCacheableLookupOperation<T>. " +
					"ICacheableOperation entries are shared across all callers; mixing with grant " +
					"semantics can leak data to callers whose grant scope no longer covers the cached " +
					"entry.",
				RelatedTypeNames: [.. unsafeCacheableGrants.Select(TypeName)],
				Recommendation: "If owner-scoped caching is intended, switch to IOwnerCacheableLookupOperation<T> " +
					"— the framework composes the OwnerId and authentication boundary into the cache key. " +
					"Otherwise, drop ICacheableOperation; per-caller authorization decisions cannot share " +
					"a cache entry safely."));
		}

		// ──────────────────────────────────────────────
		// Metrics
		// ──────────────────────────────────────────────

		var permissionCount = grantedResources
			.SelectMany(r => r.Permissions)
			.Select(p => p.ToString())
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.Count();

		metrics[$"{MetricCategories.GrantedResources}GrantedResourceCount"] = grantedResources.Count;
		metrics[$"{MetricCategories.GrantedResources}GrantFeatureCount"] = grantDomains.Count;
		metrics[$"{MetricCategories.GrantedResources}TotalPermissionCount"] = permissionCount;
		metrics[$"{MetricCategories.GrantedResources}MissingPermissionCount"] = missingPermissions.Count;
		metrics[$"{MetricCategories.GrantedResources}PermissionsWithoutGrantsCount"] = permissionsWithoutGrants.Count;
		metrics[$"{MetricCategories.GrantedResources}GrantProviderRegistered"] = grantProviderRegistered ? 1 : 0;
		metrics[$"{MetricCategories.GrantedResources}SelfScopedCount"] = selfScoped.Count;
		metrics[$"{MetricCategories.GrantedResources}CrossFeaturePermissionCount"] = crossFeature.Count;
		metrics[$"{MetricCategories.GrantedResources}UnsafeCacheableGrantCount"] = unsafeCacheableGrants.Count;

		// Summary
		if (grantedResources.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Grant system active: {grantedResources.Count} granted resource(s) across " +
					$"{grantDomains.Count} domain(s) using {permissionCount} distinct permission(s).",
				RelatedTypeNames: grantDomains));
		}

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);

	}

	/// <summary>
	/// Detects domain boundaries where some authorizable resources are granted and others
	/// are not — may indicate an incomplete migration to grants.
	/// </summary>
	private static void DetectMixedAuthorizationDomains(
		IReadOnlyList<ResourceTypeInfo> allResources,
		List<string> grantDomains,
		List<AnalysisIssue> issues) {

		if (grantDomains.Count == 0) {
			return;
		}

		// Group authorizable resources by DomainBoundary, then check if the boundary
		// has both granted and non-granted resources
		var authorizableByBoundary = allResources
			.Where(r => r.RequiresAuthorization)
			.GroupBy(r => r.DomainBoundary, StringComparer.OrdinalIgnoreCase);

		foreach (var group in authorizableByBoundary) {
			var granted = group.Where(r => r.IsGranted).ToList();
			var nonGranted = group.Where(r => !r.IsGranted).ToList();

			if (granted.Count > 0 && nonGranted.Count > 0) {
				issues.Add(new AnalysisIssue(
					Category: AnalyzerCategory,
					Severity: IssueSeverity.Info,
					Description: $"Domain boundary '{group.Key}' has {granted.Count} granted and " +
						$"{nonGranted.Count} non-granted authorizable resource(s). " +
						"This may indicate an incomplete migration to grants.",
					RelatedTypeNames: [.. nonGranted.Select(TypeName)],
					Recommendation: "If all resources in this domain should use grant-based access control, " +
						"add the appropriate Granted interface to the remaining resources. If the mix is " +
						"intentional (e.g., some operations are role-only), this can be safely ignored."));
			}
		}

	}

	private static string TypeName(ResourceTypeInfo r) =>
		r.ResourceType.FullName ?? r.ResourceType.Name;

}

internal static class GenericInterfaceExtensions {

	/// <summary>
	/// Returns <see langword="true"/> when <paramref name="candidate"/> implements a closed
	/// construction of the open generic interface <paramref name="openGenericInterface"/>
	/// (e.g., does the type implement <c>IOwnerCacheableLookupOperation&lt;&gt;</c> for any
	/// <c>T</c>).
	/// </summary>
	internal static bool IsAssignableFromGenericInterface(this Type openGenericInterface, Type candidate) {
		if (!openGenericInterface.IsGenericTypeDefinition || !openGenericInterface.IsInterface) {
			return false;
		}
		foreach (var iface in candidate.GetInterfaces()) {
			if (iface.IsGenericType && iface.GetGenericTypeDefinition() == openGenericInterface) {
				return true;
			}
		}
		return false;
	}
}
