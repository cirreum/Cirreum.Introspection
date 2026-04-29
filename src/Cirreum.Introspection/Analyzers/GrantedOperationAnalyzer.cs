namespace Cirreum.Introspection.Analyzers;

using Cirreum.Authorization.Operations;
using Cirreum.Authorization.Operations.Grants;
using Cirreum.Conductor;
using Cirreum.Introspection.Modeling;
using Cirreum.Introspection.Modeling.Types;

/// <summary>
/// Analyzes granted operations and grant domain hygiene.
/// </summary>
public class GrantedOperationAnalyzer(IDomainModel domainModel) : IDomainAnalyzer {

	public const string AnalyzerCategory = "Granted Operations";

	public AnalysisReport Analyze() {

		var issues = new List<AnalysisIssue>();
		var metrics = new Dictionary<string, int>();

		var allOperations = domainModel.GetAllOperations();

		var grantedOperations = allOperations.Where(r => r.IsGranted).ToList();
		var grantDomains = grantedOperations
			.Where(r => r.GrantDomain is not null)
			.Select(r => r.GrantDomain!)
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.ToList();

		// ──────────────────────────────────────────────
		// 1. Granted operations without [RequiresGrant]
		// ──────────────────────────────────────────────

		var missingPermissions = grantedOperations
			.Where(r => r.Permissions.Count == 0)
			.ToList();

		if (missingPermissions.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: $"Found {missingPermissions.Count} granted operation(s) without [RequiresGrant]. " +
					"These operations participate in the grant pipeline but have no permission gate, " +
					"so grant evaluation cannot enforce access control.",
				RelatedTypeNames: [.. missingPermissions.Select(TypeName)],
				Recommendation: "Add [RequiresGrant(\"name\")] to each granted operation to define " +
					"the grant permission(s) required for access."));
		}

		// ──────────────────────────────────────────────
		// 2. [RequiresGrant] on non-granted operations
		// ──────────────────────────────────────────────

		var permissionsWithoutGrants = allOperations
			.Where(r => !r.IsGranted && r.Permissions.Count > 0)
			.ToList();

		if (permissionsWithoutGrants.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Found {permissionsWithoutGrants.Count} operation(s) with [RequiresGrant] " +
					"that do not implement a Granted interface. The declared permissions are available on " +
					"AuthorizationContext.RequiredGrants for inspection in operation authorizers.",
				RelatedTypeNames: [.. permissionsWithoutGrants.Select(TypeName)],
				Recommendation: "If grant-based access control is intended, add the appropriate Granted " +
					"interface (e.g., IOwnerMutateOperation). Otherwise, ensure the operation authorizer " +
					"consumes RequiredGrants for authorization decisions."));
		}

		// ──────────────────────────────────────────────
		// 3. Granted operations without a operation authorizer
		// ──────────────────────────────────────────────

		var grantedWithoutAuthorizer = grantedOperations
			.Where(r => !r.IsProtected)
			.ToList();

		if (grantedWithoutAuthorizer.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Found {grantedWithoutAuthorizer.Count} granted operation(s) without a " +
					"operation authorizer (Phase 2). Grant evaluation (Phase 1, Step 1) runs, but no " +
					"operation-level authorization rules are applied.",
				RelatedTypeNames: [.. grantedWithoutAuthorizer.Select(TypeName)],
				Recommendation: "If these operations require operation-level authorization beyond grant " +
					"evaluation, add a AuthorizerBase<T> implementation. If grants-only " +
					"authorization is intentional, this can be safely ignored."));
		}

		// ──────────────────────────────────────────────
		// 4. Mixed authorization within a domain
		// ──────────────────────────────────────────────

		DetectMixedAuthorizationDomains(allOperations, grantDomains, issues);

		// ──────────────────────────────────────────────
		// 5. No IOperationGrantProvider registered
		// ──────────────────────────────────────────────

		var grantProviderRegistered = domainModel.IsOperationGrantProviderRegistered;

		if (grantedOperations.Count > 0 && !grantProviderRegistered) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: $"Found {grantedOperations.Count} granted operation(s) but no IOperationGrantProvider " +
					"is registered. Grant evaluation (Phase 1, Step 1) cannot run without a grant resolver.",
				RelatedTypeNames: [],
				Recommendation: "Register an IOperationGrantProvider implementation via " +
					"services.AddOperationGrants<TResolver>() to enable grant-based access control."));
		}

		// ──────────────────────────────────────────────
		// 6. Self-scoped operations summary
		// ──────────────────────────────────────────────

		var selfScoped = grantedOperations.Where(r => r.IsSelfScoped).ToList();

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

		var crossFeature = grantedOperations
			.Where(r => r.Permissions.Count >= 2)
			.Where(r => r.Permissions.Select(p => p.Feature).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
			.ToList();

		if (crossFeature.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Warning,
				Description: $"Found {crossFeature.Count} operation(s) with [RequiresGrant] attributes " +
					"spanning multiple features.",
				RelatedTypeNames: [.. crossFeature.Select(TypeName)],
				Recommendation: "All permissions on a granted operation should use the same feature. " +
					"Cross-cutting concerns belong in Phase 2 operation authorizers or Phase 3 policies."));
		}

		// ──────────────────────────────────────────────
		// 9. Unsafe ICacheableOperation + grant interface combinations
		// ──────────────────────────────────────────────
		//
		// SAFE:   IOwnerCacheableLookupOperation<T> — designed for this combination;
		//         framework composes {owner}:{boundary}:{CacheKey}, adding tenant scope.
		// UNSAFE: any other IGrantable*Base + ICacheableOperation — shared cache entry
		//         spans callers with potentially different grant scopes, causing leaks.

		var unsafeCacheableGrants = allOperations
			.Where(r => r.IsGranted && r.IsCacheableQuery)
			.Where(r => !typeof(IOwnerCacheableLookupOperation<>)
				.IsAssignableFromGenericInterface(r.OperationType))
			.ToList();

		if (unsafeCacheableGrants.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Error,
				Description: $"Found {unsafeCacheableGrants.Count} operation(s) combining ICacheableOperation " +
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

		var permissionCount = grantedOperations
			.SelectMany(r => r.Permissions)
			.Select(p => p.ToString())
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.Count();

		metrics[$"{MetricCategories.GrantedOperations}GrantedOperationCount"] = grantedOperations.Count;
		metrics[$"{MetricCategories.GrantedOperations}GrantFeatureCount"] = grantDomains.Count;
		metrics[$"{MetricCategories.GrantedOperations}TotalPermissionCount"] = permissionCount;
		metrics[$"{MetricCategories.GrantedOperations}MissingPermissionCount"] = missingPermissions.Count;
		metrics[$"{MetricCategories.GrantedOperations}PermissionsWithoutGrantsCount"] = permissionsWithoutGrants.Count;
		metrics[$"{MetricCategories.GrantedOperations}GrantProviderRegistered"] = grantProviderRegistered ? 1 : 0;
		metrics[$"{MetricCategories.GrantedOperations}SelfScopedCount"] = selfScoped.Count;
		metrics[$"{MetricCategories.GrantedOperations}CrossFeaturePermissionCount"] = crossFeature.Count;
		metrics[$"{MetricCategories.GrantedOperations}UnsafeCacheableGrantCount"] = unsafeCacheableGrants.Count;

		// Summary
		if (grantedOperations.Count > 0) {
			issues.Add(new AnalysisIssue(
				Category: AnalyzerCategory,
				Severity: IssueSeverity.Info,
				Description: $"Grant system active: {grantedOperations.Count} granted operation(s) across " +
					$"{grantDomains.Count} domain(s) using {permissionCount} distinct permission(s).",
				RelatedTypeNames: grantDomains));
		}

		return AnalysisReport.ForCategory(AnalyzerCategory, issues, metrics);

	}

	/// <summary>
	/// Detects domain boundaries where some authorizable operations are granted and others
	/// are not — may indicate an incomplete migration to grants.
	/// </summary>
	private static void DetectMixedAuthorizationDomains(
		IReadOnlyList<OperationTypeInfo> allOperations,
		List<string> grantDomains,
		List<AnalysisIssue> issues) {

		if (grantDomains.Count == 0) {
			return;
		}

		// Group authorizable operations by DomainBoundary, then check if the boundary
		// has both granted and non-granted operations
		var authorizableByBoundary = allOperations
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
						$"{nonGranted.Count} non-granted authorizable operation(s). " +
						"This may indicate an incomplete migration to grants.",
					RelatedTypeNames: [.. nonGranted.Select(TypeName)],
					Recommendation: "If all operations in this domain should use grant-based access control, " +
						"add the appropriate Granted interface to the remaining operations. If the mix is " +
						"intentional (e.g., some operations are role-only), this can be safely ignored."));
			}
		}

	}

	private static string TypeName(OperationTypeInfo r) =>
		r.OperationType.FullName ?? r.OperationType.Name;

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
