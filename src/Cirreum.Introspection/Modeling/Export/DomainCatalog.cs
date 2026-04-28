namespace Cirreum.Introspection.Modeling.Export;
/// <summary>
/// The complete catalog of domain resources organized hierarchically.
/// Structure: Domain -> Kind -> Resource
/// </summary>
public record DomainCatalog {

	/// <summary>
	/// Domain areas containing resources (e.g., "Customers", "Orders", "Inventory").
	/// </summary>
	public IReadOnlyDictionary<string, DomainBoundary> Domains { get; init; } = new Dictionary<string, DomainBoundary>();

	/// <summary>
	/// Aggregate metrics across the entire catalog.
	/// </summary>
	public CatalogMetrics Metrics { get; init; } = new();

	/// <summary>
	/// All resources as a flat list (convenience accessor).
	/// </summary>
	public IReadOnlyList<ResourceInfo> AllResources { get; init; } = [];

	/// <summary>
	/// Builds a catalog from a flat list of resources.
	/// </summary>
	public static DomainCatalog Build(List<ResourceInfo> resourceList) {

		// Group by domain -> kind
		var domainGroups = resourceList
			.GroupBy(r => r.DomainBoundary)
			.OrderBy(g => g.Key);

		var domains = new Dictionary<string, DomainBoundary>();

		foreach (var domainGroup in domainGroups) {
			var domainName = domainGroup.Key;
			var domainResources = domainGroup.ToList();

			var kindGroups = domainResources
				.GroupBy(r => r.ResourceKind)
				.OrderBy(g => g.Key);

			var kinds = new Dictionary<string, ResourceKind>();

			foreach (var kindGroup in kindGroups) {
				var kindName = kindGroup.Key;
				var kindResources = kindGroup.ToList();

				kinds[kindName] = new ResourceKind {
					Name = kindName,
					Resources = kindResources.AsReadOnly(),
					TotalCount = kindResources.Count,
					ProtectedCount = kindResources.Count(r => r.IsProtected),
					AnonymousCount = kindResources.Count(r => r.IsAnonymous),
					CoveragePercentage = CalculateCoveragePercentage(kindResources)
				};
			}

			domains[domainName] = new DomainBoundary {
				Name = domainName,
				Kinds = kinds,
				TotalCount = domainResources.Count,
				ProtectedCount = domainResources.Count(r => r.IsProtected),
				AnonymousCount = domainResources.Count(r => r.IsAnonymous),
				CoveragePercentage = CalculateCoveragePercentage(domainResources)
			};
		}

		var totalResources = resourceList.Count;
		var protectedResources = resourceList.Count(r => r.IsProtected);
		var anonymousResources = resourceList.Count(r => r.IsAnonymous);

		return new DomainCatalog {
			Domains = domains,
			AllResources = resourceList.AsReadOnly(),
			Metrics = new CatalogMetrics {
				TotalDomains = domains.Count,
				TotalKinds = domains.Values.SelectMany(d => d.Kinds.Keys).Distinct().Count(),
				TotalResources = totalResources,
				ProtectedResources = protectedResources,
				AnonymousResources = anonymousResources,
				OverallCoveragePercentage = CalculateCoveragePercentage(resourceList)
			}
		};
	}

	/// <summary>
	/// Calculates coverage as: protected / (total - anonymous).
	/// Anonymous resources don't need protection, so they're excluded from the denominator.
	/// </summary>
	private static int CalculateCoveragePercentage(IReadOnlyList<ResourceInfo> resources) {
		var authorizableCount = resources.Count(r => !r.IsAnonymous);
		if (authorizableCount == 0) {
			return 100; // No authorizable resources = 100% coverage
		}
		var protectedCount = resources.Count(r => r.IsProtected);
		return (int)((double)protectedCount / authorizableCount * 100);
	}

}
