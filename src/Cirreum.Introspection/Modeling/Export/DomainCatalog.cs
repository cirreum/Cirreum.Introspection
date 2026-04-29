namespace Cirreum.Introspection.Modeling.Export;
/// <summary>
/// The complete catalog of domain operations organized hierarchically.
/// Structure: Domain -> Kind -> Operation
/// </summary>
public record DomainCatalog {

	/// <summary>
	/// Domain areas containing operations (e.g., "Customers", "Orders", "Inventory").
	/// </summary>
	public IReadOnlyDictionary<string, DomainBoundary> Domains { get; init; } = new Dictionary<string, DomainBoundary>();

	/// <summary>
	/// Aggregate metrics across the entire catalog.
	/// </summary>
	public CatalogMetrics Metrics { get; init; } = new();

	/// <summary>
	/// All operations as a flat list (convenience accessor).
	/// </summary>
	public IReadOnlyList<OperationInfo> AllOperations { get; init; } = [];

	/// <summary>
	/// Builds a catalog from a flat list of operations.
	/// </summary>
	public static DomainCatalog Build(List<OperationInfo> operationList) {

		// Group by domain -> kind
		var domainGroups = operationList
			.GroupBy(r => r.DomainBoundary)
			.OrderBy(g => g.Key);

		var domains = new Dictionary<string, DomainBoundary>();

		foreach (var domainGroup in domainGroups) {
			var domainName = domainGroup.Key;
			var domainOperations = domainGroup.ToList();

			var kindGroups = domainOperations
				.GroupBy(r => r.OperationKind)
				.OrderBy(g => g.Key);

			var kinds = new Dictionary<string, OperationKind>();

			foreach (var kindGroup in kindGroups) {
				var kindName = kindGroup.Key;
				var kindOperations = kindGroup.ToList();

				kinds[kindName] = new OperationKind {
					Name = kindName,
					Operations = kindOperations.AsReadOnly(),
					TotalCount = kindOperations.Count,
					ProtectedCount = kindOperations.Count(r => r.IsProtected),
					AnonymousCount = kindOperations.Count(r => r.IsAnonymous),
					CoveragePercentage = CalculateCoveragePercentage(kindOperations)
				};
			}

			domains[domainName] = new DomainBoundary {
				Name = domainName,
				Kinds = kinds,
				TotalCount = domainOperations.Count,
				ProtectedCount = domainOperations.Count(r => r.IsProtected),
				AnonymousCount = domainOperations.Count(r => r.IsAnonymous),
				CoveragePercentage = CalculateCoveragePercentage(domainOperations)
			};
		}

		var totalOperations = operationList.Count;
		var protectedOperations = operationList.Count(r => r.IsProtected);
		var anonymousOperations = operationList.Count(r => r.IsAnonymous);

		return new DomainCatalog {
			Domains = domains,
			AllOperations = operationList.AsReadOnly(),
			Metrics = new CatalogMetrics {
				TotalDomains = domains.Count,
				TotalKinds = domains.Values.SelectMany(d => d.Kinds.Keys).Distinct().Count(),
				TotalOperations = totalOperations,
				ProtectedOperations = protectedOperations,
				AnonymousOperations = anonymousOperations,
				OverallCoveragePercentage = CalculateCoveragePercentage(operationList)
			}
		};
	}

	/// <summary>
	/// Calculates coverage as: protected / (total - anonymous).
	/// Anonymous operations don't need protection, so they're excluded from the denominator.
	/// </summary>
	private static int CalculateCoveragePercentage(IReadOnlyList<OperationInfo> operations) {
		var authorizableCount = operations.Count(r => !r.IsAnonymous);
		if (authorizableCount == 0) {
			return 100; // No authorizable operations = 100% coverage
		}
		var protectedCount = operations.Count(r => r.IsProtected);
		return (int)((double)protectedCount / authorizableCount * 100);
	}

}
