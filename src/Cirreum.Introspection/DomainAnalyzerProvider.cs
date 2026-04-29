namespace Cirreum.Introspection;

using Cirreum.Authorization;
using Cirreum.Introspection.Analyzers;
using Cirreum.Introspection.Modeling;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Builds the default analyzer suite. Resolves dependencies eagerly from the supplied
/// <see cref="IServiceProvider"/>; no analyzer retains the provider.
/// </summary>
public static class DomainAnalyzerProvider {

	public static CompositeAnalyzer CreateAnalyzer(
		IAuthorizationRoleRegistry roleRegistry,
		IDomainModel domainModel,
		IServiceProvider services,
		AnalysisOptions? options = null) {

		var analysisOptions = options ?? AnalysisOptions.Default;
		var analyzers = GetAnalyzers(roleRegistry, domainModel, services, analysisOptions);
		return new CompositeAnalyzer(analyzers, analysisOptions);
	}

	public static IReadOnlyList<IDomainAnalyzer> GetDefaultAnalyzers(
		IAuthorizationRoleRegistry roleRegistry,
		IDomainModel domainModel,
		IServiceProvider services) {

		var domainEnvironment = services.GetRequiredService<IDomainEnvironment>();

		return [
			new AuthorizationRuleAnalyzer(domainModel),
			new RoleHierarchyAnalyzer(roleRegistry),
			new AnonymousOperationAnalyzer(domainModel),
			new GrantedOperationAnalyzer(domainModel),
			new AuthorizableOperationAnalyzer(domainModel),
			new AuthorizationConstraintAnalyzer(domainModel),
			new PolicyValidatorAnalyzer(domainModel, domainEnvironment),
			new ProtectedResourceAnalyzer(domainModel),
		];
	}

	public static IReadOnlyList<IDomainAnalyzer> GetAnalyzers(
		IAuthorizationRoleRegistry roleRegistry,
		IDomainModel domainModel,
		IServiceProvider services,
		AnalysisOptions options) {

		var analyzers = GetDefaultAnalyzers(roleRegistry, domainModel, services);

		if (options.ExcludedCategories.Count == 0) {
			return analyzers;
		}

		return [.. analyzers.Where(a => {
			var categoryField = a.GetType()
				.GetField("AnalyzerCategory",
					System.Reflection.BindingFlags.Public |
					System.Reflection.BindingFlags.Static);

			if (categoryField?.GetValue(null) is string category) {
				return !options.ExcludedCategories.Contains(category);
			}
			return true;
		})];
	}
}
