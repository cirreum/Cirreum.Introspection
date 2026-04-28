namespace Cirreum.Introspection;

using Cirreum.Authorization;
using Cirreum.Introspection.Modeling;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Boot-time entry point for running the full authorization analyzer suite.
/// </summary>
/// <remarks>
/// <para>
/// All three extensions create a defensive scope via <see cref="ServiceProviderServiceExtensions.CreateScope"/>
/// so scoped services in the introspection graph resolve correctly under .NET's default
/// scope-validation mode. The scope is consumed eagerly within the call and not retained.
/// </para>
/// </remarks>
public static class AuthorizationStartupValidationExtensions {

	public static void ValidateAuthorizationConfiguration(
		this IServiceProvider services,
		AnalysisOptions? options = null) {

		ArgumentNullException.ThrowIfNull(services);

		using var scope = services.CreateScope();
		var sp = scope.ServiceProvider;

		var domainModel = sp.GetRequiredService<IDomainModel>();
		var registry = sp.GetRequiredService<IAuthorizationRoleRegistry>();
		var analyzer = DomainAnalyzerProvider.CreateAnalyzer(registry, domainModel, sp, options);
		var report = analyzer.AnalyzeAll();
		var summary = report.GetSummary();

		if (!summary.Passed) {
			throw new AuthorizationConfigurationException(report, summary);
		}
	}

	public static AnalysisReport? CheckAuthorizationConfiguration(
		this IServiceProvider services,
		AnalysisOptions? options = null) {

		ArgumentNullException.ThrowIfNull(services);

		using var scope = services.CreateScope();
		var sp = scope.ServiceProvider;

		var domainModel = sp.GetRequiredService<IDomainModel>();
		var registry = sp.GetRequiredService<IAuthorizationRoleRegistry>();
		var analyzer = DomainAnalyzerProvider.CreateAnalyzer(registry, domainModel, sp, options);
		var report = analyzer.AnalyzeAll();

		return report.GetSummary().Passed ? null : report;
	}

	public static AnalysisReport AnalyzeAuthorization(
		this IServiceProvider services,
		AnalysisOptions? options = null) {

		ArgumentNullException.ThrowIfNull(services);

		using var scope = services.CreateScope();
		var sp = scope.ServiceProvider;

		var domainModel = sp.GetRequiredService<IDomainModel>();
		var registry = sp.GetRequiredService<IAuthorizationRoleRegistry>();
		var analyzer = DomainAnalyzerProvider.CreateAnalyzer(registry, domainModel, sp, options);
		return analyzer.AnalyzeAll();
	}
}
