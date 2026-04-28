namespace Cirreum.Introspection;

using Cirreum.Introspection.Documentation;
using Cirreum.Introspection.Modeling;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Registration entry point for the Cirreum introspection package.
/// </summary>
public static class IntrospectionServiceCollectionExtensions {

	/// <summary>
	/// Registers <see cref="IDomainModel"/> and <see cref="IDomainDocumenter"/> as singletons.
	/// </summary>
	/// <remarks>
	/// Uses <c>TryAddSingleton</c> so consumers can substitute their own implementations
	/// (for example, test doubles). Ships no <c>IAutoInitialize</c> / <c>IStartupTask</c> —
	/// consumers compose their own startup policy by calling
	/// <see cref="AuthorizationStartupValidationExtensions.ValidateAuthorizationConfiguration"/>
	/// (or one of its siblings) when and where they choose.
	/// </remarks>
	public static IServiceCollection AddIntrospection(this IServiceCollection services) {
		services.TryAddSingleton<IDomainModel, DomainModel>();
		services.TryAddSingleton<IDomainDocumenter, DomainDocumenter>();
		return services;
	}
}
