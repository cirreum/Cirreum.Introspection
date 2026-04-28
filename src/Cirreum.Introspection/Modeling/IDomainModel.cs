namespace Cirreum.Introspection.Modeling;

using Cirreum.Introspection.Modeling.Export;
using Cirreum.Introspection.Modeling.Types;

/// <summary>
/// Singleton model of the domain's authorization-relevant types and registered services.
/// </summary>
/// <remarks>
/// <para>
/// Implementations must not retain an <see cref="IServiceProvider"/>. DI-derived data is
/// resolved through an injected <see cref="Microsoft.Extensions.DependencyInjection.IServiceScopeFactory"/>
/// at first access, snapshotted into immutable structures, and then served from cache. Reflection-derived
/// data (resources, rules, catalog) is built lazily on first access.
/// </para>
/// <para>
/// Repeated calls are pointer reads against the snapshot. There is no <c>Initialize</c> step
/// and no public refresh — the caches live for the lifetime of the singleton.
/// </para>
/// </remarks>
public interface IDomainModel {

	IReadOnlyList<ResourceTypeInfo> GetAllResources();

	IReadOnlyList<ResourceTypeInfo> GetAnonymousResources();

	IReadOnlyList<ResourceTypeInfo> GetAuthorizableResources();

	IReadOnlyList<AuthorizationRuleTypeInfo> GetAuthorizationRules();

	IReadOnlyList<PolicyRuleTypeInfo> GetPolicyRules();

	CombinedRuleTypeInfo GetAllRules();

	DomainCatalog GetCatalog();

	IReadOnlyList<Type> GetAuthorizationConstraintTypes();

	IReadOnlyList<Type> GetProtectedResourceTypes();

	IReadOnlySet<Type> GetTypesWithRegisteredAccessEntryProvider();

	bool IsResourceAccessEvaluatorRegistered { get; }

	bool IsOperationGrantProviderRegistered { get; }
}
