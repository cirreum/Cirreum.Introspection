namespace Cirreum.Introspection.Modeling;

using Cirreum;
using Cirreum.Authorization;
using Cirreum.Authorization.Operations;
using Cirreum.Authorization.Operations.Grants;
using Cirreum.Authorization.Resources;
using Cirreum.Conductor;
using Cirreum.Introspection.Modeling.Export;
using Cirreum.Introspection.Modeling.Types;
using FluentValidation;
using FluentValidation.Internal;
using FluentValidation.Validators;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;

/// <summary>
/// Default <see cref="IDomainModel"/> implementation.
/// </summary>
/// <remarks>
/// <para>
/// Holds an <see cref="IServiceScopeFactory"/> (singleton-safe) and resolves DI-derived
/// snapshots through transient scopes on first access. Reflection-derived data is cached
/// via <see cref="Lazy{T}"/>. No <see cref="IServiceProvider"/> is retained.
/// </para>
/// </remarks>
public sealed class DomainModel : IDomainModel {

	private readonly IServiceScopeFactory _scopeFactory;
	private readonly Lazy<IReadOnlyList<ResourceTypeInfo>> _resources =
		new(BuildResources, isThreadSafe: true);
	private readonly Lazy<IReadOnlyList<AuthorizationRuleTypeInfo>> _rules =
		new(BuildRules, isThreadSafe: true);
	private readonly Lazy<DomainCatalog> _catalog;
	private readonly Lazy<IReadOnlyList<Type>> _protectedResourceTypes =
		new(DiscoverProtectedResourceTypes, isThreadSafe: true);

	private IReadOnlyList<PolicyRuleTypeInfo>? _policyRules;
	private IReadOnlyList<Type>? _constraintTypes;
	private IReadOnlySet<Type>? _typesWithAccessEntryProvider;
	private bool? _evaluatorRegistered;
	private bool? _grantProviderRegistered;
	private readonly Lock _initLock = new();

	public DomainModel(IServiceScopeFactory scopeFactory) {
		this._scopeFactory = scopeFactory;
		this._catalog = new Lazy<DomainCatalog>(
			() => DomainCatalog.Build([.. this._resources.Value.Select(r => r.ToResourceInfo())]),
			isThreadSafe: true);
	}

	public DomainModel() : this(NullScopeFactory.Instance) { }

	public IReadOnlyList<ResourceTypeInfo> GetAllResources() => this._resources.Value;

	public IReadOnlyList<ResourceTypeInfo> GetAnonymousResources() =>
		this._resources.Value.Where(r => r.IsAnonymous).ToList().AsReadOnly();

	public IReadOnlyList<ResourceTypeInfo> GetAuthorizableResources() =>
		this._resources.Value.Where(r => !r.IsAnonymous).ToList().AsReadOnly();

	public IReadOnlyList<AuthorizationRuleTypeInfo> GetAuthorizationRules() =>
		this._rules.Value;

	public IReadOnlyList<PolicyRuleTypeInfo> GetPolicyRules() {
		if (this._policyRules is not null) {
			return this._policyRules;
		}

		lock (this._initLock) {
			if (this._policyRules is not null) {
				return this._policyRules;
			}

			using var scope = this._scopeFactory.CreateScope();
			this._policyRules = BuildPolicyRules(scope.ServiceProvider);
		}

		return this._policyRules;
	}

	public CombinedRuleTypeInfo GetAllRules() {
		var resourceRules = this.GetAuthorizationRules();
		var policyRules = this.GetPolicyRules();
		return new CombinedRuleTypeInfo(
			ResourceRules: resourceRules,
			PolicyRules: policyRules,
			TotalRules: resourceRules.Count + policyRules.Count
		);
	}

	public DomainCatalog GetCatalog() => this._catalog.Value;

	public IReadOnlyList<Type> GetAuthorizationConstraintTypes() {
		if (this._constraintTypes is not null) {
			return this._constraintTypes;
		}

		lock (this._initLock) {
			if (this._constraintTypes is not null) {
				return this._constraintTypes;
			}

			using var scope = this._scopeFactory.CreateScope();
			this._constraintTypes = scope.ServiceProvider
				.GetServices<IAuthorizationConstraint>()
				.Select(c => c.GetType())
				.ToList()
				.AsReadOnly();
		}

		return this._constraintTypes;
	}

	public IReadOnlyList<Type> GetProtectedResourceTypes() => this._protectedResourceTypes.Value;

	public IReadOnlySet<Type> GetTypesWithRegisteredAccessEntryProvider() {
		if (this._typesWithAccessEntryProvider is not null) {
			return this._typesWithAccessEntryProvider;
		}

		lock (this._initLock) {
			if (this._typesWithAccessEntryProvider is not null) {
				return this._typesWithAccessEntryProvider;
			}

			using var scope = this._scopeFactory.CreateScope();
			var sp = scope.ServiceProvider;
			var set = new HashSet<Type>();
			foreach (var t in this.GetProtectedResourceTypes()) {
				var providerType = typeof(IAccessEntryProvider<>).MakeGenericType(t);
				if (sp.GetService(providerType) is not null) {
					set.Add(t);
				}
			}
			this._typesWithAccessEntryProvider = set;
		}

		return this._typesWithAccessEntryProvider;
	}

	public bool IsResourceAccessEvaluatorRegistered {
		get {
			if (this._evaluatorRegistered.HasValue) {
				return this._evaluatorRegistered.Value;
			}
			lock (this._initLock) {
				if (this._evaluatorRegistered.HasValue) {
					return this._evaluatorRegistered.Value;
				}
				using var scope = this._scopeFactory.CreateScope();
				this._evaluatorRegistered = scope.ServiceProvider.GetService<IResourceAccessEvaluator>() is not null;
			}
			return this._evaluatorRegistered.Value;
		}
	}

	public bool IsOperationGrantProviderRegistered {
		get {
			if (this._grantProviderRegistered.HasValue) {
				return this._grantProviderRegistered.Value;
			}
			lock (this._initLock) {
				if (this._grantProviderRegistered.HasValue) {
					return this._grantProviderRegistered.Value;
				}
				using var scope = this._scopeFactory.CreateScope();
				this._grantProviderRegistered = scope.ServiceProvider.GetService<IOperationGrantProvider>() is not null;
			}
			return this._grantProviderRegistered.Value;
		}
	}

	private sealed class NullScopeFactory : IServiceScopeFactory {
		public static readonly NullScopeFactory Instance = new();
		public IServiceScope CreateScope() => throw new InvalidOperationException(
			"DomainModel was constructed without an IServiceScopeFactory; DI-derived members are unavailable.");
	}

	#region Build (reflection-derived)

	private static ReadOnlyCollection<ResourceTypeInfo> BuildResources() {
		var assemblies = Cirreum.AssemblyScanner.ScanAssemblies();
		var allTypes = assemblies
			.SelectMany(a => {
				try { return a.GetTypes(); } catch { return Type.EmptyTypes; }
			})
			.Where(t => t.IsClass && !t.IsAbstract)
			.ToList();

		var domainResourceTypes = allTypes.Where(IsDomainObject).ToList();
		var authorizerTypes = allTypes.Where(IsObjectAuthorizer).ToList();
		var authorizersByResource = new Dictionary<Type, Type>();
		foreach (var authorizer in authorizerTypes) {
			var resourceType = GetResourceTypeFromAuthorizer(authorizer);
			if (resourceType != null) {
				authorizersByResource[resourceType] = authorizer;
			}
		}

		var resources = new List<ResourceTypeInfo>();
		foreach (var resourceType in domainResourceTypes) {
			var hasAuthorizer = authorizersByResource.TryGetValue(resourceType, out var authorizerType);
			var rules = hasAuthorizer ? ExtractValidationRules(resourceType, authorizerType!) : [];

			var isAnonymous = !IsAuthorizableObject(resourceType);
			var isCacheableQuery = IsCacheableQuery(resourceType);
			var requiresAuthorization = !isAnonymous && ImplementsAuthorizableOperation(resourceType);

			var grantDomain = DomainFeatureResolver.Resolve(resourceType);
			var permissions = RequiredGrantCache.GetFor(resourceType);
			var isSelfScoped = typeof(IGrantableSelfBase).IsAssignableFrom(resourceType);
			var isGranted = isSelfScoped
				|| typeof(IGrantableMutateBase).IsAssignableFrom(resourceType)
				|| typeof(IGrantableLookupBase).IsAssignableFrom(resourceType)
				|| typeof(IGrantableSearchBase).IsAssignableFrom(resourceType);

			var grantableKind = isSelfScoped ? "Self"
				: typeof(IGrantableMutateBase).IsAssignableFrom(resourceType) ? "Mutate"
				: typeof(IGrantableLookupBase).IsAssignableFrom(resourceType) ? "Lookup"
				: typeof(IGrantableSearchBase).IsAssignableFrom(resourceType) ? "Search"
				: (string?)null;

			resources.Add(new ResourceTypeInfo(
				ResourceType: resourceType,
				DomainBoundary: GetDomainBoundary(resourceType),
				ResourceKind: GetResourceKind(resourceType),
				IsAnonymous: isAnonymous,
				IsCacheableQuery: isCacheableQuery,
				IsProtected: authorizerType != null,
				RequiresAuthorization: requiresAuthorization,
				AuthorizerType: authorizerType,
				Rules: rules.AsReadOnly(),
				IsGranted: isGranted,
				GrantDomain: grantDomain,
				GrantableKind: grantableKind,
				IsSelfScoped: isSelfScoped,
				Permissions: permissions
			));
		}

		return resources.AsReadOnly();
	}

	private static ReadOnlyCollection<AuthorizationRuleTypeInfo> BuildRules() {
		var assemblies = Cirreum.AssemblyScanner.ScanAssemblies();
		var allTypes = assemblies
			.SelectMany(a => {
				try { return a.GetTypes(); } catch { return Type.EmptyTypes; }
			})
			.Where(t => t.IsClass && !t.IsAbstract)
			.ToList();
		var authorizerTypes = allTypes.Where(IsObjectAuthorizer).ToList();

		var rules = new HashSet<AuthorizationRuleTypeInfo>();
		foreach (var authorizerType in authorizerTypes) {
			var resourceType = GetResourceTypeFromAuthorizer(authorizerType) ?? typeof(MissingResource);
			var ruleInfos = ExtractValidationRules(resourceType, authorizerType);
			rules.UnionWith(ruleInfos);
		}

		return rules.ToList().AsReadOnly();
	}

	private static ReadOnlyCollection<Type> DiscoverProtectedResourceTypes() {
		var types = new List<Type>();
		foreach (var assembly in Cirreum.AssemblyScanner.ScanAssemblies()) {
			Type[] assemblyTypes;
			try { assemblyTypes = assembly.GetTypes(); } catch { continue; }
			foreach (var type in assemblyTypes) {
				if (!type.IsAbstract && typeof(IProtectedResource).IsAssignableFrom(type)) {
					types.Add(type);
				}
			}
		}
		return types.AsReadOnly();
	}

	private static ReadOnlyCollection<PolicyRuleTypeInfo> BuildPolicyRules(IServiceProvider services) {
		var policyValidators = services.GetServices<IPolicyValidator>().ToList();
		var policyRules = new List<PolicyRuleTypeInfo>(policyValidators.Count);

		foreach (var policy in policyValidators) {
			policyRules.Add(new PolicyRuleTypeInfo(
				PolicyName: policy.PolicyName,
				PolicyType: policy.GetType(),
				Order: policy.Order,
				SupportedRuntimeTypes: policy.SupportedRuntimeTypes,
				IsAttributeBased: IsAttributeBasedPolicy(policy),
				TargetAttributeType: GetTargetAttributeType(policy),
				Description: GetPolicyDescription(policy)
			));
		}

		return policyRules.AsReadOnly();
	}

	#endregion

	#region Helpers

	private static string GetDomainBoundary(Type resourceType) {
		var resolved = DomainFeatureResolver.Resolve(resourceType);
		if (resolved is null) {
			return "Other";
		}
		return char.ToUpperInvariant(resolved[0]) + resolved[1..];
	}

	private static string GetResourceKind(Type resourceType) {
		var parts = resourceType.Namespace?.Split('.') ?? [];
		return parts.LastOrDefault() ?? "Unknown";
	}

	private static bool IsDomainObject(Type type) =>
		type.GetInterfaces().Any(i => i.Name == nameof(IDomainObject));

	private static bool IsAuthorizableObject(Type type) =>
		type.GetInterfaces().Any(i => i.Name == nameof(IAuthorizableObject));

	private static bool IsCacheableQuery(Type type) =>
		type.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ICacheableOperation<>));

	private static bool ImplementsAuthorizableOperation(Type type) =>
		type.GetInterfaces().Any(i => i.Name == nameof(IAuthorizableOperationBase));

	private static bool IsObjectAuthorizer(Type type) {
		if (type.BaseType?.IsGenericType == true &&
			type.BaseType.GetGenericTypeDefinition() == typeof(AuthorizerBase<>)) {
			return true;
		}
		return type.GetInterfaces()
			.Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IAuthorizer<>));
	}

	private static Type? GetResourceTypeFromAuthorizer(Type authorizerType) {
		if (authorizerType.BaseType?.IsGenericType == true &&
			authorizerType.BaseType.GetGenericTypeDefinition() == typeof(AuthorizerBase<>)) {
			return authorizerType.BaseType.GetGenericArguments()[0];
		}

		var validatorInterface = authorizerType.GetInterfaces()
			.FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IAuthorizer<>));

		return validatorInterface?.GetGenericArguments()[0];
	}

	private static bool IsAttributeBasedPolicy(IPolicyValidator policy) {
		var baseType = policy.GetType().BaseType;
		return baseType != null &&
			   baseType.IsGenericType &&
			   baseType.GetGenericTypeDefinition() == typeof(AttributeValidatorBase<>);
	}

	private static Type? GetTargetAttributeType(IPolicyValidator policy) {
		if (!IsAttributeBasedPolicy(policy)) {
			return null;
		}
		return policy.GetType().BaseType?.GetGenericArguments()[0];
	}

	private static string GetPolicyDescription(IPolicyValidator policy) {
		var type = policy.GetType();
		var description = type.GetCustomAttributes(typeof(System.ComponentModel.DescriptionAttribute), false)
			.Cast<System.ComponentModel.DescriptionAttribute>()
			.FirstOrDefault()?.Description;
		return description ?? $"Policy validator: {policy.PolicyName}";
	}

	private static List<AuthorizationRuleTypeInfo> ExtractValidationRules(Type resourceType, Type validatorType) {
		var rules = new List<AuthorizationRuleTypeInfo>();
		try {
			var validatorInstance = Activator.CreateInstance(validatorType);
			var descriptorMethod = validatorType.GetMethod("CreateDescriptor", BindingFlags.Instance | BindingFlags.Public);
			if (descriptorMethod != null && descriptorMethod.Invoke(validatorInstance, null) is IValidatorDescriptor descriptor) {
				var membersWithValidators = descriptor.GetMembersWithValidators();
				foreach (var propertyGroup in membersWithValidators) {
					var propertyPath = propertyGroup.Key;
					foreach (var (validator, options) in propertyGroup) {
						if (validator is null) {
							continue;
						}
						var validationLogic = GetValidationLogicDescription(validator);
						var message = options.GetUnformattedErrorMessage() ?? "Default error message";
						rules.Add(new AuthorizationRuleTypeInfo(
							resourceType,
							validatorType,
							propertyPath,
							validationLogic,
							message
						));
					}
				}

				foreach (var rule in descriptor.Rules) {
					if (rule is IIncludeRule) {
						rules.Add(new AuthorizationRuleTypeInfo(
							resourceType,
							validatorType,
							rule.PropertyName ?? "AuthorizationContext",
							"Included Validator",
							"References another validator"
						));

						var ruleType = rule.GetType();
						var validatorProperty = ruleType.GetProperty("Validator");
						if (validatorProperty != null) {
							var includedValidator = validatorProperty.GetValue(rule);
							if (includedValidator != null) {
								var includedValidatorType = includedValidator.GetType();
								rules[^1] = rules[^1] with {
									ValidationLogic = $"Included Validator: {includedValidatorType.Name}"
								};
							}
						}
					}
				}
			}
		} catch (Exception ex) {
			Debug.WriteLine($"Error extracting rules from validator {validatorType.Name}: {ex.Message}");
		}
		return rules;
	}

	private static string GetValidationLogicDescription(IPropertyValidator validator) {
		if (validator is INotNullValidator) {
			return "Not Null";
		}
		if (validator is INotEmptyValidator) {
			return "Not Empty";
		}
		if (validator is ILengthValidator lengthVal) {
			if (lengthVal.Max == int.MaxValue) {
				return $"Min Length: {lengthVal.Min}";
			}
			if (lengthVal.Min == 0) {
				return $"Max Length: {lengthVal.Max}";
			}
			return $"Length: {lengthVal.Min}-{lengthVal.Max}";
		}
		if (validator is IComparisonValidator compVal) {
			var comparisonType = compVal.Comparison.ToString();
			var valueToCompare = compVal.ValueToCompare?.ToString() ?? "null";
			return $"{comparisonType} {valueToCompare}";
		}
		if (validator is IRegularExpressionValidator regexVal) {
			return $"Regex: {regexVal.Expression}";
		}
		if (validator is IEmailValidator) {
			return "Email";
		}
		if (validator is IPredicateValidator) {
			return "Custom Predicate";
		}
		return ToDisplayName(validator.Name ?? validator.GetType().Name.Replace("Validator", ""));
	}

	private static string ToDisplayName(string name) {
		if (string.IsNullOrWhiteSpace(name)) {
			return name;
		}
		var sb = new System.Text.StringBuilder(name.Length + 10);
		for (var i = 0; i < name.Length; i++) {
			var current = name[i];
			var previous = i > 0 ? name[i - 1] : '\0';
			var next = i < name.Length - 1 ? name[i + 1] : '\0';
			if (i > 0 && char.IsUpper(current)) {
				if (char.IsLower(previous) ||
					char.IsDigit(previous) ||
					(char.IsUpper(previous) && char.IsLower(next))) {
					sb.Append(' ');
				}
			}
			if (i > 0 && char.IsDigit(current) && char.IsLetter(previous)) {
				sb.Append(' ');
			}
			sb.Append(i == 0 ? char.ToUpper(current) : char.ToLower(current));
		}
		return sb.ToString();
	}

	#endregion
}
