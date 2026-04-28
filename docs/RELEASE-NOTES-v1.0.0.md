# Cirreum.Introspection 1.0.0 — Initial release

Domain introspection for Cirreum applications, extracted into its own opt-in
package. Reflective domain model, analyzer suite, `DomainDocumenter`, and
`DomainSnapshot` exporter — all the pieces that previously lived under
`Cirreum.Core/Introspection/**` are now here, namespace-compatible
(`Cirreum.Introspection.*`), with a clean DI story baked in.

## Why this package exists

The introspection subsystem was originally part of `Cirreum.Core`. Two failures
in the Core 4.0.0 / 4.0.1 line traced to the same root cause: introspection
types holding onto an `IServiceProvider`. The `4.0.0` release of
`ValidateAuthorizationConfiguration` resolved scoped services from the root
provider and tripped scope validation in ASP.NET Core hosts. The `4.0.1` patch
wrapped the resolution in a scope, but a singleton `DomainModel.Instance`
retained that scoped provider and threw `ObjectDisposedException` on the next
consumer. Each fix produced a new failure mode because the bug class was
structural, not local.

The decision was a cancel-and-replace: extract introspection into its own
package, redesign so no type retains an `IServiceProvider`, and ship Core 4.0.2
as the real 4.0. This package is the result of that extraction.

## Architectural principle

> **No introspection type retains `IServiceProvider`.**

`IDomainModel` is a singleton that holds an `IServiceScopeFactory`
(singleton-safe). DI-derived data — `IPolicyValidator` registrations,
`IAuthorizationConstraint` types, `IAccessEntryProvider<T>` registrations —
is resolved through a transient scope on first access, snapshotted into
immutable structures, and the scope is disposed. Reflection-derived data
(resources, rules, catalog, protected resource types) is cached via `Lazy<T>`.
Repeated calls are pointer reads against immutable snapshots. There is no
`Initialize` step and no public refresh path.

Each analyzer takes only the dependencies it actually uses. Where the old
analyzers took `IServiceProvider` and dipped into it lazily, the new ones take
`IDomainModel` and the explicit services they need (`IDomainEnvironment` for
the policy validator analyzer, etc.). The analyzer factory
(`DomainAnalyzerProvider.CreateAnalyzer`) consumes the supplied
`IServiceProvider` eagerly to wire up these dependencies, then discards it.

## Public surface

### Registration

```csharp
builder.Services.AddIntrospection();
```

Registers `IDomainModel` and `IDomainDocumenter` as singletons via
`TryAddSingleton`, so consumers can substitute test doubles or alternative
implementations.

### `IServiceProvider` extensions — same shape across all runtimes

```csharp
// Throws AuthorizationConfigurationException on Error-severity findings.
app.Services.ValidateAuthorizationConfiguration();

// Returns the report only when validation failed; null on pass.
var failing = app.Services.CheckAuthorizationConfiguration();

// Always returns the full report.
var report = app.Services.AnalyzeAuthorization();
```

Each opens a defensive `using var scope = services.CreateScope()` so scoped
services in the introspection graph resolve under .NET's default
scope-validation mode. The scope is consumed within the call and not
retained. One scope allocation per call; trivial cost.

### Documenter

```csharp
public class DomainDocumenter(
    IAuthorizationRoleRegistry roleRegistry,
    IDomainModel domainModel,
    IDomainEnvironment domainEnvironment
) : IDomainDocumenter { ... }

public interface IDomainDocumenter {
    string GenerateMarkdown(IServiceProvider? services = null);
    string GenerateCsv(IServiceProvider? services = null);
    string RenderHtmlPage(IServiceProvider? services = null);
}
```

The optional `IServiceProvider?` parameter on each render method is consumed
only when the analyzer-driven sections are requested; passing `null` skips
those sections and uses just the model and environment. The provider is used
eagerly and not retained.

### Snapshot exporter

```csharp
DomainSnapshot.Capture(roleRegistry, serviceProvider, options?);
```

Returns a serializable point-in-time snapshot: catalog, analysis report,
analysis summary, role hierarchy, grant domains, and Mermaid diagrams for
the authorization flow and role tree. Suitable for transport to a WASM
admin client, persistence, or cross-runtime comparison. `Capture` opens its
own defensive scope; callers may pass any provider.

### Analyzer suite

`AuthorizationRuleAnalyzer`, `RoleHierarchyAnalyzer`,
`AnonymousResourceAnalyzer`, `GrantedResourceAnalyzer`,
`AuthorizableResourceAnalyzer`, `AuthorizationConstraintAnalyzer`,
`PolicyValidatorAnalyzer`, `ProtectedResourceAnalyzer`. Each constructable
directly via its public constructor with explicit dependencies, or composed
through `DomainAnalyzerProvider.CreateAnalyzer` for the standard suite plus
optional category filtering via `AnalysisOptions.ExcludedCategories`.

## Why no shipped `IAutoInitialize` / `IStartupTask` / `ISystemInitializer`

Cirreum's startup conventions auto-discover and run these. If
`Cirreum.Introspection` shipped one, every consumer that referenced the
package would get auto-validation — wrong default. Consumers compose policy
themselves:

```csharp
// ISystemInitializer-flavored
internal sealed class ValidateAuthOnStart : ISystemInitializer {
    public ValueTask RunAsync(IServiceProvider serviceProvider) {
        serviceProvider.ValidateAuthorizationConfiguration();
        return ValueTask.CompletedTask;
    }
}

// IStartupTask-flavored
internal sealed class ValidateAuthOnStart(IServiceProvider serviceProvider)
    : IStartupTask {
    public int Order => 100;
    public ValueTask ExecuteAsync() {
        serviceProvider.ValidateAuthorizationConfiguration();
        return ValueTask.CompletedTask;
    }
}
```

Or wire to an admin endpoint, integration test, debug-only init — the
library provides the model and the runners; the consumer chooses the
policy.

## Migration from in-Core introspection

For apps coming from `Cirreum.Core` 3.x or 4.0.0 / 4.0.1:

```diff
+ <PackageReference Include="Cirreum.Introspection" Version="1.0.0" />
```

```csharp
// Registration
- builder.Services.AddDefaultDomainDocumenter();
+ builder.Services.AddIntrospection();   // registers IDomainModel + IDomainDocumenter

// Validation call sites
- app.ValidateAuthorization();                         // Server member method (removed)
+ app.Services.ValidateAuthorizationConfiguration();   // IServiceProvider extension

// Direct model access (rare)
- DomainModel.Instance.GetAllResources();              // singleton accessor (removed)
+ services.GetRequiredService<IDomainModel>().GetAllResources();
```

Namespaces are unchanged (`Cirreum.Introspection.*`), so `using` statements
stay the same.

## Requirements

- **`Cirreum.Core 4.0.2` or later.** The `4.0.2` release of Core promotes
  `Cirreum.DomainFeatureResolver` to `public`; this package depends on it
  across the assembly boundary. Earlier 4.x releases will not compile against
  this package.
- .NET 10.

## Related

- [`Cirreum.Core` release notes for 4.0.2](https://github.com/cirreum/Cirreum.Core/blob/main/docs/RELEASE-NOTES-v4.0.2.md)
  — full architectural rationale, the introspection extraction story, and the
  migration table.
- [`Cirreum.Runtime.Server`] — companion patch release that removes the
  `app.ValidateAuthorization()` and `app.AnalyzeAuthorization()` member
  methods now that the same calls live on `IServiceProvider`.
