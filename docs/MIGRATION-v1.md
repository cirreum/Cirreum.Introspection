# Migration to Cirreum.Introspection v1

`Cirreum.Introspection 1.0.0` is the initial release of this package. There
is no prior version of `Cirreum.Introspection` to migrate from.

If you are coming from an earlier setup, the relevant migration is **out of
the in-`Cirreum.Core` introspection subsystem**, which lived under
`Cirreum.Core/Introspection/**` in Core 3.x and 4.0.0 / 4.0.1, and was removed
in Core 4.0.2.

## Prerequisites

- `Cirreum.Core 4.0.2` or later.
  The 4.0.2 release of Core promotes `Cirreum.DomainFeatureResolver` to
  `public`; this package depends on it across the assembly boundary. Earlier
  4.x releases will not compile against `Cirreum.Introspection 1.0.0`.

## Add the package

```diff
+ <PackageReference Include="Cirreum.Introspection" Version="1.0.0" />
```

Namespaces are unchanged from the old in-Core layout (`Cirreum.Introspection.*`),
so existing `using` statements continue to work.

## Substitutions

```csharp
// Registration
- builder.Services.AddDefaultDomainDocumenter();
+ builder.Services.AddIntrospection();   // registers IDomainModel + IDomainDocumenter

// Validation
- app.ValidateAuthorization();                         // Cirreum.Runtime.Server member method (removed)
+ app.Services.ValidateAuthorizationConfiguration();   // IServiceProvider extension

// Analysis
- app.AnalyzeAuthorization();                          // Cirreum.Runtime.Server member method (removed)
+ app.Services.AnalyzeAuthorization();

// Direct model access (rare)
- DomainModel.Instance.GetAllResources();              // singleton accessor (removed)
+ services.GetRequiredService<IDomainModel>().GetAllResources();
```

The `IServiceProvider` extensions (`Validate*` / `Check*` / `Analyze*`) work
identically across Server, Serverless, and WASM runtimes — there is no
runtime-specific call site to update.

## Architectural change to be aware of

In the old in-Core design, `DomainModel.Instance.Initialize(IServiceProvider)`
required an explicit init step that retained the supplied provider. That step
is gone:

- `IDomainModel` is registered by `AddIntrospection()` and resolved through
  DI as `IDomainModel`.
- The model holds an `IServiceScopeFactory`, not a captured provider; DI-
  derived data is snapshotted lazily on first access through transient scopes.
- There is no public `Initialize` method and no public refresh path.

If your code held onto a `DomainModel.Instance` reference or called
`Initialize` directly, replace those references with constructor-injected
`IDomainModel` and remove the init calls.

## Custom analyzers / documenters

If you implemented custom analyzers or a custom `IDomainDocumenter` against
the old in-Core types:

- Constructor signatures changed. Analyzers no longer take `IServiceProvider`
  and instead take only the dependencies they consume (typically `IDomainModel`,
  optionally `IDomainEnvironment` or `IAuthorizationRoleRegistry`). See the
  built-in analyzers under [src/Cirreum.Introspection/Analyzers/](../src/Cirreum.Introspection/Analyzers/)
  for the current shape.
- `DomainDocumenter` ctor is now
  `(IAuthorizationRoleRegistry, IDomainModel, IDomainEnvironment)`. The
  `IDomainDocumenter` interface methods accept an optional `IServiceProvider?`
  only when generating analyzer-driven sections.

## Further reading

- [RELEASE-NOTES-v1.0.0.md](RELEASE-NOTES-v1.0.0.md) — full rationale,
  public surface, and consumer examples.
- [Cirreum.Core RELEASE-NOTES-v4.0.2.md](https://github.com/cirreum/Cirreum.Core/blob/main/docs/RELEASE-NOTES-v4.0.2.md)
  — extraction story and the architectural principle (no introspection type
  retains `IServiceProvider`).
