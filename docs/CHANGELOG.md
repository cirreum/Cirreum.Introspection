# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-04-28

### Fixed

- **Publish workflow filename typo.** `.github/workflows/publish.yml` referenced
  `Cirreum.Cirreum.Introspection.slnx` (doubled prefix) instead of
  `Cirreum.Introspection.slnx`, causing the v1.0.0 GitHub Action to fail at
  the `dotnet restore` step and never publish the package to NuGet. No 1.0.0
  artifact was uploaded; 1.0.1 is the first published release.

## [1.0.0] - 2026-04-28

Initial release. Extraction of the introspection subsystem from `Cirreum.Core`
into a dedicated, opt-in package. Architectural cleanup baked in: no type retains
`IServiceProvider`, eliminating the captured-scope failure mode that affected
pre-extraction Core 4.0.0 / 4.0.1.

### Added

- **`IDomainModel` singleton** — reflective domain model with three cache flavors:
  eager (`IServiceScopeFactory` ctor parameter), lazy reflection-derived
  (`_resources`, `_rules`, `_catalog`, protected resource types), and lazy
  DI-derived snapshots (`_policyRules`, `_constraintTypes`,
  access-entry-provider registrations). DI snapshots are taken once through a
  transient scope and released; the singleton holds only immutable data.
- **`AddIntrospection()` extension on `IServiceCollection`** — registers
  `IDomainModel` and `IDomainDocumenter` as singletons via `TryAddSingleton`,
  so consumers can substitute test doubles or alternative implementations.
- **`IServiceProvider` extensions** — `ValidateAuthorizationConfiguration()`
  (throws `AuthorizationConfigurationException` on Error severity),
  `CheckAuthorizationConfiguration()` (returns the report only when validation
  fails; `null` on pass), and `AnalyzeAuthorization()` (always returns the full
  report). Each opens a defensive scope so scoped services in the introspection
  graph resolve under .NET's default scope validation. Same call shape across
  Server, Serverless, and WASM runtimes.
- **Analyzer suite** — `AuthorizationRuleAnalyzer`, `RoleHierarchyAnalyzer`,
  `AnonymousResourceAnalyzer`, `GrantedResourceAnalyzer`,
  `AuthorizableResourceAnalyzer`, `AuthorizationConstraintAnalyzer`,
  `PolicyValidatorAnalyzer`, `ProtectedResourceAnalyzer`. Each takes only the
  explicit dependencies it consumes; none retains `IServiceProvider`.
- **`DomainAnalyzerProvider.CreateAnalyzer(roleRegistry, domainModel, services, options?)`**
  — eager dependency resolution, no provider retention. Honors
  `AnalysisOptions.ExcludedCategories` to filter analyzers.
- **`DomainDocumenter`** — Markdown, CSV, and standalone HTML rendering of the
  domain. Ctor takes `(IAuthorizationRoleRegistry, IDomainModel, IDomainEnvironment)`.
  Each render method accepts an optional `IServiceProvider?` only when generating
  the analyzer-driven sections; the provider is used eagerly and not retained.
- **`DomainSnapshot.Capture(roleRegistry, serviceProvider, options?)`** —
  serializable point-in-time export of the domain model, analysis report,
  catalog, role hierarchy, grant domains, and Mermaid diagrams.
- **No shipped `IAutoInitialize` / `IStartupTask` / `ISystemInitializer`.**
  Consumers compose their own startup, admin-endpoint, or test-time policy
  (examples in the README).

### Notes

- Requires `Cirreum.Core 4.0.2` or later. The 4.0.2 release of Core promotes
  `Cirreum.DomainFeatureResolver` to `public`; this package depends on it across
  the assembly boundary.
- Migration from in-Core introspection (Core 3.x and 4.0.0 / 4.0.1) is documented
  in [Cirreum.Core RELEASE-NOTES-v4.0.2.md](https://github.com/cirreum/Cirreum.Core/blob/main/docs/RELEASE-NOTES-v4.0.2.md).
  Common substitutions:
  - `services.AddDefaultDomainDocumenter()` → `services.AddIntrospection()`
  - `app.ValidateAuthorization()` (Runtime.Server member method, removed) →
    `app.Services.ValidateAuthorizationConfiguration()`
  - `DomainModel.Instance` (removed) →
    `services.GetRequiredService<IDomainModel>()`
