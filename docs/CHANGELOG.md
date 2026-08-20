# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.24] - 2026-08-20

### Updated

- Updated NuGet packages.

## [1.0.23] - 2026-08-19

### Updated

- Updated NuGet packages.

## [1.0.22] - 2026-08-17

### Updated

- Updated NuGet packages.

## [1.0.21] - 2026-08-04

### Updated

- Updated NuGet packages (Cirreum spine 4.2.0 wave: `Cirreum.Contracts` 4.2.0 / `Cirreum.Domain` 4.2.0 and current patch releases).

## [1.0.20] - 2026-07-31

### Updated

- Updated NuGet packages (Cirreum spine 4.0.1 wave: `Cirreum.Contracts` 4.0.1 / `Cirreum.Domain` 4.0.1 / `Cirreum.Kernel` 2.0.1 / `Cirreum.AuthenticationProvider` 2.0.3).

## [1.0.19] - 2026-07-30

### Fixed

- Adopted `Cirreum.Domain` 3.0.0's Stage 3 renames in the domain model: policy rules are read
  from `IPolicyAuthorizer` (was `IPolicyValidator`) and attribute-based policies are detected via
  `AttributePolicyAuthorizerBase<>` (was `AttributeValidatorBase<>`). Model shape
  (`PolicyRuleTypeInfo`) is unchanged; policy descriptions now read "Policy authorizer: …".

### Updated

- Re-pinned `Cirreum.Domain` `2.0.0` → `3.0.0` (restores operation-authorization enforcement;
  carries the `IPolicyAuthorizer` rename).

## [1.0.18] - 2026-07-30

### Fixed

- `AuthorizableOperationAnalyzer` no longer raises the **Error** "operation(s) implement `IAuthorizableOperationBase` but have no authorizer defined" for grant- and self-scoped operations (any `IGrantable*` implementor, e.g. `ISelfLookupOperation<User>`). Those operations are authorized by the grant pipeline's Phase 1 — owner-scope grant resolution or self identity matching (`ExternalId == UserId`) — not by an `IAuthorizer<T>`, so their absence of an authorizer is by design, not an enforcement gap. The check now excludes `IsGranted` operations (`AnalyzeUnprotectedOperations`). Previously a correctly-designed grants-only/self domain failed `ValidateAuthorizationConfiguration` at startup, even though `GrantedOperationAnalyzer` (check 3) reported the identical operations at **Info** with "if grants-only authorization is intentional, this can be safely ignored" — a direct contradiction, the same class of cross-analyzer conflict resolved for the sibling analyzer in 1.0.11. Grant- and self-scoped operations without an operation authorizer remain reported by `GrantedOperationAnalyzer` at Info severity. Plain `IAuthorizableOperation<T>` types with no authorizer and no grant participation are still flagged as Errors.

## [1.0.17] - 2026-07-27

### Updated

- Updated NuGet packages.

## [1.0.16] - 2026-07-24

### Updated

- Updated NuGet packages.

## [1.0.15] - 2026-07-24

### Updated

- Updated NuGet packages.

## [1.0.14] - 2026-07-20

### Updated

- Updated NuGet packages.

## [1.0.12] - 2026-07-19

### Updated

- Updated NuGet packages.

## [1.0.11] - 2026-07-11

### Fixed

- `GrantedOperationAnalyzer` no longer reports self-scoped operations in the "granted operations without `[RequiresGrant]`" **Warning** (check 1). Self-scoped operations enforce access via identity matching (`ExternalId == UserId`), so a missing permission gate is not an enforcement gap — check 1 previously contradicted check 7's Info-severity "permissions are optional" guidance for the identical operations, and its recommendation to add `[RequiresGrant]` would break onboarding/first-grant flows. Self-scoped operations without permissions remain reported by checks 6 and 7 at Info severity. The `MissingPermissionCount` metric follows the corrected (owner-scoped) set.

## [1.0.10] - 2026-07-07

### Updated

- Updated NuGet packages (`Cirreum.Domain` 1.2.4 → 1.2.5).

## [1.0.9] - 2026-07-05

### Updated

- Updated NuGet packages (`Cirreum.Domain` 1.2.0 → 1.2.4).

## [1.0.8] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.7] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.6] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.5] - 2026-05-10

### Updated

- Updated NuGet packages.

## [1.0.4] - 2026-05-07

### Updated

- Updated NuGet packages.

## [1.0.3] - 2026-05-01

### Updated

- Updated NuGet packages.

## [1.0.2] - 2026-04-29

### Fixed

- **`DomainDocumenter` HTML/Markdown/CSV output now surfaces grants and
  authorization constraints as first-class sections, and the HTML tab order
  follows the authorization pipeline.** Previously the grant and constraint
  topologies were only visible *implicitly* via the Security Analysis tab
  (when an analyzer flagged a finding); the data was always present in
  `IDomainModel` but never rendered.
  - **HTML:** new "Grants" and "Constraints" tabs in `RenderHtmlPage`. The
    Grants tab groups granted operations by `GrantDomain`, shows the union
    of permissions per domain, and flags missing `IOperationGrantProvider`
    registration. The Constraints tab lists `IAuthorizationConstraint`
    registrations in execution order. The "Operation Rules" tab is renamed
    to **"Operations"** for parity with the other phase-named tabs. Tab
    order is now: Overview → Domain Architecture → Grants → Constraints →
    Operations → Policies → Roles → Security Analysis. Tab-button selection
    in the JS now uses a `data-tab` attribute instead of fragile text
    matching.
  - **Markdown:** new `## Authorization Constraints` and `## Grants` sections
    in `GenerateMarkdown`, with tables per grant domain.
  - **CSV:** new `## CONSTRAINTS` and `## GRANTS` sections in `GenerateCsv`,
    one row per constraint / granted operation.

- **Vocabulary aligned with Cirreum.Core 3.x/4.x — `Resource` → `Operation`**
  for all references to `IDomainObject` / `IAuthorizableObject`. In Core's
  current vocabulary, the *operation* (the command/query/event) is the verb,
  and the data it works on is the *resource*. The introspection package
  hadn't caught up — analyzer categories, model methods, type names, metric
  prefixes, and HTML/Markdown/CSV output all said "Resource" where they
  meant "Operation". Now they all say "Operation". `IProtectedResource`,
  `IResourceAccessEvaluator`, `IAccessEntryProvider`, and the Object-Level
  ACL analyzer keep "Resource" because that *is* genuinely a Resource
  (an object-level ACL target). **Source-breaking** for any caller that
  used these renamed types/methods/properties; see migration table in
  `RELEASE-NOTES-v1.0.2.md`.
- **`IDomainDocumenter` render methods now work uniformly across all call
  contexts (Blazor WASM, API request handlers, CLI hosts, hosted services).**
  The optional `IServiceProvider?` parameter on `GenerateMarkdown`,
  `GenerateCsv`, and `RenderHtmlPage` has been removed; passing `null`
  silently produced a half-rendered page (no analysis section, broken tabs).
  The documenter now takes `(IDomainModel, IDomainEnvironment,
  IServiceScopeFactory)` and opens its own transient scope per call. **Source
  break:** callers passing a provider explicitly must drop the argument.
- **`IAuthorizationRoleRegistry` resolved lazily at render time** rather than
  at documenter construction. Mirrors the pattern `IDomainModel` already uses
  for its DI-derived snapshots — the singleton holds an `IServiceScopeFactory`
  and resolves what it needs per-call. Defensive against any future startup-
  ordering edge cases (e.g. a consumer that resolves `IDomainDocumenter`
  unusually early via `IServiceProviderFactory` callbacks) and consistent with
  how the rest of the package handles DI.
- **HTML page-frame trailer (script + closing tags) was being skipped on the
  analysis-unavailable path,** breaking tab switching. The trailer is now
  emitted unconditionally via a shared `AppendHtmlTrailer` helper. The
  analysis-unavailable code path is gone entirely — the documenter can always
  render analysis because it can always open its own scope.
- **`DomainSnapshot.Capture` now opens its own defensive scope** rather than
  resolving directly from the supplied `IServiceProvider`, matching the
  pattern used by `Validate*` / `Check*` / `Analyze*` extensions. Behavior is
  unchanged today (all introspection-graph services are singleton); the
  change makes the snapshot robust to future scoped services in the graph.
- **README startup-validation example uses `IHostedService.StartAsync`.**
  Both `IStartupTask` and `IHostedService.StartAsync` run after the runtime's
  `IAutoInitialize` pass, so either works for `ValidateAuthorizationConfiguration`.
  `IHostedService.StartAsync` is preferred because it runs *after*
  `ApplicationStarted` fires — fully initialized, including any side effects
  from `IStartupTask` execution — and is the standard ASP.NET Core extension
  point for "run this once when the app comes up."

`AddIntrospection()` registration is unchanged. `IDomainDocumenter` remains a
`TryAddSingleton`; the new constructor is naturally singleton-safe.

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
