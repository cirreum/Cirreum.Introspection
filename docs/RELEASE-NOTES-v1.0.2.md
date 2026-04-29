# Cirreum.Introspection 1.0.2 — Documenter ergonomics + startup ordering

This release tightens the consumer surface for `IDomainDocumenter` based on
real-world use, fixes a tab-rendering bug in the HTML output, and corrects the
startup-validation guidance that was leading consumers to false negatives.

## Why this release exists

Five things came up the first time the package was actually consumed:

1. **The `IServiceProvider?` parameter on `RenderHtmlPage` / `GenerateMarkdown`
   / `GenerateCsv` was easy to miss.** Calling `RenderHtmlPage()` with no args
   produced a half-rendered page (no analysis section, broken tabs) instead of
   either a full page or a loud failure.
2. **The HTML output's `<script>` block was conditional on the analysis path.**
   When the documenter took the "no service provider" branch, it bailed before
   emitting the JavaScript that drives tab switching and Mermaid initialization.
   The visual page was structurally complete but functionally broken.
3. **The introspection vocabulary was out of step with Cirreum.Core 3.x/4.x.**
   In Core's current model, the *operation* (the command/query/event — anything
   implementing `IDomainObject` or `IAuthorizableObject`) is the verb; the
   data the operation works with is the *resource*. The introspection package
   was still calling operations "Resources" everywhere — analyzer categories,
   model methods, public type names, metric prefixes, and the HTML / Markdown
   / CSV output. Confusing for anyone reading the report next to Core docs.

4. **The HTML/Markdown/CSV report had no first-class view of grants or
   authorization constraints.** Both topologies were only visible
   *implicitly* via Security Analysis findings — i.e. you only saw the data
   when an analyzer flagged a problem. The fact that 12 operations were
   granted across 3 domains, or that 2 `IAuthorizationConstraint`
   implementations ran before everything else, was nowhere on the report.

5. **The v1.0.0 README's startup-validation example used `IStartupTask`,**
   which works (the Cirreum startup pipeline runs
   `ISystemInitializer` → `IAutoInitialize` → `IStartupTask`, so the registry
   is populated by the time `IStartupTask` runs) but isn't the strongest
   guidance for "validate the configuration once at app startup." The
   `IHostedService.StartAsync` extension point runs after `ApplicationStarted`
   fires — fully-initialized state, post-`IStartupTask` — and is the standard
   ASP.NET Core idiom for that lifecycle moment.

This release addresses all three with a single coherent change.

## Architectural change

The documenter now follows the same pattern `IDomainModel` already uses
internally: it injects an `IServiceScopeFactory` (singleton-safe), opens a
transient scope per render call, resolves what it needs (most importantly
`IAuthorizationRoleRegistry`) inside that scope, and disposes the scope before
returning. No `IServiceProvider` is retained.

Two consequences fall out of this:

- **Render methods are parameterless.** `GenerateMarkdown()`, `GenerateCsv()`,
  and `RenderHtmlPage()` no longer take an `IServiceProvider?`. The same call
  works from any context — Blazor WASM component, API request handler, CLI
  host, integration test — because the documenter handles its own DI access.
- **Startup ordering is no longer an issue.** Because the registry is resolved
  lazily at render time rather than at construction, the documenter is robust
  to *when* it's first used. The first render after app start sees a populated
  registry; so does the hundredth render ten minutes later.

## Public surface change

```diff
  public interface IDomainDocumenter {
-     string GenerateMarkdown(IServiceProvider? services = null);
-     string GenerateCsv(IServiceProvider? services = null);
-     string RenderHtmlPage(IServiceProvider? services = null);
+     string GenerateMarkdown();
+     string GenerateCsv();
+     string RenderHtmlPage();
  }
```

Constructor:

```diff
  public class DomainDocumenter(
-     IAuthorizationRoleRegistry roleRegistry,
      IDomainModel domainModel,
-     IDomainEnvironment domainEnvironment
+     IDomainEnvironment domainEnvironment,
+     IServiceScopeFactory scopeFactory
  ) : IDomainDocumenter
```

`AddIntrospection()` registration is unchanged — `IDomainDocumenter` is still
a `TryAddSingleton`. The new constructor is naturally singleton-safe.

## New report sections — Grants, Constraints, and pipeline-ordered tabs

The HTML output now has eight tabs ordered to follow the authorization
pipeline:

| # | Tab | What it shows |
|---|---|---|
| 1 | Overview | Authorization-flow Mermaid diagram |
| 2 | Domain Architecture | `DomainCatalog` + Anonymous-Operation findings |
| 3 | Grants | Granted operations grouped by `GrantDomain` (new) |
| 4 | Constraints | `IAuthorizationConstraint` registrations in order (new) |
| 5 | Operations | Per-operation authorization rules (renamed from "Operation Rules") |
| 6 | Policies | Policy validators (renamed from "Policy Validators") |
| 7 | Roles | Role hierarchy + Mermaid tree |
| 8 | Security Analysis | Full `analysisReport.Issues` |

The "Operations" rename mirrors the other phase-named tabs (Grants /
Constraints / Policies / Roles), and tab-button selection in the JS now
uses a `data-tab` attribute on each button rather than the previous
text-substring heuristic — robust against future renames.

The two new tabs surface data that was already in `IDomainModel` but had
no dedicated view:

**Constraints tab** — `IAuthorizationConstraint` implementations in
registration order (Phase 1, Step 2 of the pipeline). Each constraint can
short-circuit the pipeline before any policy or operation authorizer runs;
typical uses are global maintenance mode, tenant suspension, IP allow-list,
etc. The tab shows the type name, fully-qualified name, and namespace per
constraint, plus a count summary card.

**Grants tab** — granted operations (Phase 1, Step 1) grouped by
`GrantDomain`. Per domain: the union of declared permissions across the
group, then a per-operation table with kind (Self/Mutate/Lookup/Search),
permissions, and authorizer. Summary cards at the top show total granted
operations, grant domains, distinct permissions, and whether
`IOperationGrantProvider` is registered (red if missing, since grant
evaluation cannot run without it).

Matching sections were added to the Markdown (`## Authorization Constraints`,
`## Grants`) and CSV (`## CONSTRAINTS`, `## GRANTS`) outputs so all three
render targets stay in parity.

## Vocabulary alignment — `Resource` → `Operation`

Renamed to match Cirreum.Core's current "operations operate on resources"
model. **`IProtectedResource`, `IResourceAccessEvaluator`, `IAccessEntryProvider`,
the Object-Level ACL analyzer, and the `Cirreum.Authorization.Resources`
namespace are unchanged** — those genuinely refer to Resources (the data
that object-level ACLs gate access to).

| Before | After |
|---|---|
| `ResourceTypeInfo` | `OperationTypeInfo` |
| `ResourceInfo` | `OperationInfo` |
| `ResourceKind` | `OperationKind` |
| `AnonymousResourceAnalyzer` | `AnonymousOperationAnalyzer` |
| `AuthorizableResourceAnalyzer` | `AuthorizableOperationAnalyzer` |
| `GrantedResourceAnalyzer` | `GrantedOperationAnalyzer` |
| `IDomainModel.GetAllResources()` | `IDomainModel.GetAllOperations()` |
| `IDomainModel.GetAnonymousResources()` | `IDomainModel.GetAnonymousOperations()` |
| `IDomainModel.GetAuthorizableResources()` | `IDomainModel.GetAuthorizableOperations()` |
| `OperationTypeInfo.ResourceType` (Type) | `OperationTypeInfo.OperationType` |
| `OperationTypeInfo.ResourceKind` (string) | `OperationTypeInfo.OperationKind` |
| `OperationInfo.ResourceName` | `OperationInfo.OperationName` |
| `OperationInfo.ResourceFullName` | `OperationInfo.OperationFullName` |
| `OperationKind.Resources` (collection) | `OperationKind.Operations` |
| `DomainCatalog.AllResources` | `DomainCatalog.AllOperations` |
| `CatalogMetrics.TotalResources` | `CatalogMetrics.TotalOperations` |
| `CatalogMetrics.ProtectedResources` | `CatalogMetrics.ProtectedOperations` |
| `CatalogMetrics.AnonymousResources` | `CatalogMetrics.AnonymousOperations` |
| `AuthorizationRuleInfo.ResourceTypeName` | `AuthorizationRuleInfo.OperationTypeName` |
| `AuthorizationRuleInfo.ResourceTypeFullName` | `AuthorizationRuleInfo.OperationTypeFullName` |
| `CombinedRuleTypeInfo.ResourceRules` | `CombinedRuleTypeInfo.OperationRules` |
| `MetricCategories.AnonymousResources` | `MetricCategories.AnonymousOperations` |
| `MetricCategories.AuthorizableResources` | `MetricCategories.AuthorizableOperations` |
| `MetricCategories.GrantedResources` | `MetricCategories.GrantedOperations` |
| Analyzer category `"Anonymous Resources"` | `"Anonymous Operations"` |
| Analyzer category `"Authorizable Resources"` | `"Authorizable Operations"` |
| Analyzer category `"Granted Resources"` | `"Granted Operations"` |

User-facing strings in Markdown / CSV / HTML reports are renamed alongside
("Total Resources" → "Total Operations", "Resource:" → "Operation:",
"Resource-Role Matrix" → "Operation-Role Matrix", etc.).

## Migration

For any caller passing a service provider explicitly, drop the argument:

```diff
- string html = documenter.RenderHtmlPage(app.Services);
+ string html = documenter.RenderHtmlPage();
```

If you were constructing a `DomainDocumenter` manually (e.g. in tests), inject
an `IServiceScopeFactory` and drop the registry:

```diff
- var documenter = new DomainDocumenter(roleRegistry, domainModel, domainEnvironment);
+ var documenter = new DomainDocumenter(domainModel, domainEnvironment, scopeFactory);
```

The simplest test-time `IServiceScopeFactory` is the one Microsoft DI exposes
on any `IServiceProvider`:

```csharp
var scopeFactory = serviceProvider.GetRequiredService<IServiceScopeFactory>();
var documenter = new DomainDocumenter(domainModel, domainEnvironment, scopeFactory);
```

## Startup-validation guidance — preferred shape

The Cirreum startup pipeline runs in this order:

```
ISystemInitializer  →  IAutoInitialize  →  IStartupTask  →  ApplicationStarted  →  IHostedService.StartAsync
```

The role registry, policy validators, authorization constraints, and grant
providers are populated by `IAutoInitialize`, so any call site downstream of
that pass — `IStartupTask`, `IHostedService.StartAsync`, request handlers,
admin endpoints — observes a fully-populated graph and works correctly.

The recommended shape is `IHostedService.StartAsync`, because it runs after
`ApplicationStarted` fires (the cleanest "fully-initialized" signal,
including any side effects from `IStartupTask` execution) and is the standard
ASP.NET Core extension point for "run this once when the app comes up":

```csharp
internal sealed class ValidateAuthOnStart(IServiceProvider services) : IHostedService {
    public Task StartAsync(CancellationToken ct) {
        services.ValidateAuthorizationConfiguration();   // throws on Error severity
        return Task.CompletedTask;
    }
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
```

Register:

```csharp
builder.Services.AddHostedService<ValidateAuthOnStart>();
```

`IStartupTask` is also a valid call site if you prefer that idiom; both run
post-`IAutoInitialize`. The pre-`IAutoInitialize` extension points
(`ISystemInitializer`, `IAutoInitialize` itself) are not, since the registry
is being built during that phase.

This applies to any call to `Validate*` / `Check*` / `Analyze*`, not just
the documenter.

## Other fixes in this release

### HTML trailer was being skipped on the analysis-unavailable path

`RenderHtmlPage` had an early return when `services` was null that emitted the
"Analysis unavailable" notice but bailed *before* the trailing
`<script>...</script>` block. Tab switching and Mermaid (re)initialization
both live in that block, so the resulting page rendered visually but was
functionally inert. With render methods now parameterless and the documenter
always able to run analysis, this code path is gone — but the script-emitting
trailer is also extracted into a private `AppendHtmlTrailer` helper called
from a single point, so any future early-exit paths can't reintroduce the bug.

### `DomainSnapshot.Capture` now opens its own defensive scope

For consistency with the `IServiceProvider` extensions (`Validate*` / `Check*`
/ `Analyze*`), `DomainSnapshot.Capture` now wraps its work in
`using var scope = serviceProvider.CreateScope()`. Behavior is unchanged
today — every service in the introspection graph is singleton — but the
snapshot is now robust to future scoped services entering the graph.

## Compatibility

- **Source break** — any caller passing an `IServiceProvider` to a
  `IDomainDocumenter` method must drop the argument. All other consumers
  (just calling the documenter parameterless from a request handler or
  component, or using the `IServiceProvider` extensions for validation) need
  no change.
- **Binary-compatible at the runtime level** — same package on NuGet, same
  registration, same singleton lifetime. The break is purely at the API
  signature.
- Requires `Cirreum.Core 4.0.2` or later (unchanged from v1.0.0).
