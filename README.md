# Cirreum.Introspection

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Introspection.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Introspection/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Introspection.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Introspection/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Introspection?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Introspection/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Introspection?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Introspection/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Reflective domain model and authorization analysis for Cirreum applications.**

## Overview

**Cirreum.Introspection** provides a reflection-derived domain model, a suite of analyzers that inspect authorization configuration, and a `DomainDocumenter` that emits human-readable reports from a live Cirreum application.

This package is opt-in. Apps reference it only when they want to validate, document, or analyze their domain. None of the runtime packages (`Cirreum.Runtime.Server`, `Cirreum.Runtime.Serverless`, `Cirreum.Runtime.Wasm`) depend on it.

### Install

```
dotnet add package Cirreum.Introspection
```

### Register

```csharp
builder.Services.AddIntrospection();
```

`AddIntrospection` registers `IDomainModel` and `IDomainDocumenter` as singletons via `TryAddSingleton`, so consumers can substitute test doubles or alternative implementations.

### Use

The package surfaces three extensions on `IServiceProvider` — usable from any runtime, any host:

```csharp
// Throws AuthorizationConfigurationException on Error-level findings.
app.Services.ValidateAuthorizationConfiguration();

// Returns the full report only if validation failed; null on pass.
var failing = app.Services.CheckAuthorizationConfiguration();

// Always returns the full analysis report.
var report = app.Services.AnalyzeAuthorization();
```

#### Startup validation (consumer-authored)

The library deliberately ships no `ISystemInitializer` / `IAutoInitialize` / `IStartupTask`. If every consumer that referenced the package got auto-validation, that would be the wrong default. Compose your own policy:

#### ISystemInitializer

```csharp
internal sealed class ValidateAuthOnStart : ISystemInitializer {
	public ValueTask RunAsync(IServiceProvider serviceProvider) {
		sp.ValidateAuthorizationConfiguration();
		return ValueTask.CompletedTask;
	}
}
```

#### IStartupTask

```csharp
internal sealed class ValidateAuthOnStart(
	IServiceProvider serviceProvider
) : IStartupTask {
	public int Order { get; } = 100;
	public ValueTask ExecuteAsync() {
		sp.ValidateAuthorizationConfiguration();
		return ValueTask.CompletedTask;
	}
}
```

#### Admin endpoint

```csharp
app.MapGet("/admin/authz/report", (IServiceProvider sp) =>
	sp.AnalyzeAuthorization()).RequireAuthorization("Admin");
```

#### Integration test

```csharp
[Fact]
public void Authorization_Configuration_Has_No_Errors() {
	using var host = TestHost.Build();
	Action act = () => host.Services.ValidateAuthorizationConfiguration();
	act.Should().NotThrow();
}
```

### Architectural principle

**No introspection type retains `IServiceProvider`.** `IDomainModel` is a singleton that holds an `IServiceScopeFactory`; DI-derived data (policy validators, authorization constraints, access-provider registrations) is snapshotted on first access through a transient scope, and the scope is released. Reflection-derived data (resources, rules, catalog) is cached via `Lazy<T>`. Repeated calls are pointer reads against immutable snapshots.

There is no `Initialize` step and no public refresh path. The captured-scope failure mode that affected pre-extraction releases is structurally impossible.

## Documentation

- [CHANGELOG.md](docs/CHANGELOG.md) — versioned change history
- Cirreum.Core [`RELEASE-NOTES-v4.0.2.md`](https://github.com/cirreum/Cirreum.Core/blob/main/docs/RELEASE-NOTES-v4.0.2.md) — extraction rationale and migration steps from the old in-Core introspection

## Contribution Guidelines

1. **Be conservative with new abstractions**  
   The API surface must remain stable and meaningful.

2. **Limit dependency expansion**  
   Only add foundational, version-stable dependencies.

3. **Favor additive, non-breaking changes**  
   Breaking changes ripple through the entire ecosystem.

4. **Include thorough unit tests**  
   All primitives and patterns should be independently testable.

5. **Document architectural decisions**  
   Context and reasoning should be clear for future maintainers.

6. **Follow .NET conventions**  
   Use established patterns from Microsoft.Extensions.* libraries.

## Versioning

Cirreum.Introspection follows [Semantic Versioning](https://semver.org/):

- **Major** - Breaking API changes
- **Minor** - New features, backward compatible
- **Patch** - Bug fixes, backward compatible

Given its foundational role, major version bumps are rare and carefully considered.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*
