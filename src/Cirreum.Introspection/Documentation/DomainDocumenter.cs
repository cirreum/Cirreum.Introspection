namespace Cirreum.Introspection.Documentation;

using Cirreum.Authorization;
using Cirreum.Introspection;
using Cirreum.Introspection.Documentation.Formatters;
using Cirreum.Introspection.Modeling;
using Microsoft.Extensions.DependencyInjection;
using System.Text;

/// <summary>
/// Default <see cref="IDomainDocumenter"/> implementation.
/// </summary>
/// <remarks>
/// <para>
/// Holds an <see cref="IServiceScopeFactory"/> (singleton-safe) and opens a
/// transient scope per-render-call to resolve <see cref="IAuthorizationRoleRegistry"/>
/// and to drive the analyzer pipeline. The registry is resolved lazily at render
/// time rather than at construction so the documenter is robust to startup order:
/// the registry's <c>IAutoInitialize</c> pass is guaranteed to have completed by
/// the time any render call returns content.
/// </para>
/// <para>
/// No <see cref="IServiceProvider"/> is retained; the per-call scope is disposed
/// before the method returns.
/// </para>
/// </remarks>
public class DomainDocumenter(
	IDomainModel domainModel,
	IDomainEnvironment domainEnvironment,
	IServiceScopeFactory scopeFactory
) : IDomainDocumenter {

	public string GenerateMarkdown() {

		using var scope = scopeFactory.CreateScope();
		var sp = scope.ServiceProvider;
		var roleRegistry = sp.GetRequiredService<IAuthorizationRoleRegistry>();

		var sb = new StringBuilder();
		var combinedInfo = domainModel.GetAllRules();

		sb.AppendLine("# Authorization System Documentation");
		sb.AppendLine();
		sb.AppendLine($"**Generated**: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
		sb.AppendLine($"**Runtime**: {domainEnvironment.RuntimeType}");
		sb.AppendLine();

		// Executive Summary
		sb.AppendLine("## Executive Summary");
		sb.AppendLine();
		sb.AppendLine($"- **Total Authorization Rules**: {combinedInfo.TotalRules}");
		sb.AppendLine($"- **Operation Rules**: {combinedInfo.OperationRules.Count}");
		sb.AppendLine($"- **Policy Rules**: {combinedInfo.PolicyRules.Count}");
		sb.AppendLine($"- **Protected Operation Types**: {combinedInfo.OperationRules.Select(r => r.OperationType).Distinct().Count()}");
		sb.AppendLine();

		// Policy Validators Section
		sb.AppendLine("## Policy Validators");
		sb.AppendLine();
		sb.AppendLine("Global and attribute-based policies that apply across multiple operations:");
		sb.AppendLine();

		if (combinedInfo.PolicyRules.Any()) {
			sb.AppendLine("| Policy Name | Type | Order | Runtime Support | Target Attribute |");
			sb.AppendLine("|-------------|------|-------|-----------------|------------------|");

			foreach (var policy in combinedInfo.PolicyRules.OrderBy(p => p.Order)) {
				var runtimeSupport = string.Join(", ", policy.SupportedRuntimeTypes);
				var targetAttribute = policy.TargetAttributeType?.Name ?? "N/A (Global)";

				sb.AppendLine($"| {policy.PolicyName} | {(policy.IsAttributeBased ? "Attribute-Based" : "Global")} | {policy.Order} | {runtimeSupport} | {targetAttribute} |");
			}
		} else {
			sb.AppendLine("No policy validators configured.");
		}

		sb.AppendLine();

		// Domain Architecture Section
		sb.AppendLine("## Domain Architecture");
		sb.AppendLine();

		// Get domain data from the unified provider
		var catalog = domainModel.GetCatalog();

		// Extract metrics
		var totalOperations = catalog.Metrics.TotalOperations;
		var protectedOperations = catalog.Metrics.ProtectedOperations;
		var anonymousOperations = catalog.Metrics.AnonymousOperations;
		var coveragePercentage = catalog.Metrics.OverallCoveragePercentage;
		var domainBoundaries = catalog.Metrics.TotalDomains;

		sb.AppendLine("### Domain Summary");
		sb.AppendLine();
		sb.AppendLine($"- **Domain Boundaries**: {domainBoundaries}");
		sb.AppendLine($"- **Total Operations**: {totalOperations}");
		sb.AppendLine($"- **Protected Operations**: {protectedOperations} ({coveragePercentage}%)");
		sb.AppendLine($"- **Anonymous Operations**: {anonymousOperations}");
		sb.AppendLine();

		// Domain details are available in the Domain Architecture tab and analysis results

		// Authorization Constraints (Phase 1, Step 2)
		sb.AppendLine("## Authorization Constraints");
		sb.AppendLine();
		sb.AppendLine("`IAuthorizationConstraint` implementations run as Phase 1, Step 2 of the authorization pipeline, in registration order, after grant evaluation and before any operation authorizer or policy. Each can short-circuit the pipeline.");
		sb.AppendLine();
		var constraintTypes = domainModel.GetAuthorizationConstraintTypes();
		if (constraintTypes.Count == 0) {
			sb.AppendLine("_No constraints registered._");
		} else {
			sb.AppendLine("| Order | Type | Namespace |");
			sb.AppendLine("|------:|------|-----------|");
			var idx = 1;
			foreach (var ct in constraintTypes) {
				sb.AppendLine($"| {idx} | `{ct.Name}` | `{ct.Namespace ?? "-"}` |");
				idx++;
			}
		}
		sb.AppendLine();

		// Grants (Phase 1, Step 1)
		sb.AppendLine("## Grants");
		sb.AppendLine();
		var grantedOperations = domainModel.GetAllOperations().Where(o => o.IsGranted).ToList();
		if (grantedOperations.Count == 0) {
			sb.AppendLine("_No granted operations registered._");
		} else {
			sb.AppendLine($"- **Granted operations:** {grantedOperations.Count}");
			sb.AppendLine($"- **`IOperationGrantProvider` registered:** {(domainModel.IsOperationGrantProviderRegistered ? "yes" : "**no — grant evaluation cannot run**")}");
			sb.AppendLine();

			var byDomain = grantedOperations
				.GroupBy(o => o.GrantDomain ?? "(no domain)", StringComparer.OrdinalIgnoreCase)
				.OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase);
			foreach (var dg in byDomain) {
				sb.AppendLine($"### Domain: `{dg.Key}` ({dg.Count()})");
				sb.AppendLine();
				sb.AppendLine("| Operation | Kind | Permissions | Authorizer |");
				sb.AppendLine("|-----------|------|-------------|------------|");
				foreach (var op in dg.OrderBy(o => o.OperationType.Name)) {
					var perms = op.Permissions.Count > 0
						? string.Join(", ", op.Permissions.Select(p => $"`{p}`"))
						: "_none_";
					var authorizer = op.AuthorizerType?.Name is { } an ? $"`{an}`" : "_none_";
					sb.AppendLine($"| `{op.OperationType.Name}` | {op.GrantableKind ?? "?"} | {perms} | {authorizer} |");
				}
				sb.AppendLine();
			}
		}

		// Rest of the existing documentation...
		sb.AppendLine("## Role Hierarchy");
		sb.AppendLine();
		sb.AppendLine("```text");
		sb.AppendLine(RoleHierarchyRenderer.ToTextTree(roleRegistry));
		sb.AppendLine("```");
		sb.AppendLine();

		// Analysis section
		var analysisReport = this.RunAnalysis(sp, roleRegistry);
		sb.Append(analysisReport.ToMarkdown());

		return sb.ToString();
	}

	public string GenerateCsv() {

		using var scope = scopeFactory.CreateScope();
		var sp = scope.ServiceProvider;
		var roleRegistry = sp.GetRequiredService<IAuthorizationRoleRegistry>();

		var sb = new StringBuilder();
		var combinedInfo = domainModel.GetAllRules();
		var allRoles = roleRegistry.GetRegisteredRoles();

		sb.AppendLine("AUTHORIZATION SYSTEM EXPORT");
		sb.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
		sb.AppendLine($"Runtime: {domainEnvironment.RuntimeType}");
		sb.AppendLine($"Total Authorization Rules: {combinedInfo.TotalRules}");
		sb.AppendLine();

		// Policy Validators Section
		sb.AppendLine("POLICY VALIDATORS");
		sb.AppendLine("Section,PolicyName,ValidatorType,Order,IsAttributeBased,TargetAttribute,RuntimeTypes,Description");

		foreach (var policy in combinedInfo.PolicyRules) {
			var runtimeTypes = string.Join(";", policy.SupportedRuntimeTypes);
			var targetAttribute = policy.TargetAttributeType?.Name ?? "";

			sb.AppendLine(
				$"PolicyValidator," +
				$"{EscapeCsvField(policy.PolicyName)}," +
				$"{EscapeCsvField(policy.PolicyType.Name)}," +
				$"{policy.Order}," +
				$"{policy.IsAttributeBased}," +
				$"{EscapeCsvField(targetAttribute)}," +
				$"{EscapeCsvField(runtimeTypes)}," +
				$"{EscapeCsvField(policy.Description)}");
		}

		sb.AppendLine();

		// Authorization Constraints (Phase 1, Step 2)
		sb.AppendLine("## CONSTRAINTS");
		sb.AppendLine("Section,Order,TypeName,FullName,Namespace");
		var constraintTypes = domainModel.GetAuthorizationConstraintTypes();
		var constraintIdx = 1;
		foreach (var ct in constraintTypes) {
			sb.AppendLine(
				$"Constraint," +
				$"{constraintIdx}," +
				$"{EscapeCsvField(ct.Name)}," +
				$"{EscapeCsvField(ct.FullName ?? ct.Name)}," +
				$"{EscapeCsvField(ct.Namespace ?? string.Empty)}");
			constraintIdx++;
		}
		sb.AppendLine();

		// Grants (Phase 1, Step 1)
		sb.AppendLine("## GRANTS");
		sb.AppendLine("Section,GrantDomain,OperationName,OperationFullName,GrantableKind,Permissions,AuthorizerName,IsSelfScoped,GrantProviderRegistered");
		var grantedOperationsForCsv = domainModel.GetAllOperations().Where(o => o.IsGranted).ToList();
		var grantProviderRegistered = domainModel.IsOperationGrantProviderRegistered;
		foreach (var op in grantedOperationsForCsv.OrderBy(o => o.GrantDomain).ThenBy(o => o.OperationType.Name)) {
			var perms = string.Join(";", op.Permissions.Select(p => p.ToString()));
			sb.AppendLine(
				$"Grant," +
				$"{EscapeCsvField(op.GrantDomain ?? string.Empty)}," +
				$"{EscapeCsvField(op.OperationType.Name)}," +
				$"{EscapeCsvField(op.OperationType.FullName ?? op.OperationType.Name)}," +
				$"{EscapeCsvField(op.GrantableKind ?? string.Empty)}," +
				$"{EscapeCsvField(perms)}," +
				$"{EscapeCsvField(op.AuthorizerType?.Name ?? string.Empty)}," +
				$"{op.IsSelfScoped}," +
				$"{grantProviderRegistered}");
		}
		sb.AppendLine();

		// SECTION 1: Role hierarchy with improved structure
		sb.AppendLine("## ROLE HIERARCHY");
		sb.AppendLine("Section,ParentRole,ChildRole,InheritanceDepth");

		var processedRoles = new HashSet<string>();
		foreach (var role in allRoles) {
			var childRoles = roleRegistry.GetInheritedRoles(role);
			foreach (var childRole in childRoles) {
				// Calculate an approximate inheritance depth for visualization tools
				var inheritanceDepth = 1; // Default to direct inheritance

				// Add relationship to CSV
				sb.AppendLine(
					$"RoleHierarchy," +
					$"{EscapeCsvField(role.ToString())}," +
					$"{EscapeCsvField(childRole.ToString())}," +
					$"{inheritanceDepth}");

				processedRoles.Add(role.ToString());
				processedRoles.Add(childRole.ToString());
			}
		}

		// Add standalone roles (not in any hierarchy)
		foreach (var role in allRoles) {
			if (!processedRoles.Contains(role.ToString())) {
				sb.AppendLine(
					$"RoleHierarchy," +
					$"{EscapeCsvField(role.ToString())}," +
					$"," + // No child
					$"0"); // Zero depth (standalone)
			}
		}

		sb.AppendLine();

		// SECTION 2: Authorization rules with improved structure for visualization
		var rules = domainModel.GetAuthorizationRules();
		sb.AppendLine("## AUTHORIZATION RULES");
		sb.AppendLine("Section,OperationName,ValidatorName,PropertyPath,ValidationType,Message,Condition,IncludesRBAC,SortOrder");

		var sortOrder = 0;
		foreach (var rule in rules) {
			sortOrder++;

			// Determine if the ABAC rule includes RBAC
			var includesRBAC =
				!string.IsNullOrWhiteSpace(rule.PropertyPath)
				&& rule.PropertyPath == nameof(AuthorizationContext<>.EffectiveRoles);

			// Extract validation type for better categorization
			var validationType = ExtractValidationType(rule.ValidationLogic);

			sb.AppendLine(
				$"AuthRule," +
				$"{EscapeCsvField(rule.OperationType.Name)}," +
				$"{EscapeCsvField(rule.AuthorizerType.Name)}," +
				$"{EscapeCsvField(rule.PropertyPath ?? "AuthorizationContext")}," +
				$"{EscapeCsvField(validationType)}," +
				$"{EscapeCsvField(rule.Message)}," +
				$"{(includesRBAC ? "True" : "False")}," +
				$"{sortOrder}");
		}

		sb.AppendLine();

		// SECTION 3: Domain Architecture
		// Note: Domain architecture details are available in the Domain Architecture
		// analyzer results and the dedicated Domain Architecture tab/section

		// SECTION 4: Operation-Role Matrix (excellent for heat map visualizations)
		sb.AppendLine("## OPERATION ROLE MATRIX");
		sb.AppendLine("Section,OperationName,RoleName,AccessConditions");

		// Get unique operation types
		var operationTypes = rules
			.Select(r => r.OperationType.Name)
			.Distinct();

		// Generate the matrix
		foreach (var operationType in operationTypes) {
			foreach (var role in allRoles) {
				// Check for explicit rules
				var explicitRules = rules.Where(r =>
					r.OperationType.Name == operationType &&
					r.Message.Contains(role.ToString()));
				if (explicitRules.Any()) {

					var accessConditions = "";

					sb.AppendLine(
						$"OperationRoleMatrix," +
						$"{EscapeCsvField(operationType)}," +
						$"{EscapeCsvField(role.ToString())}," +
						$"{EscapeCsvField(accessConditions)}");

				}
			}
		}

		sb.AppendLine();

		// SECTION 5: Security analysis
		var analysisReport = this.RunAnalysis(sp, roleRegistry);
		sb.AppendLine("## SECURITY ANALYSIS");
		sb.AppendLine("Section,Category,Severity,Description,RelatedObjects,ImpactedOperations,ImpactedRoles");

		foreach (var issue in analysisReport.Issues) {
			// Join related objects with semicolon for CSV compatibility
			var relatedObjs = string.Join(";", issue.RelatedTypeNames);

			// Extract impacted operations
			var impactedOperations = string.Join(";",
				issue.RelatedTypeNames
					.Where(typeName => operationTypes.Any(rt => typeName.Contains(rt))));

			// Extract impacted roles
			var impactedRoles = string.Join(";",
				issue.RelatedTypeNames
					.Where(typeName => allRoles.Any(r => typeName.Contains(r.ToString()))));

			sb.AppendLine(
				$"SecurityIssue," +
				$"{EscapeCsvField(issue.Category)}," +
				$"{EscapeCsvField(issue.Severity.ToString())}," +
				$"{EscapeCsvField(issue.Description)}," +
				$"{EscapeCsvField(relatedObjs)}," +
				$"{EscapeCsvField(impactedOperations)}," +
				$"{EscapeCsvField(impactedRoles)}");
		}

		return sb.ToString();

	}
	private static string ExtractValidationType(string validationLogic) {
		return validationLogic.Replace(" ", "");
	}
	private static string EscapeCsvField(string field) {
		if (string.IsNullOrEmpty(field)) {
			return "";
		}

		if (field.Contains(',') || field.Contains('"') || field.Contains('\n')) {
			return $"\"{field.Replace("\"", "\"\"")}\"";
		}
		return field;
	}

	public string RenderHtmlPage() {

		using var scope = scopeFactory.CreateScope();
		var sp = scope.ServiceProvider;
		var roleRegistry = sp.GetRequiredService<IAuthorizationRoleRegistry>();

		var sb = new StringBuilder();

		sb.AppendLine("<!DOCTYPE html>");
		sb.AppendLine("<html>");
		sb.AppendLine("<head>");
		sb.AppendLine("  <title>Authorization System Visualization</title>");
		sb.AppendLine("  <style>");
		sb.AppendLine("    body { font-family: Arial, sans-serif; margin: 20px; }");
		sb.AppendLine("    .role { background-color: #f8f0ff; border: 1px solid #d0b0ff; border-radius: 4px; margin: 5px; padding: 10px; }");
		sb.AppendLine("    .app-role { background-color: #f0f0ff; border: 1px solid #b0b0ff; }");
		sb.AppendLine("    .custom-role { background-color: #fff0f0; border: 1px solid #ffb0b0; }");
		sb.AppendLine("    .operation { background-color: #f0fff0; border: 1px solid #b0ffb0; border-radius: 4px; margin: 10px 0; padding: 10px; }");
		sb.AppendLine("    .validator { margin-left: 20px; }");
		sb.AppendLine("    .rule { margin-left: 40px; background-color: #fffff0; border: 1px solid #ffffd0; border-radius: 4px; padding: 8px; margin-bottom: 5px; }");
		sb.AppendLine("    .inheritance { color: #666; }");
		sb.AppendLine("    .error { background-color: #ffeeee; border: 1px solid #ffaaaa; border-radius: 4px; padding: 8px; margin: 5px 0; }");
		sb.AppendLine("    .warning { background-color: #ffffee; border: 1px solid #ffffaa; border-radius: 4px; padding: 8px; margin: 5px 0; }");
		sb.AppendLine("    .info { background-color: #eeeeff; border: 1px solid #aaaaff; border-radius: 4px; padding: 8px; margin: 5px 0; }");

		// NEW: Policy-related styles
		sb.AppendLine("    .policy { background-color: #fff9e6; border: 1px solid #ffcc80; border-radius: 4px; margin: 10px 0; padding: 10px; }");
		sb.AppendLine("    .attribute-policy { background-color: #e8f5e8; border: 1px solid #a5d6a7; }");
		sb.AppendLine("    .global-policy { background-color: #fce4ec; border: 1px solid #f8bbd9; }");
		sb.AppendLine("    .policy-badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin-right: 5px; }");
		sb.AppendLine("    .badge-attribute { background-color: #c8e6c9; color: #2e7d32; }");
		sb.AppendLine("    .badge-global { background-color: #f8bbd9; color: #c2185b; }");
		sb.AppendLine("    .badge-order { background-color: #e1bee7; color: #7b1fa2; }");
		sb.AppendLine("    .runtime-support { font-size: 0.9em; color: #666; margin-top: 5px; }");
		sb.AppendLine("    .policy-description { font-style: italic; color: #555; margin-top: 8px; }");
		sb.AppendLine("    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }");
		sb.AppendLine("    .stat-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; text-align: center; }");
		sb.AppendLine("    .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }");
		sb.AppendLine("    .stat-label { color: #6c757d; font-size: 0.9em; }");

		sb.AppendLine("    h1, h2, h3 { color: #444; }");
		sb.AppendLine("    .generated-timestamp { color: #666; font-size: 0.9em; margin-top: -10px; }");
		sb.AppendLine("    .diagram { margin: 20px 0; overflow: auto; max-height: 800px; }");
		sb.AppendLine("    .tabs { display: flex; margin-bottom: 10px; }");
		sb.AppendLine("    .tab { padding: 8px 16px; cursor: pointer; border: 1px solid #ccc; margin-right: 4px; }");
		sb.AppendLine("    .tab.active { background-color: #f0f0f0; border-bottom: none; }");
		sb.AppendLine("    .tab-content { display: none; padding: 20px; border: 1px solid #ccc; }");
		sb.AppendLine("    .tab-content.active { display: block; }");
		sb.AppendLine("  </style>");
		sb.AppendLine("  <script src=\"https://unpkg.com/mermaid@11.7.0/dist/mermaid.min.js\"></script>");
		sb.AppendLine("</head>");
		sb.AppendLine("<body>");

		sb.AppendLine("<h1>Authorization System Documentation</h1>");
		sb.AppendLine($"<p class=\"generated-timestamp\"><strong>Generated:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC | <strong>Runtime:</strong> {domainEnvironment.RuntimeType}</p>");

		// Get data for statistics
		var combinedInfo = domainModel.GetAllRules();
		var allRoles = roleRegistry.GetRegisteredRoles();

		// Add executive summary with statistics
		sb.AppendLine("<div class=\"stats-grid\">");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\" style=\"font-size: 1.2em; color: #6c757d;\">{domainEnvironment.RuntimeType}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Runtime</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\">{combinedInfo.TotalRules}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Total Authorization Rules</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\">{combinedInfo.OperationRules.Count}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Operation Rules</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\">{combinedInfo.PolicyRules.Count}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Policy Rules</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\">{allRoles.Count}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Total Roles</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("</div>");

		// Enhanced tabs - ADD NEW POLICY TAB
		sb.AppendLine("<div class=\"tabs\">");
		// Tab order follows the DefaultAuthorization pipeline:
		// Overview/Domain set the stage, then pipeline phases:
		//   Grants (Phase 1, Step 1) → Constraints (Phase 1, Step 2)
		//   → Operations (Phase 2 — authorizer rules) → Policies (Phase 3)
		// Roles before Security Analysis closes the report.
		sb.AppendLine("  <div class=\"tab active\" data-tab=\"overview\" onclick=\"showTab('overview')\">Overview</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"domain\" onclick=\"showTab('domain')\">Domain Architecture</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"grants\" onclick=\"showTab('grants')\">Grants</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"constraints\" onclick=\"showTab('constraints')\">Constraints</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"operations\" onclick=\"showTab('operations')\">Operations</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"policies\" onclick=\"showTab('policies')\">Policies</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"roles\" onclick=\"showTab('roles')\">Roles</div>");
		sb.AppendLine("  <div class=\"tab\" data-tab=\"analysis\" onclick=\"showTab('analysis')\">Security Analysis</div>");
		sb.AppendLine("</div>");

		// NEW: Overview Tab
		sb.AppendLine("<div id=\"overview\" class=\"tab-content active\">");
		sb.AppendLine("  <h2>Authorization System Overview</h2>");

		sb.AppendLine("  <h3>Authorization Flow</h3>");
		sb.AppendLine("  <div class=\"diagram\">");
		sb.AppendLine("    <div class=\"mermaid\">");
		sb.Append(AuthorizationFlowRenderer.ToMermaidDiagram());
		sb.AppendLine("    ");
		sb.AppendLine("    style A fill:#e1f5fe");
		sb.AppendLine("    style O fill:#e8f5e8");
		sb.AppendLine("    style C fill:#ffebee");
		sb.AppendLine("    style E fill:#ffebee");
		sb.AppendLine("    style H fill:#ffebee");
		sb.AppendLine("    style N fill:#ffebee");
		sb.AppendLine("    style K fill:#fff3e0");
		sb.AppendLine("    style L fill:#f3e5f5");
		sb.AppendLine("    </div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("</div>");

		// NEW: Domain Architecture Tab
		sb.AppendLine("<div id=\"domain\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Domain Architecture</h2>");
		sb.AppendLine("  <p>Complete view of all domain operations (IDomainObject) across your domain, including both protected and anonymous operations.</p>");

		// Get domain data from the unified provider
		var htmlCatalog = domainModel.GetCatalog();

		// Extract overall metrics
		var totalDomainOperations = htmlCatalog.Metrics.TotalOperations;
		var protectedDomainOperations = htmlCatalog.Metrics.ProtectedOperations;
		var anonymousDomainOperations = htmlCatalog.Metrics.AnonymousOperations;
		var domainCoveragePercentage = htmlCatalog.Metrics.OverallCoveragePercentage;
		var totalDomainBoundaries = htmlCatalog.Metrics.TotalDomains;

		// Summary cards
		sb.AppendLine("  <div class=\"stats-grid\">");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\">{totalDomainBoundaries}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Domain Boundaries</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\">{totalDomainOperations}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Total Operations</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\" style=\"color: #28a745;\">{protectedDomainOperations}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Protected</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\" style=\"color: #ffc107;\">{anonymousDomainOperations}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Anonymous</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\">{domainCoveragePercentage}%</div>");
		sb.AppendLine("      <div class=\"stat-label\">Coverage</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("  </div>");

		// Domain breakdown details are available through the Anonymous Operation analyzer issues and analysis

		// Domain architecture issues - pulled from the analysis report
		var analysisReportForDomain = this.RunAnalysis(sp, roleRegistry);
		var domainIssues = analysisReportForDomain.Issues
			.Where(i => i.Category == "Anonymous Operations").ToList();
		if (domainIssues.Count != 0) {
			sb.AppendLine("  <h3>Architecture Recommendations</h3>");

			foreach (var issue in domainIssues) {
				var issueClass = issue.Severity switch {
					IssueSeverity.Error => "error",
					IssueSeverity.Warning => "warning",
					_ => "info"
				};

				sb.AppendLine($"  <div class=\"{issueClass}\">");
				sb.AppendLine($"    <strong>{issue.Severity}:</strong> {issue.Description}");
				if (issue.RelatedTypeNames?.Count > 0 && issue.RelatedTypeNames.Count <= 5) {
					sb.AppendLine($"    <div style=\"margin-top: 5px; font-size: 0.9em;\">Related: {string.Join(", ", issue.RelatedTypeNames)}</div>");
				}
				sb.AppendLine("  </div>");
			}
		}

		sb.AppendLine("</div>");

		// Policy Validators Tab
		sb.AppendLine("<div id=\"policies\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Policy Validators</h2>");
		sb.AppendLine("  <p>Cross-cutting authorization policies that apply to multiple operations based on attributes or global rules.</p>");

		if (combinedInfo.PolicyRules.Any()) {
			var attributePolicies = combinedInfo.PolicyRules.Where(p => p.IsAttributeBased).OrderBy(p => p.Order);
			var globalPolicies = combinedInfo.PolicyRules.Where(p => !p.IsAttributeBased).OrderBy(p => p.Order);

			// Attribute-based policies
			if (attributePolicies.Any()) {
				sb.AppendLine("  <h3>Attribute-Based Policies</h3>");
				foreach (var policy in attributePolicies) {
					sb.AppendLine($"  <div class=\"policy attribute-policy\">");
					sb.AppendLine($"    <h4>");
					sb.AppendLine($"      <span class=\"policy-badge badge-attribute\">Attribute</span>");
					sb.AppendLine($"      <span class=\"policy-badge badge-order\">Order: {policy.Order}</span>");
					sb.AppendLine($"      {policy.PolicyName}");
					sb.AppendLine($"    </h4>");
					sb.AppendLine($"    <div><strong>Target Attribute:</strong> {policy.TargetAttributeType?.Name}</div>");
					sb.AppendLine($"    <div><strong>Validator Type:</strong> {policy.PolicyType.Name}</div>");
					sb.AppendLine($"    <div class=\"runtime-support\"><strong>Runtime Support:</strong> {string.Join(", ", policy.SupportedRuntimeTypes)}</div>");
					sb.AppendLine($"    <div class=\"policy-description\">{policy.Description}</div>");
					sb.AppendLine($"  </div>");
				}
			}

			// Global policies
			if (globalPolicies.Any()) {
				sb.AppendLine("  <h3>Global Policies</h3>");
				foreach (var policy in globalPolicies) {
					sb.AppendLine($"  <div class=\"policy global-policy\">");
					sb.AppendLine($"    <h4>");
					sb.AppendLine($"      <span class=\"policy-badge badge-global\">Global</span>");
					sb.AppendLine($"      <span class=\"policy-badge badge-order\">Order: {policy.Order}</span>");
					sb.AppendLine($"      {policy.PolicyName}");
					sb.AppendLine($"    </h4>");
					sb.AppendLine($"    <div><strong>Validator Type:</strong> {policy.PolicyType.Name}</div>");
					sb.AppendLine($"    <div class=\"runtime-support\"><strong>Runtime Support:</strong> {string.Join(", ", policy.SupportedRuntimeTypes)}</div>");
					sb.AppendLine($"    <div class=\"policy-description\">{policy.Description}</div>");
					sb.AppendLine($"  </div>");
				}
			}

			// Policy execution order diagram
			var orderDG = new StringBuilder();
			sb.AppendLine("  <h3>Policy Execution Order</h3>");
			sb.AppendLine("  <div class=\"diagram\">");
			sb.AppendLine("    <div class=\"mermaid\">");

			orderDG.AppendLine("flowchart TD");
			orderDG.AppendLine("    Start[Policy Validation Starts] --> Filter[Filter Applicable Policies]");

			var orderedPolicies = combinedInfo.PolicyRules.OrderBy(p => p.Order).ToList();
			for (var i = 0; i < orderedPolicies.Count && i < 10; i++) {
				var policy = orderedPolicies[i];
				var nodeId = $"P{i}";
				var policyType = policy.IsAttributeBased ? "ATTR" : "GLOBAL";

				// Create the node definition
				orderDG.AppendLine($"    {nodeId}[\"{policyType}: {policy.PolicyName} (Order: {policy.Order})\"]");

				// Create the connection FROM this node
				if (i == 0) {
					orderDG.AppendLine($"    Filter --> {nodeId}");
				}

				// Connect to next node or end
				if (i == orderedPolicies.Count - 1 || i == 9) {
					orderDG.AppendLine($"    {nodeId} --> End[All Policies Complete]");
				} else {
					orderDG.AppendLine($"    {nodeId} --> P{i + 1}");
				}
			}

			orderDG.AppendLine("    ");
			orderDG.AppendLine("    classDef attributePolicy fill:#e8f5e8,stroke:#4caf50");
			orderDG.AppendLine("    classDef globalPolicy fill:#fce4ec,stroke:#e91e63");

			for (var i = 0; i < orderedPolicies.Count && i < 10; i++) {
				var policy = orderedPolicies[i];
				var styleClass = policy.IsAttributeBased ? "attributePolicy" : "globalPolicy";
				orderDG.AppendLine($"    class P{i} {styleClass}");
			}
			sb.Append(orderDG);
			sb.AppendLine("    </div>");
			sb.AppendLine("  </div>");
		} else {
			sb.AppendLine("  <div class=\"info\">");
			sb.AppendLine("    <strong>No Policy Validators Configured</strong><br>");
			sb.AppendLine("    Consider adding policy validators for cross-cutting authorization concerns like security clearance, business hours, or maintenance mode.");
			sb.AppendLine("  </div>");
		}
		sb.AppendLine("</div>");

		// Constraints Tab — IAuthorizationConstraint registrations (Phase 1, Step 2 of pipeline)
		sb.AppendLine("<div id=\"constraints\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Authorization Constraints</h2>");
		sb.AppendLine("  <p><code>IAuthorizationConstraint</code> implementations run as <strong>Phase 1, Step 2</strong> of the authorization pipeline, in registration order, after grant evaluation and before any operation authorizer or policy validator. Each can short-circuit the pipeline (e.g. global maintenance mode, tenant suspension, IP allow-list).</p>");

		var constraintTypes = domainModel.GetAuthorizationConstraintTypes();
		if (constraintTypes.Count == 0) {
			sb.AppendLine("  <div class=\"info\"><strong>No constraints registered.</strong> This is a valid configuration — most apps don't need cross-cutting pre-authorization gates.</div>");
		} else {
			sb.AppendLine("  <div class=\"stats-grid\">");
			sb.AppendLine($"    <div class=\"stat-card\"><div class=\"stat-number\">{constraintTypes.Count}</div><div class=\"stat-label\">Registered</div></div>");
			sb.AppendLine("  </div>");

			sb.AppendLine("  <h3>Execution Order</h3>");
			sb.AppendLine("  <p>Constraints execute in the order shown below. The first failure short-circuits the pipeline.</p>");
			var idx = 1;
			foreach (var ct in constraintTypes) {
				sb.AppendLine("  <div class=\"resource\">");
				sb.AppendLine($"    <h4>{idx}. {ct.Name}</h4>");
				sb.AppendLine($"    <div><strong>Type:</strong> <code>{ct.FullName ?? ct.Name}</code></div>");
				if (ct.Namespace is not null) {
					sb.AppendLine($"    <div><strong>Namespace:</strong> {ct.Namespace}</div>");
				}
				sb.AppendLine("  </div>");
				idx++;
			}
		}
		sb.AppendLine("</div>");

		// Grants Tab — granted operations grouped by grant domain
		sb.AppendLine("<div id=\"grants\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Grants</h2>");
		sb.AppendLine("  <p>Operations gated by the grant pipeline (<strong>Phase 1, Step 1</strong>). A granted operation implements one of <code>IGrantableSelfBase</code>, <code>IGrantableMutateBase</code>, <code>IGrantableLookupBase</code>, or <code>IGrantableSearchBase</code>, and (typically) declares one or more <code>[RequiresGrant]</code> permissions. Grant evaluation runs through the registered <code>IOperationGrantProvider</code> before constraints, operation authorizers, or policy validators.</p>");

		var grantedOperations = domainModel.GetAllOperations()
			.Where(o => o.IsGranted)
			.ToList();

		if (grantedOperations.Count == 0) {
			sb.AppendLine("  <div class=\"info\"><strong>No granted operations registered.</strong> Grant-based access control is unused. This is fine for apps relying solely on RBAC + operation authorizers.</div>");
		} else {
			var grantDomains = grantedOperations
				.Where(o => o.GrantDomain is not null)
				.Select(o => o.GrantDomain!)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
				.ToList();

			var distinctPermissions = grantedOperations
				.SelectMany(o => o.Permissions)
				.Select(p => p.ToString())
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.Count();

			sb.AppendLine("  <div class=\"stats-grid\">");
			sb.AppendLine($"    <div class=\"stat-card\"><div class=\"stat-number\">{grantedOperations.Count}</div><div class=\"stat-label\">Granted Operations</div></div>");
			sb.AppendLine($"    <div class=\"stat-card\"><div class=\"stat-number\">{grantDomains.Count}</div><div class=\"stat-label\">Grant Domains</div></div>");
			sb.AppendLine($"    <div class=\"stat-card\"><div class=\"stat-number\">{distinctPermissions}</div><div class=\"stat-label\">Distinct Permissions</div></div>");
			sb.AppendLine($"    <div class=\"stat-card\"><div class=\"stat-number\" style=\"color: {(domainModel.IsOperationGrantProviderRegistered ? "#28a745" : "#cc0000")};\">{(domainModel.IsOperationGrantProviderRegistered ? "Registered" : "Missing")}</div><div class=\"stat-label\"><code>IOperationGrantProvider</code></div></div>");
			sb.AppendLine("  </div>");

			if (!domainModel.IsOperationGrantProviderRegistered) {
				sb.AppendLine("  <div class=\"error\"><strong>Critical:</strong> granted operations are declared but no <code>IOperationGrantProvider</code> is registered. Grant evaluation cannot run; access decisions will fail. Register a provider via <code>services.AddOperationGrants&lt;TResolver&gt;()</code>.</div>");
			}

			// Group operations by grant domain
			var byDomain = grantedOperations
				.GroupBy(o => o.GrantDomain ?? "(no domain)", StringComparer.OrdinalIgnoreCase)
				.OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase);

			foreach (var domainGroup in byDomain) {
				sb.AppendLine("  <div class=\"resource\">");
				sb.AppendLine($"    <h3>Domain: <code>{domainGroup.Key}</code> ({domainGroup.Count()} operation(s))</h3>");

				var domainPermissions = domainGroup
					.SelectMany(o => o.Permissions)
					.Select(p => p.ToString())
					.Distinct(StringComparer.OrdinalIgnoreCase)
					.OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
					.ToList();

				if (domainPermissions.Count > 0) {
					sb.AppendLine($"    <div><strong>Permissions:</strong> {string.Join(", ", domainPermissions.Select(p => $"<code>{p}</code>"))}</div>");
				}

				sb.AppendLine("    <table style=\"width: 100%; margin-top: 10px; border-collapse: collapse;\">");
				sb.AppendLine("      <thead><tr style=\"background: #f0f0f0;\"><th style=\"text-align:left; padding: 6px;\">Operation</th><th style=\"text-align:left; padding: 6px;\">Kind</th><th style=\"text-align:left; padding: 6px;\">Permissions</th><th style=\"text-align:left; padding: 6px;\">Authorizer</th></tr></thead>");
				sb.AppendLine("      <tbody>");
				foreach (var op in domainGroup.OrderBy(o => o.OperationType.Name)) {
					var perms = op.Permissions.Count > 0
						? string.Join(", ", op.Permissions.Select(p => $"<code>{p}</code>"))
						: "<em>none</em>";
					var authorizer = op.AuthorizerType is not null
						? $"<code>{op.AuthorizerType.Name}</code>"
						: "<em>none</em>";
					var kind = op.GrantableKind ?? "?";
					sb.AppendLine($"        <tr style=\"border-bottom: 1px solid #eee;\"><td style=\"padding: 6px;\"><code>{op.OperationType.Name}</code></td><td style=\"padding: 6px;\">{kind}</td><td style=\"padding: 6px;\">{perms}</td><td style=\"padding: 6px;\">{authorizer}</td></tr>");
				}
				sb.AppendLine("      </tbody></table>");
				sb.AppendLine("  </div>");
			}
		}
		sb.AppendLine("</div>");

		// Roles Tab (existing, but now not the first tab)
		sb.AppendLine("<div id=\"roles\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Role Hierarchy</h2>");

		foreach (var role in allRoles.OrderBy(r => r.ToString())) {
			var roleClass = role.IsApplicationRole ? "app-role" : "custom-role";
			sb.AppendLine($"  <div class=\"role {roleClass}\">");
			sb.AppendLine($"    <h4>{role}</h4>");

			var childRoles = roleRegistry.GetInheritedRoles(role);
			if (childRoles.Count > 0) {
				sb.AppendLine("    <div class=\"inheritance\">");
				sb.AppendLine("      <strong>Inherits from:</strong> " + string.Join(", ", childRoles));
				sb.AppendLine("    </div>");
			}

			var parentRoles = roleRegistry.GetInheritingRoles(role);
			if (parentRoles.Count > 0) {
				sb.AppendLine("    <div class=\"inheritance\">");
				sb.AppendLine("      <strong>Inherited by:</strong> " + string.Join(", ", parentRoles));
				sb.AppendLine("    </div>");
			}

			sb.AppendLine("  </div>");
		}

		sb.AppendLine("  <h3>Role Hierarchy Diagram</h3>");
		sb.AppendLine("  <div class=\"diagram\">");
		sb.AppendLine("    <div class=\"mermaid\">");
		sb.Append(RoleHierarchyRenderer.ToMermaidDiagram(roleRegistry));
		sb.AppendLine("    </div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("</div>");

		// Operation Rules Tab (renamed from "Rules")
		sb.AppendLine("<div id=\"operations\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Operations</h2>");
		sb.AppendLine("  <p>Each operation (<code>IDomainObject</code> / <code>IAuthorizableObject</code>) and the resource-specific authorization rules attached by its authorizer (Phase 2 of the pipeline).</p>");

		// Group rules by operation
		var rulesByOperation = combinedInfo.OperationRules
			.GroupBy(r => r.OperationType)
			.OrderBy(g => g.Key.Name);

		foreach (var operationGroup in rulesByOperation) {
			sb.AppendLine($"  <div class=\"operation\">");
			sb.AppendLine($"    <h3>Operation: {operationGroup.Key.Name}</h3>");

			// Show which policies might also apply to this operation
			var applicablePolicies = combinedInfo.PolicyRules
				.Where(p => p.IsAttributeBased && p.TargetAttributeType is not null && operationGroup.Key.GetCustomAttributes(p.TargetAttributeType, false).Length != 0)
				.ToList();

			if (applicablePolicies.Count != 0) {
				sb.AppendLine($"    <div class=\"info\" style=\"margin-bottom: 10px;\">");
				sb.AppendLine($"      <strong>Applicable Policy Validators:</strong> {string.Join(", ", applicablePolicies.Select(p => p.PolicyName))}");
				sb.AppendLine($"    </div>");
			}

			// Group by validator
			var validatorGroups = operationGroup
				.GroupBy(r => r.AuthorizerType)
				.OrderBy(g => g.Key.Name);

			foreach (var validatorGroup in validatorGroups) {
				sb.AppendLine($"    <div class=\"validator\">");
				sb.AppendLine($"      <h4>Validator: {validatorGroup.Key.Name}</h4>");

				foreach (var rule in validatorGroup) {
					sb.AppendLine($"      <div class=\"rule\">");
					sb.AppendLine($"        <strong>{rule.PropertyPath ?? "AuthorizationContext"}</strong>");
					sb.AppendLine($"        <div>Validation: {rule.ValidationLogic}</div>");
					sb.AppendLine($"        <div>Message: {rule.Message}</div>");

					// If rule mentions roles, display them
					var relatedRoles = allRoles.Where(r => rule.ValidationLogic.Contains(r.ToString())).ToList();
					if (relatedRoles.Count != 0) {
						sb.AppendLine($"        <div>Related Roles: {string.Join(", ", relatedRoles)}</div>");
					}

					sb.AppendLine($"      </div>");
				}

				sb.AppendLine($"    </div>");
			}

			sb.AppendLine($"  </div>");
		}
		sb.AppendLine("</div>");

		// Analysis Tab
		sb.AppendLine("<div id=\"analysis\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Security Analysis</h2>");

		var analysisReport = this.RunAnalysis(sp, roleRegistry);

		// Overall Status
		sb.AppendLine("  <div class=\"operation\">");
		sb.AppendLine("    <h3>Overall Status</h3>");
		sb.AppendLine($"    <div>Issues Found: {(analysisReport.HasIssues ? "Yes" : "No")}</div>");
		sb.AppendLine($"    <div>Total Issues: {analysisReport.Issues.Count}</div>");

		// Quick Summary
		sb.AppendLine("    <h4>Summary</h4>");
		var errorCount = analysisReport.Issues.Count(i => i.Severity == IssueSeverity.Error);
		var warningCount = analysisReport.Issues.Count(i => i.Severity == IssueSeverity.Warning);
		var infoCount = analysisReport.Issues.Count(i => i.Severity == IssueSeverity.Info);

		sb.AppendLine($"    <div><span style=\"color: #cc0000; font-weight: bold;\">&#9679;</span> Error: {errorCount}</div>");
		sb.AppendLine($"    <div><span style=\"color: #cccc00; font-weight: bold;\">&#9679;</span> Warning: {warningCount}</div>");
		sb.AppendLine($"    <div><span style=\"color: #00cc00; font-weight: bold;\">&#9679;</span> Info: {infoCount}</div>");
		sb.AppendLine("  </div>");

		// Detailed Issues
		sb.AppendLine("  <div class=\"operation\">");
		sb.AppendLine("    <h3>Detailed Issues</h3>");

		foreach (var category in analysisReport.AnalyzerCategories.OrderBy(c => c)) {
			sb.AppendLine($"    <h4>{category}</h4>");
			var categoryIssues = analysisReport.Issues.Where(i => i.Category == category);

			if (!categoryIssues.Any()) {
				sb.AppendLine("    <div>No issues found</div>");
				continue;
			}

			foreach (var severityGroup in categoryIssues.GroupBy(issue => issue.Severity)) {
				var severityClass = severityGroup.Key.ToString().ToLower();
				var issueIndex = 1;
				foreach (var issue in severityGroup) {
					sb.AppendLine($"    <div class=\"{severityClass}\">");
					sb.AppendLine($"      <strong>Issue {issueIndex++}: {issue.Description}</strong>");
					if (issue.RelatedTypeNames != null && issue.RelatedTypeNames.Any()) {
						sb.AppendLine($"      <div>Related Objects: {string.Join(", ", issue.RelatedTypeNames)}</div>");
					}
					sb.AppendLine("    </div>");
				}
			}
		}
		sb.AppendLine("  </div>");

		// Security Issues Diagram (existing)
		var analysisIssues = analysisReport.Issues.Where(i => i.Severity == IssueSeverity.Error || i.Severity == IssueSeverity.Warning).ToList();
		if (analysisIssues.Count != 0) {
			sb.AppendLine("  <h3>Security Issues Diagram</h3>");
			sb.AppendLine("  <div class=\"diagram\">");
			sb.AppendLine("    <div class=\"mermaid\">");
			sb.AppendLine("graph TD");

			for (var i = 0; i < analysisIssues.Count; i++) {
				var issue = analysisIssues[i];
				var issueId = $"Issue_{i}";
				var severity = issue.Severity == IssueSeverity.Error ? "ERROR" : "WARNING";
				var description = issue.Description.Replace("\"", "'").Replace("\n", "<br/>");
				sb.AppendLine($"    {issueId}[\"{severity}: {description}\"]");

				// Connect issues to related roles if applicable
				foreach (var relatedTypeName in issue.RelatedTypeNames) {
					// Check if this type name corresponds to a known role
					var matchingRole = allRoles.FirstOrDefault(r => relatedTypeName.Contains(r.ToString()));
					if (matchingRole != null) {
						var roleId = matchingRole.ToString().Replace(":", "_");
						sb.AppendLine($"    {issueId} -.-> {roleId}[\"{matchingRole}\"]");
					}
				}
			}

			sb.AppendLine("    %% Styling");
			sb.AppendLine("    classDef error fill:#ffcccc,stroke:#990000,stroke-width:2px;");
			sb.AppendLine("    classDef warning fill:#ffffcc,stroke:#999900,stroke-width:1px;");

			// Apply styles
			for (var i = 0; i < analysisIssues.Count; i++) {
				var issue = analysisIssues[i];
				var issueId = $"Issue_{i}";
				var styleClass = issue.Severity == IssueSeverity.Error ? "error" : "warning";
				sb.AppendLine($"    class {issueId} {styleClass};");
			}

			sb.AppendLine("    </div>");
			sb.AppendLine("  </div>");
		}

		sb.AppendLine("</div>");

		AppendHtmlTrailer(sb);
		return sb.ToString();
	}

	/// <summary>
	/// Closes the tabs page-frame and emits the JavaScript that drives tab switching
	/// and Mermaid (re-)initialization. Always call before returning the HTML so the
	/// page renders correctly even on early-exit paths (e.g. analysis tab unavailable).
	/// </summary>
	private static void AppendHtmlTrailer(StringBuilder sb) {
		sb.AppendLine("<script>");
		sb.AppendLine("mermaid.initialize({");
		sb.AppendLine("  startOnLoad: false,");
		sb.AppendLine("  securityLevel: 'loose',");
		sb.AppendLine("  theme: 'default',");
		sb.AppendLine("  flowchart: { useMaxWidth: false, htmlLabels: true }");
		sb.AppendLine("});");
		sb.AppendLine("");
		sb.AppendLine("function showTab(tabId) {");
		sb.AppendLine("  document.querySelectorAll('.tab-content').forEach(content => {");
		sb.AppendLine("    content.classList.remove('active');");
		sb.AppendLine("  });");
		sb.AppendLine("  document.getElementById(tabId).classList.add('active');");
		sb.AppendLine("  document.querySelectorAll('.tab').forEach(tab => {");
		sb.AppendLine("    tab.classList.toggle('active', tab.getAttribute('data-tab') === tabId);");
		sb.AppendLine("  });");
		sb.AppendLine("  if (document.getElementById(tabId).querySelector('.mermaid')) {");
		sb.AppendLine("    setTimeout(() => {");
		sb.AppendLine("      try {");
		sb.AppendLine("        const mermaidElements = document.getElementById(tabId).querySelectorAll('.mermaid');");
		sb.AppendLine("        mermaidElements.forEach(element => {");
		sb.AppendLine("          if (!element.dataset.originalContent) {");
		sb.AppendLine("            element.dataset.originalContent = element.textContent;");
		sb.AppendLine("          }");
		sb.AppendLine("          element.innerHTML = element.dataset.originalContent;");
		sb.AppendLine("          element.removeAttribute('data-processed');");
		sb.AppendLine("        });");
		sb.AppendLine("        mermaid.init(undefined, mermaidElements);");
		sb.AppendLine("      } catch (error) {");
		sb.AppendLine("        console.error('Error initializing mermaid:', error);");
		sb.AppendLine("      }");
		sb.AppendLine("    }, 250);");
		sb.AppendLine("  }");
		sb.AppendLine("}");
		sb.AppendLine("");
		sb.AppendLine("window.addEventListener('load', function() {");
		sb.AppendLine("  document.querySelectorAll('.mermaid').forEach(element => {");
		sb.AppendLine("    element.dataset.originalContent = element.textContent;");
		sb.AppendLine("  });");
		sb.AppendLine("  try {");
		sb.AppendLine("    mermaid.init(undefined, document.querySelectorAll('.tab-content.active .mermaid'));");
		sb.AppendLine("  } catch (error) {");
		sb.AppendLine("    console.error('Error initializing mermaid:', error);");
		sb.AppendLine("  }");
		sb.AppendLine("});");
		sb.AppendLine("</script>");
		sb.AppendLine("</body>");
		sb.AppendLine("</html>");
	}

	private AnalysisReport RunAnalysis(IServiceProvider scopedProvider, IAuthorizationRoleRegistry roleRegistry) {
		var analyzer = DomainAnalyzerProvider.CreateAnalyzer(roleRegistry, domainModel, scopedProvider);
		return analyzer.AnalyzeAll();
	}

}
