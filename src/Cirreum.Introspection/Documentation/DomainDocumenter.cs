namespace Cirreum.Introspection.Documentation;

using Cirreum.Authorization;
using Cirreum.Introspection;
using Cirreum.Introspection.Documentation.Formatters;
using Cirreum.Introspection.Modeling;
using System.Text;

public class DomainDocumenter : IDomainDocumenter {

	private readonly IAuthorizationRoleRegistry _roleRegistry;
	private readonly IDomainModel _domainModel;

	public DomainDocumenter(IAuthorizationRoleRegistry roleRegistry, IDomainModel domainModel) {
		this._roleRegistry = roleRegistry;
		this._domainModel = domainModel;
	}

	public string GenerateMarkdown(IServiceProvider? services = null) {
		var sb = new StringBuilder();
		var combinedInfo = this._domainModel.GetAllRules();

		sb.AppendLine("# Authorization System Documentation");
		sb.AppendLine();
		sb.AppendLine($"**Generated**: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
		sb.AppendLine($"**Runtime**: {DomainContext.RuntimeType}");
		sb.AppendLine();

		// Executive Summary
		sb.AppendLine("## Executive Summary");
		sb.AppendLine();
		sb.AppendLine($"- **Total Authorization Rules**: {combinedInfo.TotalRules}");
		sb.AppendLine($"- **Resource Rules**: {combinedInfo.ResourceRules.Count}");
		sb.AppendLine($"- **Policy Rules**: {combinedInfo.PolicyRules.Count}");
		sb.AppendLine($"- **Protected Resource Types**: {combinedInfo.ResourceRules.Select(r => r.ResourceType).Distinct().Count()}");
		sb.AppendLine();

		// Policy Validators Section
		sb.AppendLine("## Policy Validators");
		sb.AppendLine();
		sb.AppendLine("Global and attribute-based policies that apply across multiple resources:");
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
		var catalog = this._domainModel.GetCatalog();

		// Extract metrics
		var totalResources = catalog.Metrics.TotalResources;
		var protectedResources = catalog.Metrics.ProtectedResources;
		var anonymousResources = catalog.Metrics.AnonymousResources;
		var coveragePercentage = catalog.Metrics.OverallCoveragePercentage;
		var domainBoundaries = catalog.Metrics.TotalDomains;

		sb.AppendLine("### Domain Summary");
		sb.AppendLine();
		sb.AppendLine($"- **Domain Boundaries**: {domainBoundaries}");
		sb.AppendLine($"- **Total Resources**: {totalResources}");
		sb.AppendLine($"- **Protected Resources**: {protectedResources} ({coveragePercentage}%)");
		sb.AppendLine($"- **Anonymous Resources**: {anonymousResources}");
		sb.AppendLine();

		// Domain details are available in the Domain Architecture tab and analysis results

		// Rest of the existing documentation...
		sb.AppendLine("## Role Hierarchy");
		sb.AppendLine();
		sb.AppendLine("```text");
		sb.AppendLine(RoleHierarchyRenderer.ToTextTree(this._roleRegistry));
		sb.AppendLine("```");
		sb.AppendLine();

		// Enhanced Analysis Results (omitted when no service provider was supplied)
		if (services is not null) {
			var analysisReport = this.GetAnalysisReport(services);
			sb.Append(analysisReport.ToMarkdown());
		}

		return sb.ToString();
	}

	public string GenerateCsv(IServiceProvider? services = null) {
		var sb = new StringBuilder();
		var combinedInfo = this._domainModel.GetAllRules();
		var allRoles = this._roleRegistry.GetRegisteredRoles();

		sb.AppendLine("AUTHORIZATION SYSTEM EXPORT");
		sb.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
		sb.AppendLine($"Runtime: {DomainContext.RuntimeType}");
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

		// SECTION 1: Role hierarchy with improved structure
		sb.AppendLine("## ROLE HIERARCHY");
		sb.AppendLine("Section,ParentRole,ChildRole,InheritanceDepth");

		var processedRoles = new HashSet<string>();
		foreach (var role in allRoles) {
			var childRoles = this._roleRegistry.GetInheritedRoles(role);
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
		var rules = this._domainModel.GetAuthorizationRules();
		sb.AppendLine("## AUTHORIZATION RULES");
		sb.AppendLine("Section,ResourceName,ValidatorName,PropertyPath,ValidationType,Message,Condition,IncludesRBAC,SortOrder");

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
				$"{EscapeCsvField(rule.ResourceType.Name)}," +
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

		// SECTION 4: Resource-Role Matrix (excellent for heat map visualizations)
		sb.AppendLine("## RESOURCE ROLE MATRIX");
		sb.AppendLine("Section,ResourceName,RoleName,AccessConditions");

		// Get unique resource types
		var resourceTypes = rules
			.Select(r => r.ResourceType.Name)
			.Distinct();

		// Generate the matrix
		foreach (var resourceType in resourceTypes) {
			foreach (var role in allRoles) {
				// Check for explicit rules
				var explicitRules = rules.Where(r =>
					r.ResourceType.Name == resourceType &&
					r.Message.Contains(role.ToString()));
				if (explicitRules.Any()) {

					var accessConditions = "";

					sb.AppendLine(
						$"ResourceRoleMatrix," +
						$"{EscapeCsvField(resourceType)}," +
						$"{EscapeCsvField(role.ToString())}," +
						$"{EscapeCsvField(accessConditions)}");

				}
			}
		}

		sb.AppendLine();

		// SECTION 5: Security analysis (omitted when no service provider was supplied)
		if (services is null) {
			return sb.ToString();
		}
		var analysisReport = this.GetAnalysisReport(services);
		sb.AppendLine("## SECURITY ANALYSIS");
		sb.AppendLine("Section,Category,Severity,Description,RelatedObjects,ImpactedResources,ImpactedRoles");

		foreach (var issue in analysisReport.Issues) {
			// Join related objects with semicolon for CSV compatibility
			var relatedObjs = string.Join(";", issue.RelatedTypeNames);

			// Extract impacted resources
			var impactedResources = string.Join(";",
				issue.RelatedTypeNames
					.Where(typeName => resourceTypes.Any(rt => typeName.Contains(rt))));

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
				$"{EscapeCsvField(impactedResources)}," +
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

	public string RenderHtmlPage(IServiceProvider? services = null) {
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
		sb.AppendLine("    .resource { background-color: #f0fff0; border: 1px solid #b0ffb0; border-radius: 4px; margin: 10px 0; padding: 10px; }");
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
		sb.AppendLine($"<p class=\"generated-timestamp\"><strong>Generated:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC | <strong>Runtime:</strong> {DomainContext.RuntimeType}</p>");

		// Get data for statistics
		var combinedInfo = this._domainModel.GetAllRules();
		var allRoles = this._roleRegistry.GetRegisteredRoles();

		// Add executive summary with statistics
		sb.AppendLine("<div class=\"stats-grid\">");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\" style=\"font-size: 1.2em; color: #6c757d;\">{DomainContext.RuntimeType}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Runtime</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\">{combinedInfo.TotalRules}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Total Authorization Rules</div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("  <div class=\"stat-card\">");
		sb.AppendLine($"    <div class=\"stat-number\">{combinedInfo.ResourceRules.Count}</div>");
		sb.AppendLine("    <div class=\"stat-label\">Resource Rules</div>");
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
		sb.AppendLine("  <div class=\"tab active\" onclick=\"showTab('overview')\">Overview</div>");
		sb.AppendLine("  <div class=\"tab\" onclick=\"showTab('domain')\">Domain Architecture</div>");
		sb.AppendLine("  <div class=\"tab\" onclick=\"showTab('policies')\">Policy Validators</div>");
		sb.AppendLine("  <div class=\"tab\" onclick=\"showTab('roles')\">Roles</div>");
		sb.AppendLine("  <div class=\"tab\" onclick=\"showTab('rules')\">Resource Rules</div>");
		sb.AppendLine("  <div class=\"tab\" onclick=\"showTab('analysis')\">Security Analysis</div>");
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
		sb.AppendLine("  <p>Complete view of all domain resources (IDomainObject) across your domain, including both protected and anonymous resources.</p>");

		// Get domain data from the unified provider
		var htmlCatalog = this._domainModel.GetCatalog();

		// Extract overall metrics
		var totalDomainResources = htmlCatalog.Metrics.TotalResources;
		var protectedDomainResources = htmlCatalog.Metrics.ProtectedResources;
		var anonymousDomainResources = htmlCatalog.Metrics.AnonymousResources;
		var domainCoveragePercentage = htmlCatalog.Metrics.OverallCoveragePercentage;
		var totalDomainBoundaries = htmlCatalog.Metrics.TotalDomains;

		// Summary cards
		sb.AppendLine("  <div class=\"stats-grid\">");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\">{totalDomainBoundaries}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Domain Boundaries</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\">{totalDomainResources}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Total Resources</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\" style=\"color: #28a745;\">{protectedDomainResources}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Protected</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\" style=\"color: #ffc107;\">{anonymousDomainResources}</div>");
		sb.AppendLine("      <div class=\"stat-label\">Anonymous</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("    <div class=\"stat-card\">");
		sb.AppendLine($"      <div class=\"stat-number\">{domainCoveragePercentage}%</div>");
		sb.AppendLine("      <div class=\"stat-label\">Coverage</div>");
		sb.AppendLine("    </div>");
		sb.AppendLine("  </div>");

		// Domain breakdown details are available through the Anonymous Resource analyzer issues and analysis

		// Domain architecture issues - get from full analysis report (only when sp supplied)
		var analysisReportForDomain = services is not null ? this.GetAnalysisReport(services) : null;
		var domainIssues = analysisReportForDomain?.Issues
			.Where(i => i.Category == "Anonymous Resources").ToList() ?? [];
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
		sb.AppendLine("  <p>Cross-cutting authorization policies that apply to multiple resources based on attributes or global rules.</p>");

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

		// Roles Tab (existing, but now not the first tab)
		sb.AppendLine("<div id=\"roles\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Role Hierarchy</h2>");

		foreach (var role in allRoles.OrderBy(r => r.ToString())) {
			var roleClass = role.IsApplicationRole ? "app-role" : "custom-role";
			sb.AppendLine($"  <div class=\"role {roleClass}\">");
			sb.AppendLine($"    <h4>{role}</h4>");

			var childRoles = this._roleRegistry.GetInheritedRoles(role);
			if (childRoles.Count > 0) {
				sb.AppendLine("    <div class=\"inheritance\">");
				sb.AppendLine("      <strong>Inherits from:</strong> " + string.Join(", ", childRoles));
				sb.AppendLine("    </div>");
			}

			var parentRoles = this._roleRegistry.GetInheritingRoles(role);
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
		sb.Append(RoleHierarchyRenderer.ToMermaidDiagram(this._roleRegistry));
		sb.AppendLine("    </div>");
		sb.AppendLine("  </div>");
		sb.AppendLine("</div>");

		// Resource Rules Tab (renamed from "Rules")
		sb.AppendLine("<div id=\"rules\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Resource-Specific Authorization Rules</h2>");

		// Group rules by resource
		var rulesByResource = combinedInfo.ResourceRules
			.GroupBy(r => r.ResourceType)
			.OrderBy(g => g.Key.Name);

		foreach (var resourceGroup in rulesByResource) {
			sb.AppendLine($"  <div class=\"resource\">");
			sb.AppendLine($"    <h3>Resource: {resourceGroup.Key.Name}</h3>");

			// Show which policies might also apply to this resource
			var applicablePolicies = combinedInfo.PolicyRules
				.Where(p => p.IsAttributeBased && p.TargetAttributeType is not null && resourceGroup.Key.GetCustomAttributes(p.TargetAttributeType, false).Length != 0)
				.ToList();

			if (applicablePolicies.Count != 0) {
				sb.AppendLine($"    <div class=\"info\" style=\"margin-bottom: 10px;\">");
				sb.AppendLine($"      <strong>Applicable Policy Validators:</strong> {string.Join(", ", applicablePolicies.Select(p => p.PolicyName))}");
				sb.AppendLine($"    </div>");
			}

			// Group by validator
			var validatorGroups = resourceGroup
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

		// Analysis Tab (only when sp supplied)
		sb.AppendLine("<div id=\"analysis\" class=\"tab-content\">");
		sb.AppendLine("  <h2>Security Analysis</h2>");

		if (services is null) {
			sb.AppendLine("  <div class=\"info\"><strong>Analysis unavailable.</strong> Pass an <code>IServiceProvider</code> to <code>RenderHtmlPage</code> to populate this tab.</div>");
			sb.AppendLine("</div>");
			sb.AppendLine("</body></html>");
			return sb.ToString();
		}

		var analysisReport = this.GetAnalysisReport(services);

		// Overall Status
		sb.AppendLine("  <div class=\"resource\">");
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
		sb.AppendLine("  <div class=\"resource\">");
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

		// Enhanced JavaScript (existing with minor updates)
		sb.AppendLine("<script>");
		sb.AppendLine("// Initialize mermaid with configuration");
		sb.AppendLine("mermaid.initialize({");
		sb.AppendLine("  startOnLoad: false,");  // Changed from true to false
		sb.AppendLine("  securityLevel: 'loose',");
		sb.AppendLine("  theme: 'default',");
		sb.AppendLine("  flowchart: { useMaxWidth: false, htmlLabels: true }");
		sb.AppendLine("});");
		sb.AppendLine("");
		sb.AppendLine("function showTab(tabId) {");
		sb.AppendLine("  // Hide all tab contents");
		sb.AppendLine("  document.querySelectorAll('.tab-content').forEach(content => {");
		sb.AppendLine("    content.classList.remove('active');");
		sb.AppendLine("  });");
		sb.AppendLine("  ");
		sb.AppendLine("  // Show the selected tab content");
		sb.AppendLine("  document.getElementById(tabId).classList.add('active');");
		sb.AppendLine("  ");
		sb.AppendLine("  // Update tab buttons");
		sb.AppendLine("  document.querySelectorAll('.tab').forEach(tab => {");
		sb.AppendLine("    tab.classList.remove('active');");
		sb.AppendLine("  });");
		sb.AppendLine("  ");
		sb.AppendLine("  // Add active class to clicked tab");
		sb.AppendLine("  document.querySelectorAll('.tab').forEach(tab => {");
		sb.AppendLine("    const tabText = tab.textContent.toLowerCase();");
		sb.AppendLine("    const tabIdNormalized = tabId.replace('policies', 'policy').replace('domain', 'domain architecture');");
		sb.AppendLine("    if (tabText.includes(tabIdNormalized) || (tabId === 'domain' && tabText.includes('domain'))) {");
		sb.AppendLine("      tab.classList.add('active');");
		sb.AppendLine("    }");
		sb.AppendLine("  });");
		sb.AppendLine("  ");
		sb.AppendLine("  // Re-render mermaid diagrams when switching tabs");
		sb.AppendLine("  if (document.getElementById(tabId).querySelector('.mermaid')) {");
		sb.AppendLine("    setTimeout(() => {");
		sb.AppendLine("      try {");
		sb.AppendLine("        // Reset all mermaid diagrams in this tab");
		sb.AppendLine("        const mermaidElements = document.getElementById(tabId).querySelectorAll('.mermaid');");
		sb.AppendLine("        mermaidElements.forEach(element => {");
		sb.AppendLine("          // Store original content if not already stored");
		sb.AppendLine("          if (!element.dataset.originalContent) {");
		sb.AppendLine("            element.dataset.originalContent = element.textContent;");
		sb.AppendLine("          }");
		sb.AppendLine("          // Restore original content and reset processed flag");
		sb.AppendLine("          element.innerHTML = element.dataset.originalContent;");
		sb.AppendLine("          element.removeAttribute('data-processed');");
		sb.AppendLine("        });");
		sb.AppendLine("        ");
		sb.AppendLine("        // Re-initialize");
		sb.AppendLine("        mermaid.init(undefined, mermaidElements);");
		sb.AppendLine("      } catch (error) {");
		sb.AppendLine("        console.error('Error initializing mermaid:', error);");
		sb.AppendLine("      }");
		sb.AppendLine("    }, 250);");
		sb.AppendLine("  }");
		sb.AppendLine("}");
		sb.AppendLine("");
		sb.AppendLine("// Initialize on page load");
		sb.AppendLine("window.addEventListener('load', function() {");
		sb.AppendLine("  // Store original content for all mermaid elements before any processing");
		sb.AppendLine("  document.querySelectorAll('.mermaid').forEach(element => {");
		sb.AppendLine("    element.dataset.originalContent = element.textContent;");
		sb.AppendLine("  });");
		sb.AppendLine("  ");
		sb.AppendLine("  // Initialize only the active tab on page load");
		sb.AppendLine("  try {");
		sb.AppendLine("    mermaid.init(undefined, document.querySelectorAll('.tab-content.active .mermaid'));");
		sb.AppendLine("  } catch (error) {");
		sb.AppendLine("    console.error('Error initializing mermaid:', error);");
		sb.AppendLine("  }");
		sb.AppendLine("});");
		sb.AppendLine("</script>");

		sb.AppendLine("</body>");
		sb.AppendLine("</html>");

		return sb.ToString();

	}

	private AnalysisReport GetAnalysisReport(IServiceProvider services) {
		var analyzer = DomainAnalyzerProvider.CreateAnalyzer(this._roleRegistry, this._domainModel, services);
		return analyzer.AnalyzeAll();
	}

}
