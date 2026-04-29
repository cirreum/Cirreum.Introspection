namespace Cirreum.Introspection.Documentation;

/// <summary>
/// Renders the domain's authorization configuration as Markdown, CSV, or HTML.
/// </summary>
/// <remarks>
/// Implementations resolve <see cref="Cirreum.Authorization.IAuthorizationRoleRegistry"/>
/// and the analyzer pipeline lazily, per render call, through an injected
/// <see cref="Microsoft.Extensions.DependencyInjection.IServiceScopeFactory"/>. This
/// makes calls safe regardless of whether the caller already has a DI scope, and
/// robust to startup ordering: the runtime's <c>IAutoInitialize</c> pass is guaranteed
/// to have populated the registry by the time any render call returns.
/// </remarks>
public interface IDomainDocumenter {

	/// <summary>
	/// Generates a comprehensive Markdown document of the authorization system,
	/// including the analysis report.
	/// </summary>
	string GenerateMarkdown();

	/// <summary>
	/// Generates a CSV export of the authorization system, including the analysis report.
	/// </summary>
	string GenerateCsv();

	/// <summary>
	/// Renders a complete, self-contained HTML page visualizing the authorization
	/// system, including the analysis report and Mermaid diagrams.
	/// </summary>
	string RenderHtmlPage();
}
