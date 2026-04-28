namespace Cirreum.Introspection.Documentation;

public interface IDomainDocumenter {

	/// <summary>
	/// Generates a comprehensive Markdown documentation of the authorization system.
	/// </summary>
	/// <param name="services">
	/// Optional service provider. When supplied, the analysis report section is included.
	/// When null, the analysis section is omitted. The provider is used eagerly and not retained.
	/// </param>
	string GenerateMarkdown(IServiceProvider? services = null);

	/// <summary>
	/// Generates a CSV export of the authorization system.
	/// </summary>
	/// <param name="services">
	/// Optional service provider. When supplied, the security analysis section is included.
	/// </param>
	string GenerateCsv(IServiceProvider? services = null);

	/// <summary>
	/// Renders a complete HTML page visualizing the authorization system.
	/// </summary>
	/// <param name="services">
	/// Optional service provider. When supplied, the security analysis tab is populated.
	/// </param>
	string RenderHtmlPage(IServiceProvider? services = null);
}
