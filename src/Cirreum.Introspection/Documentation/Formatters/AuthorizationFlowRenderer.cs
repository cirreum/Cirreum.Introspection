namespace Cirreum.Introspection.Documentation.Formatters;

using System.Text;

/// <summary>
/// Provides methods to render authorization flow diagrams and visualizations.
/// </summary>
/// <remarks>
/// <para>
/// This renderer provides multiple visualization formats for the authorization pipeline flow,
/// making it easy to understand how operations are processed through the authorization system.
/// </para>
/// <para>
/// Available visualization formats:
/// <list type="bullet">
/// <item><description>Text-based flow using ASCII characters for console or log output</description></item>
/// <item><description>Mermaid diagram markup for visual representation in documentation</description></item>
/// </list>
/// </para>
/// <para>
/// The visualizations show:
/// <list type="bullet">
/// <item><description>Authentication check as the first gate</description></item>
/// <item><description>Role resolution including inheritance</description></item>
/// <item><description>Operation and policy validator execution order</description></item>
/// <item><description>Success and failure paths with appropriate exceptions</description></item>
/// </list>
/// </para>
/// </remarks>
public static class AuthorizationFlowRenderer {

	/// <summary>
	/// Generates a textual representation of the authorization flow.
	/// </summary>
	/// <returns>A string containing the text representation of the authorization pipeline.</returns>
	/// <remarks>
	/// <para>
	/// The text visualization uses ASCII characters to show the flow:
	/// <list type="bullet">
	/// <item><description>[Step] for process steps</description></item>
	/// <item><description>--&gt; for flow direction</description></item>
	/// <item><description>YES/NO for decision branches</description></item>
	/// </list>
	/// </para>
	/// <para>
	/// Example output:
	/// <code>
	/// AUTHORIZATION FLOW
	/// ==================
	///
	/// [Operation]
	///     |
	///     v
	/// {Authenticated?}
	///     |-- NO --> [UnauthenticatedAccessException]
	///     |
	///    YES
	///     |
	///     v
	/// {Any Validators?}
	///     |-- NO --> [InvalidOperationException: No Protection]
	/// ...
	/// </code>
	/// </para>
	/// </remarks>
	public static string ToText() {
		var sb = new StringBuilder();

		sb.AppendLine("AUTHORIZATION FLOW");
		sb.AppendLine("==================");
		sb.AppendLine();
		sb.AppendLine("[Operation]");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("{Authenticated?}");
		sb.AppendLine("    |-- NO --> [UnauthenticatedAccessException]");
		sb.AppendLine("    |");
		sb.AppendLine("   YES");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("{Any Validators?} (Operation or Policy)");
		sb.AppendLine("    |-- NO --> [InvalidOperationException: No Protection]");
		sb.AppendLine("    |");
		sb.AppendLine("   YES");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("[Get User Roles]");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("{Has Roles?}");
		sb.AppendLine("    |-- NO --> [ForbiddenAccessException: No Roles]");
		sb.AppendLine("    |");
		sb.AppendLine("   YES");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("[Resolve Effective Roles via Inheritance]");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("[Create Authorization Context]");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("[Run Operation Validators] (collect failures)");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("[Run Applicable Policy Validators in Order] (collect failures)");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("{Any Failures?}");
		sb.AppendLine("    |-- YES --> [ForbiddenAccessException]");
		sb.AppendLine("    |");
		sb.AppendLine("    NO");
		sb.AppendLine("    |");
		sb.AppendLine("    v");
		sb.AppendLine("[Access Granted]");

		return sb.ToString();
	}

	/// <summary>
	/// Generates a Mermaid diagram showing the authorization flow pipeline.
	/// </summary>
	/// <returns>A string containing the Mermaid diagram markup.</returns>
	/// <remarks>
	/// <para>
	/// The Mermaid diagram provides a visual representation with:
	/// <list type="bullet">
	/// <item><description>Rectangles for process steps</description></item>
	/// <item><description>Diamonds for decision points</description></item>
	/// <item><description>Arrows showing flow direction with labels</description></item>
	/// <item><description>Color-coded outcomes (success, failure, warning)</description></item>
	/// </list>
	/// </para>
	/// <para>
	/// Flow stages:
	/// <list type="bullet">
	/// <item><description>Authentication - Verifies user identity</description></item>
	/// <item><description>Protection Check - Ensures validators exist</description></item>
	/// <item><description>Role Check - Verifies user has assigned roles</description></item>
	/// <item><description>Role Resolution - Resolves effective roles via inheritance</description></item>
	/// <item><description>Validation - Runs operation and policy validators, collecting all failures</description></item>
	/// <item><description>Access Decision - Grants access only if no failures</description></item>
	/// </list>
	/// </para>
	/// <para>
	/// The output includes Markdown formatting and can be rendered by any Mermaid-compatible viewer.
	/// </para>
	/// </remarks>
	public static string ToMermaidDiagram() {
		var sb = new StringBuilder();

		sb.AppendLine("flowchart TD");
		sb.AppendLine("    %% Authorization Flow Diagram");
		sb.AppendLine();
		sb.AppendLine("    %% Entry Point");
		sb.AppendLine("    A[Operation] --> B{Authenticated?}");
		sb.AppendLine();
		sb.AppendLine("    %% Authentication Check");
		sb.AppendLine("    B -->|No| C[UnauthenticatedAccessException]");
		sb.AppendLine("    B -->|Yes| D{Any Validators?}");
		sb.AppendLine();
		sb.AppendLine("    %% Protection Check");
		sb.AppendLine("    D -->|No| E[InvalidOperationException:<br/>No Protection]");
		sb.AppendLine("    D -->|Yes| F[Get User Roles]");
		sb.AppendLine();
		sb.AppendLine("    %% Role Check");
		sb.AppendLine("    F --> G{Has Roles?}");
		sb.AppendLine("    G -->|No| H[ForbiddenAccessException:<br/>No Roles]");
		sb.AppendLine("    G -->|Yes| I[Resolve Effective Roles<br/>via Inheritance]");
		sb.AppendLine();
		sb.AppendLine("    %% Context and Validation");
		sb.AppendLine("    I --> J[Create Authorization Context]");
		sb.AppendLine("    J --> K[Run Operation Validators]");
		sb.AppendLine("    K --> L[Run Applicable Policy<br/>Validators in Order]");
		sb.AppendLine();
		sb.AppendLine("    %% Access Decision");
		sb.AppendLine("    L --> M{Any Failures?}");
		sb.AppendLine("    M -->|Yes| N[ForbiddenAccessException]");
		sb.AppendLine("    M -->|No| O[Access Granted]");

		return sb.ToString();
	}

}
