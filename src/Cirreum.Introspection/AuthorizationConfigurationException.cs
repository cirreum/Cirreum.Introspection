namespace Cirreum.Introspection;

using System.Text;

/// <summary>
/// Thrown by <see cref="AuthorizationStartupValidationExtensions.ValidateAuthorizationConfiguration"/>
/// when one or more analyzers report <see cref="IssueSeverity.Error"/> findings against the
/// configured authorization graph. Boot-time enforcement of "Error severity = build break" —
/// surfaces missing authorizers, missing grant providers, unsafe cacheable+grant combinations,
/// and other framework-detectable misconfigurations before the host begins serving requests.
/// </summary>
public sealed class AuthorizationConfigurationException : Exception {

	/// <summary>
	/// The full analysis report that triggered the failure. Contains all issues across
	/// every severity, every category, plus metrics — useful for logging or attaching to
	/// startup-failure telemetry.
	/// </summary>
	public AnalysisReport Report { get; }

	/// <summary>
	/// Aggregated counts and pass/fail status derived from <see cref="Report"/>.
	/// </summary>
	public AnalysisSummary Summary { get; }

	internal AuthorizationConfigurationException(AnalysisReport report, AnalysisSummary summary)
		: base(BuildMessage(report, summary)) {
		this.Report = report;
		this.Summary = summary;
	}

	private static string BuildMessage(AnalysisReport report, AnalysisSummary summary) {
		var sb = new StringBuilder();
		sb.Append("Authorization configuration validation failed: ")
			.Append(summary.ErrorCount)
			.Append(summary.ErrorCount == 1 ? " error" : " errors")
			.AppendLine(".");

		if (summary.WarningCount > 0) {
			sb.Append("(plus ")
				.Append(summary.WarningCount)
				.Append(summary.WarningCount == 1 ? " warning" : " warnings")
				.AppendLine(", not fatal but worth reviewing)");
		}

		sb.AppendLine();

		foreach (var issue in report.Issues) {
			if (issue.Severity != IssueSeverity.Error) {
				continue;
			}
			sb.Append("  [").Append(issue.Category).Append("] ").AppendLine(issue.Description);
			if (!string.IsNullOrWhiteSpace(issue.Recommendation)) {
				sb.Append("    → ").AppendLine(issue.Recommendation);
			}
			if (issue.RelatedTypeNames.Count > 0) {
				sb.Append("    Affected: ").AppendLine(string.Join(", ", issue.RelatedTypeNames));
			}
			sb.AppendLine();
		}

		return sb.ToString();
	}
}
