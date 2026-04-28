namespace Cirreum.Introspection;

/// <summary>
/// Defines severity levels for analysis issues.
/// </summary>
public enum IssueSeverity {
	/// <summary>
	/// Informational items that might be worth reviewing.
	/// </summary>
	Info,

	/// <summary>
	/// Potential problems that should be reviewed.
	/// </summary>
	Warning,

	/// <summary>
	/// Serious issues that need to be addressed.
	/// </summary>
	Error
}
