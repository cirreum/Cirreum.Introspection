namespace Cirreum.Introspection.Tests.Analyzers;

using Cirreum.Authorization;
using Cirreum.Introspection.Analyzers;
using Cirreum.Introspection.Modeling;
using Cirreum.Introspection.Modeling.Types;

public sealed class AuthorizableOperationAnalyzerTests {

	// A self-scoped operation (e.g. ISelfLookupOperation<User>): it implements
	// IAuthorizableOperationBase (RequiresAuthorization) but is authorized by the grant
	// pipeline's self rule (ExternalId == UserId), so it has no IAuthorizer<T> (IsProtected
	// == false, IsGranted == true). This is the shape that GetUser / GetUserByExternalId take.
	private static OperationTypeInfo SelfScopedGranted(Type operationType) => new(
		OperationType: operationType,
		DomainBoundary: "Users",
		OperationKind: "Queries",
		IsAnonymous: false,
		IsCacheableQuery: false,
		IsProtected: false,
		RequiresAuthorization: true,
		AuthorizerType: null,
		Rules: [],
		IsGranted: true,
		GrantDomain: "users",
		GrantableKind: "Self",
		IsSelfScoped: true,
		Permissions: PermissionSet.Empty);

	// A plain IAuthorizableOperation<T> with no authorizer and no grant participation. This
	// genuinely will fail authorization and MUST still be flagged.
	private static OperationTypeInfo PlainUnprotected(Type operationType) => new(
		OperationType: operationType,
		DomainBoundary: "Widgets",
		OperationKind: "Commands",
		IsAnonymous: false,
		IsCacheableQuery: false,
		IsProtected: false,
		RequiresAuthorization: true,
		AuthorizerType: null,
		Rules: [],
		IsGranted: false,
		Permissions: PermissionSet.Empty);

	private static AuthorizableOperationAnalyzer AnalyzerFor(params OperationTypeInfo[] operations) {
		var domainModel = Substitute.For<IDomainModel>();
		domainModel.GetAuthorizableOperations().Returns(operations);
		domainModel.GetPolicyRules().Returns([]);
		return new AuthorizableOperationAnalyzer(domainModel);
	}

	[Fact]
	public void Self_scoped_granted_operation_without_authorizer_produces_no_error() {
		var analyzer = AnalyzerFor(
			SelfScopedGranted(typeof(GetUser)),
			SelfScopedGranted(typeof(GetUserByExternalId)));

		var report = analyzer.Analyze();

		report.GetSummary().Passed.Should().BeTrue();
		report.Issues.Should().NotContain(i => i.Severity == IssueSeverity.Error);
	}

	[Fact]
	public void Plain_authorizable_operation_without_authorizer_still_produces_error() {
		var analyzer = AnalyzerFor(PlainUnprotected(typeof(DeleteWidget)));

		var report = analyzer.Analyze();

		var error = report.Issues.Should().ContainSingle(i => i.Severity == IssueSeverity.Error).Subject;
		error.Description.Should().Contain("have no authorizer defined");
		error.RelatedTypeNames.Should().Contain(typeof(DeleteWidget).FullName);
	}

	[Fact]
	public void Error_names_only_the_plain_operation_not_the_granted_one() {
		var analyzer = AnalyzerFor(
			SelfScopedGranted(typeof(GetUser)),
			PlainUnprotected(typeof(DeleteWidget)));

		var report = analyzer.Analyze();

		var error = report.Issues.Should().ContainSingle(i => i.Severity == IssueSeverity.Error).Subject;
		error.RelatedTypeNames.Should().ContainSingle().Which.Should().Be(typeof(DeleteWidget).FullName);
		error.RelatedTypeNames.Should().NotContain(typeof(GetUser).FullName);
	}

	// Fake operation marker types — the analyzer reads the OperationTypeInfo fields set above
	// and only uses these Types for their names, so they need no interface implementations.
	private sealed record GetUser;
	private sealed record GetUserByExternalId;
	private sealed record DeleteWidget;

}
