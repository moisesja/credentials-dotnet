using Credentials.TestSupport;
using Credentials.Validation;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// M7 (FR-044 / D1): the validity window is projected from the version-correct members — 2.0 reads
/// <c>validFrom</c>/<c>validUntil</c>, 1.1 reads <c>issuanceDate</c>/<c>expirationDate</c> — in one place,
/// without rewriting the document (no upgrade).
/// </summary>
public sealed class ValidityProjectionTests
{
    [Fact]
    public void V1_reads_issuanceDate_and_expirationDate()
    {
        var c = TestVectors.ValidV1Credential();
        c["expirationDate"] = "2030-01-01T00:00:00Z";

        ValidityProjection.GetValidFrom(c, VcdmVersion.V1_1)
            .Should().Be(DateTimeOffset.Parse("2020-01-01T00:00:00Z"));
        ValidityProjection.GetValidUntil(c, VcdmVersion.V1_1)
            .Should().Be(DateTimeOffset.Parse("2030-01-01T00:00:00Z"));
    }

    [Fact]
    public void V1_ignores_v2_members()
    {
        // A 1.1 document is NOT read through 2.0 members — validFrom/validUntil are invisible to the 1.1
        // projection, so a stray 2.0 member cannot masquerade as the 1.1 window (no cross-version read).
        var c = TestVectors.ValidV1Credential();
        c["validFrom"] = "1999-01-01T00:00:00Z";
        c["validUntil"] = "1999-12-31T00:00:00Z";

        ValidityProjection.GetValidFrom(c, VcdmVersion.V1_1)
            .Should().Be(DateTimeOffset.Parse("2020-01-01T00:00:00Z")); // issuanceDate, not validFrom
        ValidityProjection.GetValidUntil(c, VcdmVersion.V1_1).Should().BeNull(); // no expirationDate present
    }

    [Fact]
    public void V1_missing_expirationDate_is_unbounded()
    {
        var c = TestVectors.ValidV1Credential(); // issuanceDate only
        ValidityProjection.GetValidUntil(c, VcdmVersion.V1_1).Should().BeNull();
    }

    [Fact]
    [FrTag("FR-044")]
    public void V2_reads_validFrom_and_validUntil()
    {
        var c = TestVectors.ValidV2Credential();
        c["validUntil"] = "2030-01-01T00:00:00Z";

        ValidityProjection.GetValidFrom(c, VcdmVersion.V2_0)
            .Should().Be(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        ValidityProjection.GetValidUntil(c, VcdmVersion.V2_0)
            .Should().Be(DateTimeOffset.Parse("2030-01-01T00:00:00Z"));
    }

    [Fact]
    public void V2_ignores_v1_members()
    {
        // The mirror of V1_ignores_v2_members: a 2.0 document is read only through 2.0 members — a stray
        // issuanceDate/expirationDate cannot masquerade as the 2.0 window (no cross-version read).
        var c = TestVectors.ValidV2Credential();
        c["issuanceDate"] = "1999-01-01T00:00:00Z";
        c["expirationDate"] = "1999-12-31T00:00:00Z";

        ValidityProjection.GetValidFrom(c, VcdmVersion.V2_0)
            .Should().Be(DateTimeOffset.Parse("2026-01-01T00:00:00Z")); // validFrom, not issuanceDate
        ValidityProjection.GetValidUntil(c, VcdmVersion.V2_0).Should().BeNull(); // no validUntil present
    }
}
