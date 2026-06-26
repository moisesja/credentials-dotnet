using Credentials.Resolution;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>
/// The tri-state resolution structs must fail closed by default (F7): a <c>default</c>-constructed (or
/// otherwise zero-initialized) value must NOT present as <c>Resolved</c>, or a consumer would treat its
/// null / empty key material as a verified verification method. The success state is therefore a non-zero
/// enum value; these tests pin that invariant so a future reorder cannot silently reintroduce the footgun.
/// </summary>
public sealed class TriStateResolutionDefaultsTests
{
    [Fact]
    public void Default_verification_method_resolution_fails_closed()
    {
        default(VerificationMethodResolution).Status.Should().NotBe(VerificationMethodResolutionStatus.Resolved);
        default(VerificationMethodResolution).Method.Should().BeNull();
    }

    [Fact]
    public void Default_envelope_key_resolution_fails_closed()
    {
        default(EnvelopeKeyResolution).Status.Should().NotBe(EnvelopeKeyResolutionStatus.Resolved);
    }
}
