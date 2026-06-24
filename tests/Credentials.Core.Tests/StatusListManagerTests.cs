using Credentials;
using Credentials.Status;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.Tests;

/// <summary>Issuer-side status-list production and maintenance (FR-020/021).</summary>
public sealed class StatusListManagerTests
{
    private readonly StatusListManager _manager = new();

    private Credential CreateRevocationList() => _manager.CreateList(new StatusListCreateOptions
    {
        Id = "https://issuer.example/status/1",
        Issuer = "did:example:issuer",
        StatusPurpose = StatusPurpose.Revocation,
    });

    [Fact]
    public void CreateList_produces_a_conformant_unsecured_status_list_credential()
    {
        var list = CreateRevocationList();

        list.Securing.Should().Be(SecuringState.Unsecured);
        list.HasEmbeddedProof.Should().BeFalse();
        list.Type.Should().Contain(StatusListManager.CredentialType);
        list.Type.Should().Contain("VerifiableCredential");

        var subject = list.CredentialSubjects.Should().ContainSingle().Subject;
        subject["type"]!.GetValue<string>().Should().Be(StatusListManager.SubjectType);
        subject["statusPurpose"]!.GetValue<string>().Should().Be(StatusPurpose.Revocation);
        subject["encodedList"]!.GetValue<string>().Should().StartWith("u");
    }

    [Fact]
    public void A_fresh_list_has_every_status_clear()
    {
        var list = CreateRevocationList();

        _manager.GetStatus(list, 0).Should().BeFalse();
        _manager.GetStatus(list, 94_567).Should().BeFalse();
    }

    [Fact]
    public void Revoke_sets_the_bit_and_reproduces_the_list()
    {
        var list = CreateRevocationList();
        var before = list.CredentialSubjects[0]["encodedList"]!.GetValue<string>();

        var revoked = _manager.Revoke(list, 94_567);

        _manager.GetStatus(revoked, 94_567).Should().BeTrue();
        _manager.GetStatus(revoked, 94_566).Should().BeFalse("only the targeted index changes");
        revoked.CredentialSubjects[0]["encodedList"]!.GetValue<string>()
            .Should().NotBe(before, "the re-produced list carries a different encodedList");
        // The original is untouched (frozen source of truth).
        _manager.GetStatus(list, 94_567).Should().BeFalse();
    }

    [Fact]
    public void Reinstate_clears_a_previously_set_bit()
    {
        var revoked = _manager.Revoke(CreateRevocationList(), 10);
        _manager.GetStatus(revoked, 10).Should().BeTrue();

        var reinstated = _manager.Reinstate(revoked, 10);
        _manager.GetStatus(reinstated, 10).Should().BeFalse();
    }

    [Fact]
    public void Suspend_uses_a_separate_purpose_list()
    {
        var suspensionList = _manager.CreateList(new StatusListCreateOptions
        {
            Id = "https://issuer.example/status/suspension",
            Issuer = "did:example:issuer",
            StatusPurpose = StatusPurpose.Suspension,
        });

        suspensionList.CredentialSubjects[0]["statusPurpose"]!.GetValue<string>().Should().Be(StatusPurpose.Suspension);
        var suspended = _manager.Suspend(suspensionList, 3);
        _manager.GetStatus(suspended, 3).Should().BeTrue();
    }

    [Fact]
    public void Updates_survive_a_byte_round_trip()
    {
        var revoked = _manager.Revoke(CreateRevocationList(), 500);
        var reparsed = Credential.Parse(revoked.ToBytes());

        _manager.GetStatus(reparsed, 500).Should().BeTrue();
    }

    [Fact]
    [FrTag("FR-021")]
    public void Set_reproduce_read_then_clear_reproduce_read_round_trips_the_bit()
    {
        const long index = 1_234;

        // Baseline: a freshly produced list reads the index clear.
        var produced = CreateRevocationList();
        _manager.GetStatus(Reproduce(produced), index).Should().BeFalse(
            "a freshly produced list has every bit clear");

        // Set (revoke) → re-produce (serialize→re-parse) → the bit reads back SET.
        var revoked = _manager.Revoke(produced, index);
        var revokedReparsed = Reproduce(revoked);
        _manager.GetStatus(revokedReparsed, index).Should().BeTrue(
            "the re-produced list carries the set bit across a byte round-trip");
        // The re-produced encodedList differs from the baseline — the bitstring was genuinely re-encoded.
        EncodedListOf(revokedReparsed).Should().NotBe(EncodedListOf(produced));

        // Clear (reinstate) → re-produce → the bit reads back CLEAR again.
        var reinstated = _manager.Reinstate(revokedReparsed, index);
        var reinstatedReparsed = Reproduce(reinstated);
        _manager.GetStatus(reinstatedReparsed, index).Should().BeFalse(
            "reinstating clears the bit and the cleared state survives re-production");
    }

    private static Credential Reproduce(Credential statusList) => Credential.Parse(statusList.ToBytes());

    private static string EncodedListOf(Credential statusList) =>
        statusList.CredentialSubjects[0]["encodedList"]!.GetValue<string>();
}
