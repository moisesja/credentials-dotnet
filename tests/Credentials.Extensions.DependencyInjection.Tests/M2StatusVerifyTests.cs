using System.Text.Json;
using System.Text.Json.Nodes;
using Credentials;
using Credentials.Roles;
using Credentials.Status;
using Credentials.Verification;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NSubstitute;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>
/// M2 end-to-end credential-status verification (FR-022) through the real wiring with a mocked
/// <see cref="IStatusListFetcher"/>. Covers the E1 (list/purpose guards) and E2 (recursive list-proof +
/// validity) fixes, report-don't-throw, and the hook-gating ⇒ Skipped behaviour.
/// </summary>
public sealed class M2StatusVerifyTests
{
    private const string ListUrl = "https://issuer.example/status/1";
    private const long Index = 94_567;

    private static readonly StatusListManager Manager = new();

    private static ServiceProvider BuildProvider(IStatusListFetcher? fetcher) =>
        new ServiceCollection()
            .AddCredentials(b =>
            {
                b.UseNetDid();
                if (fetcher is not null)
                {
                    b.UseStatusListFetcher(fetcher);
                }
            })
            .BuildServiceProvider();

    // A subject credential that references the status list.
    private static async Task<Credential> IssueSubjectAsync(IIssuer issuer, TestKey key, string purpose = StatusPurpose.Revocation)
    {
        var unsecured = Credential.Build()
            .WithId("urn:uuid:22222222-2222-2222-2222-222222222222")
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .AddStatus(BitstringStatusListEntry.Create(purpose, Index, ListUrl))
            .Seal();

        var issued = await issuer.IssueAsync(unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
        return issued.Credential;
    }

    // A signed status list VC with the bit at Index set/clear (or an explicit purpose / validity window).
    private static async Task<byte[]> IssueStatusListAsync(
        IIssuer issuer, TestKey key, bool revoked, string purpose = StatusPurpose.Revocation,
        DateTimeOffset? validUntil = null)
    {
        var list = Manager.CreateList(new StatusListCreateOptions
        {
            Id = ListUrl,
            Issuer = key.Did,
            StatusPurpose = purpose,
            ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
            ValidUntil = validUntil,
        });

        if (revoked)
        {
            list = Manager.WithStatus(list, Index, isSet: true);
        }

        var issued = await issuer.IssueAsync(list,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
        return issued.Credential.ToBytes();
    }

    private static IStatusListFetcher FetcherReturning(byte[] listBytes)
    {
        var fetcher = Substitute.For<IStatusListFetcher>();
        fetcher.FetchAsync(Arg.Any<StatusListReference>(), Arg.Any<CancellationToken>())
            .Returns(StatusListFetchResult.Found(listBytes));
        return fetcher;
    }

    [Fact]
    public async Task Clear_bit_passes_status_and_accepts()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var listBytes = await IssueStatusListWith(key, revoked: false);
        using var provider = BuildProvider(FetcherReturning(listBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);

        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Passed, result.ToString());
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task Revoked_bit_fails_status_and_rejects()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var listBytes = await IssueStatusListWith(key, revoked: true);
        using var provider = BuildProvider(FetcherReturning(listBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);

        var status = result.Check(CheckKinds.Status)!;
        status.Status.Should().Be(CheckStatus.Failed);
        status.Diagnostics.Should().Contain(d => d.Code == "status.revoked");
        result.Decision.Should().Be(VerificationDecision.Rejected);
        // The proof itself is valid — only status fails.
        result.Check(CheckKinds.Proof)!.Status.Should().Be(CheckStatus.Passed);
    }

    [Fact]
    public async Task Suspended_then_reinstated()
    {
        var key = TestKeys.New(KeyType.Ed25519);

        // Suspended: the suspension-purpose list has the bit set.
        var suspendedBytes = await IssueStatusListWith(key, revoked: true, purpose: StatusPurpose.Suspension);
        using (var provider = BuildProvider(FetcherReturning(suspendedBytes)))
        {
            var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, StatusPurpose.Suspension);
            var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
            var status = result.Check(CheckKinds.Status)!;
            status.Status.Should().Be(CheckStatus.Failed);
            status.Diagnostics.Should().Contain(d => d.Code == "status.suspended");
        }

        // Reinstated: the bit is cleared.
        var reinstatedBytes = await IssueStatusListWith(key, revoked: false, purpose: StatusPurpose.Suspension);
        using (var provider = BuildProvider(FetcherReturning(reinstatedBytes)))
        {
            var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, StatusPurpose.Suspension);
            var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
            result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Passed);
        }
    }

    [Fact]
    public async Task Unreachable_list_is_indeterminate_and_fail_closed_rejects()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var fetcher = Substitute.For<IStatusListFetcher>();
        fetcher.FetchAsync(Arg.Any<StatusListReference>(), Arg.Any<CancellationToken>())
            .Returns(StatusListFetchResult.NotFound("list_unreachable"));
        using var provider = BuildProvider(fetcher);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);

        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Indeterminate);
        result.Decision.Should().Be(VerificationDecision.Rejected); // fail-closed default
    }

    [Fact]
    public async Task Tampered_list_proof_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var listBytes = await IssueStatusListWith(key, revoked: false);

        // Tamper the signed status list: flip its encodedList after signing → its own proof no longer verifies.
        var node = JsonNode.Parse(listBytes)!.AsObject();
        var subjectNode = node["credentialSubject"]!.AsObject();
        subjectNode["encodedList"] = subjectNode["encodedList"]!.GetValue<string>() + "AA";
        var tampered = JsonSerializer.SerializeToUtf8Bytes(node);

        using var provider = BuildProvider(FetcherReturning(tampered));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Indeterminate, "a list with a broken proof is not trusted (E2)");
    }

    [Fact]
    public async Task Expired_list_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        byte[] listBytes;
        using (var seed = BuildProvider(null))
        {
            listBytes = await IssueStatusListAsync(
                seed.GetRequiredService<IIssuer>(), key, revoked: false,
                validUntil: DateTimeOffset.UtcNow.AddDays(-1)); // expired window
        }

        using var provider = BuildProvider(FetcherReturning(listBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Indeterminate, "a stale list is not trusted (E2 validity)");
    }

    [Fact]
    public async Task Purpose_mismatch_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        // The list is a revocation list, but the entry declares suspension.
        var listBytes = await IssueStatusListWith(key, revoked: false, purpose: StatusPurpose.Revocation);
        using var provider = BuildProvider(FetcherReturning(listBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key, StatusPurpose.Suspension);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var status = result.Check(CheckKinds.Status)!;
        status.Status.Should().Be(CheckStatus.Indeterminate);
        status.Diagnostics.Should().Contain(d => d.Code == "status.purpose_mismatch");
    }

    [Fact]
    public async Task Wrong_list_type_is_indeterminate()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        // Return a plain (non-status-list) signed credential as the "list".
        using var seed = BuildProvider(null);
        var issuer = seed.GetRequiredService<IIssuer>();
        var plain = Credential.Build().WithIssuer(key.Did).AddSubject(new JsonObject { ["id"] = "did:example:x" }).Seal();
        var issuedPlain = await issuer.IssueAsync(plain,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        using var provider = BuildProvider(FetcherReturning(issuedPlain.Credential.ToBytes()));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var status = result.Check(CheckKinds.Status)!;
        status.Status.Should().Be(CheckStatus.Indeterminate);
        status.Diagnostics.Should().Contain(d => d.Code == "status.list_type_mismatch");
    }

    [Fact]
    public async Task A_list_signed_by_a_different_issuer_is_indeterminate_no_revocation_masking()
    {
        // Adversarial HIGH: an attacker who controls what the fetcher returns substitutes an all-clear list
        // validly self-signed by an UNRELATED issuer. The list's own proof verifies, but it is not the
        // credential's issuer, so it must NOT be trusted (no revocation masking).
        var credentialKey = TestKeys.New(KeyType.Ed25519);
        var attackerKey = TestKeys.New(KeyType.Ed25519);

        // All-clear list, validly signed by the attacker (issuer = attacker, not the credential issuer).
        byte[] forgedList;
        using (var seed = BuildProvider(null))
        {
            forgedList = await IssueStatusListAsync(seed.GetRequiredService<IIssuer>(), attackerKey, revoked: false);
        }

        using var provider = BuildProvider(FetcherReturning(forgedList));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), credentialKey);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        var status = result.Check(CheckKinds.Status)!;
        status.Status.Should().Be(CheckStatus.Indeterminate);
        status.Diagnostics.Should().Contain(d => d.Code == "status.list_issuer_mismatch");
        result.Decision.Should().Be(VerificationDecision.Rejected); // fail-closed
    }

    [Fact]
    public async Task Multi_bit_revocation_with_nonzero_value_fails()
    {
        // Adversarial LOW: a statusSize>1 revocation slot with a nonzero value still means revoked.
        var key = TestKeys.New(KeyType.Ed25519);

        byte[] listBytes;
        using (var seed = BuildProvider(null))
        {
            var issuer = seed.GetRequiredService<IIssuer>();
            var list = Manager.CreateList(new StatusListCreateOptions
            {
                Id = ListUrl,
                Issuer = key.Did,
                StatusPurpose = StatusPurpose.Revocation,
                LengthBits = StatusBitstring.MinimumBits * 2, // ≥131,072 ENTRIES at statusSize 2
            });
            // statusSize 2, entry index 5, value 0b11 (3) — the manager computes the bit position.
            list = Manager.WithStatusValue(list, entryIndex: 5, value: 3, statusSize: 2);
            var issued = await issuer.IssueAsync(list,
                new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
            listBytes = issued.Credential.ToBytes();
        }

        using var provider = BuildProvider(FetcherReturning(listBytes));
        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .AddStatus(BitstringStatusListEntry.Create(StatusPurpose.Revocation, 5, ListUrl, statusSize: 2))
            .Seal();
        var issuedSubject = await provider.GetRequiredService<IIssuer>().IssueAsync(unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(issuedSubject.Credential);
        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Failed);
        result.Check(CheckKinds.Status)!.Diagnostics.Should().Contain(d => d.Code == "status.revoked");
    }

    [Fact]
    public async Task Revocation_at_the_last_valid_index_is_read_correctly()
    {
        // Boundary / off-by-one guard: the highest index in the 131,072-bit minimum list.
        const long lastIndex = StatusBitstring.MinimumBits - 1;
        var key = TestKeys.New(KeyType.Ed25519);

        byte[] listBytes;
        using (var seed = BuildProvider(null))
        {
            var list = Manager.CreateList(new StatusListCreateOptions
            {
                Id = ListUrl, Issuer = key.Did, StatusPurpose = StatusPurpose.Revocation,
            });
            list = Manager.Revoke(list, lastIndex);
            var issued = await seed.GetRequiredService<IIssuer>().IssueAsync(list,
                new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
            listBytes = issued.Credential.ToBytes();
        }

        using var provider = BuildProvider(FetcherReturning(listBytes));
        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .AddStatus(BitstringStatusListEntry.Create(StatusPurpose.Revocation, lastIndex, ListUrl))
            .Seal();
        var issuedSubject = await provider.GetRequiredService<IIssuer>().IssueAsync(unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(issuedSubject.Credential);
        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Failed);
        result.Check(CheckKinds.Status)!.Diagnostics.Should().Contain(d => d.Code == "status.revoked");
    }

    [Fact]
    public async Task Multi_bit_message_status_surfaces_the_status_message_and_passes()
    {
        // statusMessage hex lookup (a hit): a 2-bit 'message' status with value 2 ⇒ "rejected", informational
        // (Passed), and the resolved message is on the status detail.
        var key = TestKeys.New(KeyType.Ed25519);

        byte[] listBytes;
        using (var seed = BuildProvider(null))
        {
            var list = Manager.CreateList(new StatusListCreateOptions
            {
                Id = ListUrl, Issuer = key.Did, StatusPurpose = StatusPurpose.Message,
                LengthBits = StatusBitstring.MinimumBits * 2, // ≥131,072 ENTRIES at statusSize 2
            });
            list = Manager.WithStatusValue(list, entryIndex: 7, value: 2, statusSize: 2);
            var issued = await seed.GetRequiredService<IIssuer>().IssueAsync(list,
                new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });
            listBytes = issued.Credential.ToBytes();
        }

        using var provider = BuildProvider(FetcherReturning(listBytes));
        var statusEntry = new JsonObject
        {
            ["type"] = BitstringStatusListEntry.TypeName,
            ["statusPurpose"] = StatusPurpose.Message,
            ["statusListIndex"] = "7",
            ["statusListCredential"] = ListUrl,
            ["statusSize"] = 2,
            ["statusMessage"] = new JsonArray(
                new JsonObject { ["status"] = "0x0", ["message"] = "pending" },
                new JsonObject { ["status"] = "0x1", ["message"] = "accepted" },
                new JsonObject { ["status"] = "0x2", ["message"] = "rejected" },
                new JsonObject { ["status"] = "0x3", ["message"] = "revoked" }),
        };
        var unsecured = Credential.Build()
            .WithIssuer(key.Did)
            .AddSubject(new JsonObject { ["id"] = "did:example:subject" })
            .AddStatus(statusEntry)
            .Seal();
        var issuedSubject = await provider.GetRequiredService<IIssuer>().IssueAsync(unsecured,
            new DataIntegrityIssuanceRequest { Cryptosuite = "eddsa-jcs-2022", Signer = key.Signer, VerificationMethod = key.VerificationMethod });

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(issuedSubject.Credential);
        var status = result.Check(CheckKinds.Status)!;
        status.Status.Should().Be(CheckStatus.Passed, "the 'message' purpose is informational");
        var detail = status.GetDetail<StatusCheckResult>();
        detail.Should().NotBeNull();
        detail!.Details.Should().ContainSingle()
            .Which.Should().Match<StatusCheckDetail>(d => d.Value == 2 && d.StatusMessage == "rejected");
    }

    [Fact]
    public async Task No_fetcher_configured_skips_status()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        using var provider = BuildProvider(fetcher: null);
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>().VerifyCredentialAsync(subject);
        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Skipped);
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    [Fact]
    public async Task CheckStatus_false_skips_status()
    {
        var key = TestKeys.New(KeyType.Ed25519);
        var listBytes = await IssueStatusListWith(key, revoked: true); // would otherwise reject
        using var provider = BuildProvider(FetcherReturning(listBytes));
        var subject = await IssueSubjectAsync(provider.GetRequiredService<IIssuer>(), key);

        var result = await provider.GetRequiredService<IVerifier>()
            .VerifyCredentialAsync(subject, new CredentialVerificationOptions { CheckStatus = false });

        result.Check(CheckKinds.Status)!.Status.Should().Be(CheckStatus.Skipped);
        result.Decision.Should().Be(VerificationDecision.Accepted);
    }

    // Convenience: issue a status list using a throwaway provider's issuer.
    private static async Task<byte[]> IssueStatusListWith(TestKey key, bool revoked, string purpose = StatusPurpose.Revocation)
    {
        using var provider = BuildProvider(null);
        return await IssueStatusListAsync(provider.GetRequiredService<IIssuer>(), key, revoked, purpose);
    }
}
