using System.Globalization;
using System.Text.Json.Nodes;
using Credentials.Json;
using Credentials.Roles;
using Credentials.Verification;

namespace Credentials.Status;

/// <summary>
/// The verifier's credential-status stage (FR-022). For each <c>credentialStatus</c> entry of type
/// <c>BitstringStatusListEntry</c> it: resolves the list via the injected <see cref="IStatusListFetcher"/>;
/// verifies the fetched list credential's <em>own</em> proof recursively through the same
/// <see cref="IVerifier"/> with the validity window enabled (FR-050, fix E2 — a stale or unsigned list is
/// not trusted); asserts the list/subject types and that the entry's purpose is one the list declares (fix
/// E1); decodes the bitstring (bounded against decompression bombs) and reads the bit.
///
/// <para>
/// Never throws (FR-045): a set revocation/suspension bit is <see cref="CheckStatus.Failed"/>; any
/// operational problem (unreachable, unverifiable, stale, malformed, out-of-range) is
/// <see cref="CheckStatus.Indeterminate"/>. Reports <see cref="CheckStatus.Skipped"/> when status checking
/// is disabled, the credential declares no status, or no fetcher is configured.
/// </para>
/// </summary>
internal sealed class StatusStage
{
    private readonly IStatusListFetcher? _fetcher;

    public StatusStage(IStatusListFetcher? fetcher) => _fetcher = fetcher;

    public async Task<CheckResult> EvaluateAsync(
        Credential credential,
        CredentialVerificationOptions options,
        IVerifier verifier,
        CancellationToken cancellationToken)
    {
        if (!options.CheckStatus)
        {
            return CheckResult.Skipped(CheckKinds.Status, "Status checking is disabled for this verification.");
        }

        var entries = credential.CredentialStatus;
        if (entries.Count == 0)
        {
            return CheckResult.Skipped(CheckKinds.Status, "The credential declares no credentialStatus.");
        }

        if (_fetcher is null)
        {
            return CheckResult.Skipped(CheckKinds.Status, "No status-list fetcher is configured.");
        }

        var details = new List<StatusCheckDetail>();
        var diagnostics = new List<CheckDiagnostic>();
        var worst = CheckStatus.Passed;

        var credentialIssuerId = credential.Issuer?.Id;
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var outcome = await EvaluateEntryAsync(entry.Raw, credentialIssuerId, options, verifier, cancellationToken).ConfigureAwait(false);
            worst = Worse(worst, outcome.Status);
            if (outcome.Detail is not null)
            {
                details.Add(outcome.Detail);
            }

            if (outcome.Diagnostic is not null)
            {
                diagnostics.Add(outcome.Diagnostic);
            }
        }

        var detail = new StatusCheckResult { Details = details };
        var result = worst switch
        {
            CheckStatus.Failed => CheckResult.Failed(CheckKinds.Status, diagnostics),
            CheckStatus.Indeterminate => CheckResult.Indeterminate(CheckKinds.Status, diagnostics),
            _ => CheckResult.Passed(CheckKinds.Status),
        };

        return result.WithDetail(detail);
    }

    private async Task<EntryOutcome> EvaluateEntryAsync(
        JsonObject entry,
        string? credentialIssuerId,
        CredentialVerificationOptions options,
        IVerifier verifier,
        CancellationToken cancellationToken)
    {
        var entryType = JsonShape.AsString(entry["type"]);
        if (!string.Equals(entryType, BitstringStatusListEntry.TypeName, StringComparison.Ordinal))
        {
            return EntryOutcome.Indeterminate("status.unsupported_type",
                "The credentialStatus type is not a BitstringStatusListEntry and cannot be checked.");
        }

        var purpose = JsonShape.AsString(entry["statusPurpose"]);
        if (string.IsNullOrEmpty(purpose))
        {
            return EntryOutcome.Indeterminate("status.entry_invalid", "The status entry has no statusPurpose.");
        }

        var indexText = JsonShape.AsString(entry["statusListIndex"]);
        if (indexText is null
            || !long.TryParse(indexText, NumberStyles.None, CultureInfo.InvariantCulture, out var index))
        {
            return EntryOutcome.Indeterminate("status.entry_invalid",
                "The status entry has no valid base-10 statusListIndex.");
        }

        var listUrl = JsonShape.AsString(entry["statusListCredential"]);
        if (string.IsNullOrEmpty(listUrl))
        {
            return EntryOutcome.Indeterminate("status.entry_invalid", "The status entry has no statusListCredential.");
        }

        var statusSize = ReadStatusSize(entry);
        if (statusSize < 1)
        {
            return EntryOutcome.Indeterminate("status.entry_invalid", "statusSize must be a positive integer.");
        }

        // 1. Resolve the list (caller controls egress). A miss is Indeterminate, never a throw.
        StatusListFetchResult fetch;
        try
        {
            var reference = new StatusListReference
            {
                StatusListCredential = listUrl,
                StatusPurpose = purpose,
                StatusListIndex = indexText,
                StatusSize = statusSize,
                Raw = (JsonObject)entry.DeepClone(),
            };
            fetch = await _fetcher!.FetchAsync(reference, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return EntryOutcome.Indeterminate("status.list_unreachable", "The status list could not be retrieved.");
        }

        if (fetch is null || !fetch.IsFound)
        {
            return EntryOutcome.Indeterminate("status.list_unreachable", "The status list could not be retrieved.");
        }

        // 2. Parse the fetched list. A malformed FETCHED list is Indeterminate (it is not the verifier's
        //    own input, so CredentialFormatException must not escape).
        Credential listCredential;
        try
        {
            listCredential = Credential.Parse(fetch.Credential);
        }
        catch (CredentialFormatException)
        {
            return EntryOutcome.Indeterminate("status.list_malformed", "The fetched status list is not a valid credential.");
        }

        // 3. Verify the list credential's OWN proof recursively, with the validity window enabled (E2).
        //    Disable status/schema/trust on the recursion to avoid re-entrancy and extra fetches.
        var innerOptions = new CredentialVerificationOptions
        {
            VerificationTime = options.VerificationTime,
            ClockSkew = options.ClockSkew,
            AcceptVcdm11 = options.AcceptVcdm11,
            Policy = options.Policy,
            CheckStatus = false,
            CheckSchema = false,
            EvaluateIssuerTrust = false,
        };

        var listResult = await verifier.VerifyCredentialAsync(listCredential, innerOptions, cancellationToken).ConfigureAwait(false);
        if (listResult.Decision != VerificationDecision.Accepted)
        {
            return EntryOutcome.Indeterminate("status.list_unverified",
                "The status list credential's own proof did not verify (or it is outside its validity window).");
        }

        // 4. Assert the list and subject types (E1).
        if (!listCredential.Type.Contains(StatusListManager.CredentialType, StringComparer.Ordinal))
        {
            return EntryOutcome.Indeterminate("status.list_type_mismatch",
                "The fetched credential is not a BitstringStatusListCredential.");
        }

        // 4a. Bind the status list to the credential's issuer. The recursive proof check (step 3) only
        //     proves the list is signed by SOMEONE — not by the right someone. Without this, an attacker
        //     who can influence what the fetcher returns (SSRF, cache poisoning, a colluding intermediary)
        //     could substitute an all-clear list validly self-signed by an unrelated DID and silently mask
        //     a real revocation. Require the list issuer to be the credential issuer (cross-issuer status
        //     delegation is not supported in v1; it would need an explicit caller-supplied authority hook).
        var listIssuerId = listCredential.Issuer?.Id;
        if (string.IsNullOrEmpty(credentialIssuerId)
            || !string.Equals(listIssuerId, credentialIssuerId, StringComparison.Ordinal))
        {
            return EntryOutcome.Indeterminate("status.list_issuer_mismatch",
                "The status list is not issued by the credential's issuer.");
        }

        // 5. Find the subject whose declared purpose matches the entry's purpose (E1).
        var subject = FindMatchingSubject(listCredential, purpose);
        if (subject is null)
        {
            return EntryOutcome.Indeterminate("status.purpose_mismatch",
                "No BitstringStatusList subject in the list matches the entry's statusPurpose.");
        }

        var encoded = JsonShape.AsString(subject["encodedList"]);
        if (string.IsNullOrEmpty(encoded))
        {
            return EntryOutcome.Indeterminate("status.list_malformed", "The status list subject has no encodedList.");
        }

        // 6. Decode (bounded) and read the bit(s).
        byte[] bitstring;
        try
        {
            bitstring = StatusBitstring.Decode(encoded);
        }
        catch (FormatException)
        {
            return EntryOutcome.Indeterminate("status.list_decode_error", "The status list bitstring could not be decoded.");
        }

        long position;
        try
        {
            position = checked(index * statusSize);
        }
        catch (OverflowException)
        {
            return EntryOutcome.Indeterminate("status.index_out_of_range", "The status index is outside the status list.");
        }

        try
        {
            if (statusSize == 1)
            {
                var isSet = StatusBitstring.GetBit(bitstring, position);
                return ClassifyBit(purpose, isSet);
            }

            var value = StatusBitstring.GetValue(bitstring, position, statusSize);
            var message = ResolveStatusMessage(entry, subject, value);
            var detail = new StatusCheckDetail { StatusPurpose = purpose, IsSet = value != 0, Value = value, StatusMessage = message };
            // A nonzero multi-bit value still means revoked/suspended for those purposes; only the
            // informational 'message' purpose (and any other) is non-failing.
            if (value != 0 && purpose is StatusPurpose.Revocation or StatusPurpose.Suspension)
            {
                var code = purpose == StatusPurpose.Revocation ? "status.revoked" : "status.suspended";
                var reason = purpose == StatusPurpose.Revocation ? "The credential has been revoked." : "The credential is suspended.";
                return EntryOutcome.Failed(code, reason, detail);
            }

            return EntryOutcome.Passed(detail);
        }
        catch (ArgumentOutOfRangeException)
        {
            return EntryOutcome.Indeterminate("status.index_out_of_range", "The status index is outside the status list.");
        }
    }

    private static EntryOutcome ClassifyBit(string purpose, bool isSet)
    {
        var detail = new StatusCheckDetail { StatusPurpose = purpose, IsSet = isSet };
        if (!isSet)
        {
            return EntryOutcome.Passed(detail);
        }

        return purpose switch
        {
            StatusPurpose.Revocation => EntryOutcome.Failed("status.revoked", "The credential has been revoked.", detail),
            StatusPurpose.Suspension => EntryOutcome.Failed("status.suspended", "The credential is suspended.", detail),
            // A set bit for any other purpose is reported but not treated as a definitive negative.
            _ => EntryOutcome.Passed(detail),
        };
    }

    private static JsonObject? FindMatchingSubject(Credential listCredential, string purpose)
    {
        var subjects = listCredential.CredentialSubjects;
        foreach (var s in subjects)
        {
            var raw = s.Claims;
            if (!string.Equals(JsonShape.AsString(raw["type"]), StatusListManager.SubjectType, StringComparison.Ordinal))
            {
                continue;
            }

            var purposes = JsonShape.ReadStringOrStringArray(raw["statusPurpose"]);
            if (purposes.Contains(purpose, StringComparer.Ordinal))
            {
                return raw;
            }
        }

        return null;
    }

    private static int ReadStatusSize(JsonObject entry)
    {
        var node = entry["statusSize"];
        if (node is null)
        {
            return 1;
        }

        try
        {
            return node.GetValue<int>();
        }
        catch
        {
            return -1; // signals an invalid statusSize to the caller
        }
    }

    private static string? ResolveStatusMessage(JsonObject entry, JsonObject subject, long value)
    {
        var hex = "0x" + value.ToString("x", CultureInfo.InvariantCulture);
        // statusMessage may live on the entry or on the list subject.
        foreach (var source in new[] { entry["statusMessage"], subject["statusMessage"] })
        {
            if (source is JsonArray array)
            {
                foreach (var item in array)
                {
                    if (item is JsonObject obj
                        && string.Equals(JsonShape.AsString(obj["status"]), hex, StringComparison.OrdinalIgnoreCase))
                    {
                        return JsonShape.AsString(obj["message"]);
                    }
                }
            }
        }

        return null;
    }

    private static CheckStatus Worse(CheckStatus a, CheckStatus b)
    {
        // Failed dominates Indeterminate dominates Passed (Skipped never reaches here).
        if (a == CheckStatus.Failed || b == CheckStatus.Failed)
        {
            return CheckStatus.Failed;
        }

        if (a == CheckStatus.Indeterminate || b == CheckStatus.Indeterminate)
        {
            return CheckStatus.Indeterminate;
        }

        return CheckStatus.Passed;
    }

    private readonly record struct EntryOutcome(CheckStatus Status, CheckDiagnostic? Diagnostic, StatusCheckDetail? Detail)
    {
        public static EntryOutcome Passed(StatusCheckDetail detail) => new(CheckStatus.Passed, null, detail);

        public static EntryOutcome Failed(string code, string message, StatusCheckDetail detail) =>
            new(CheckStatus.Failed, new CheckDiagnostic(code, message, DiagnosticSeverity.Error), detail);

        public static EntryOutcome Indeterminate(string code, string message) =>
            new(CheckStatus.Indeterminate, new CheckDiagnostic(code, message, DiagnosticSeverity.Error), null);
    }
}
