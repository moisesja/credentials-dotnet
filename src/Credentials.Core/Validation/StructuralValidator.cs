using System.Text.Json.Nodes;
using Credentials.Json;

namespace Credentials.Validation;

/// <summary>
/// Version-aware VCDM 2.0 / 1.1 structural conformance validation over the raw document node (not a
/// lossy projection). This is the single validator used both at issuance
/// (<see cref="CredentialBuilder.Seal"/>, pinned to <see cref="VcdmVersion.V2_0"/> — D8) and on the
/// verification path (version detected from the document). It folds in the conformance fixes:
/// A1 exact base-context match, A3 type shape + base-type presence, B1 credentialSubject shape,
/// C1 strict <c>xsd:dateTimeStamp</c>, C2 validity-window ordering, D1 positive version detection +
/// version/date-member consistency, F8 version-detected presentations, and H2–H4 typed-member
/// requirements.
/// </summary>
public static class StructuralValidator
{
    /// <summary>
    /// Validates <paramref name="root"/> in the given <paramref name="role"/> against the given
    /// <paramref name="version"/>. Never throws on malformed content — every problem is returned in
    /// the result (FR-045). Pass <see cref="VcdmVersion.Unknown"/> only when version detection itself
    /// failed; the validator will report it.
    /// </summary>
    public static StructuralValidationResult Validate(JsonObject root, VcRole role, VcdmVersion version)
    {
        ArgumentNullException.ThrowIfNull(root);

        var problems = new List<StructuralProblem>();
        var baseType = role == VcRole.Credential ? "VerifiableCredential" : "VerifiablePresentation";

        ValidateContext(root, version, problems);
        ValidateType(root, baseType, problems);
        ValidateId(root, problems);

        if (role == VcRole.Credential)
        {
            ValidateIssuer(root, problems);
            ValidateCredentialSubject(root, problems);
            ValidateValidity(root, version, problems);
            ValidateTypedEntries(root, "credentialStatus", requireId: false, problems);
            ValidateTypedEntries(root, "credentialSchema", requireId: true, problems);
            ValidateTypedEntries(root, "refreshService", requireId: false, problems);
            ValidateTypedEntries(root, "termsOfUse", requireId: false, problems);
            ValidateTypedEntries(root, "evidence", requireId: false, problems);
            ValidateRelatedResource(root, problems);
            ValidateNameAndDescription(root, string.Empty, problems);
            if (root["issuer"] is JsonObject issuerObject)
            {
                ValidateNameAndDescription(issuerObject, "/issuer", problems);
            }
        }
        else
        {
            ValidateHolder(root, problems);
        }

        return problems.Count == 0 ? StructuralValidationResult.Valid : new StructuralValidationResult(problems);
    }

    // A1 + D1: @context must be a non-empty array whose first entry is the exact base URL for the version.
    private static void ValidateContext(JsonObject root, VcdmVersion version, List<StructuralProblem> problems)
    {
        var context = root["@context"];
        if (context is null)
        {
            problems.Add(new StructuralProblem("context.missing", "/@context", "@context is required."));
        }
        else if (context is JsonArray array)
        {
            if (array.Count == 0)
            {
                problems.Add(new StructuralProblem("context.empty", "/@context", "@context must not be empty."));
            }
            else if (!JsonShape.IsString(array[0]))
            {
                // An object (or any non-string) at index 0 is a distinct failure from a wrong URL (A1).
                problems.Add(new StructuralProblem("context.index0_not_string", "/@context/0",
                    "The first @context entry must be the base context URL string."));
            }
            else
            {
                var expected = VersionProjection.BaseContextFor(version);
                var actual = JsonShape.AsString(array[0]);
                if (expected is not null && actual != expected)
                {
                    problems.Add(new StructuralProblem("context.index0_mismatch", "/@context/0",
                        $"The first @context entry must be '{expected}'."));
                }
            }

            // Every subsequent @context entry must be a string IRI or a context object (A1);
            // numbers, booleans, and null are non-conformant.
            for (var i = 1; i < array.Count; i++)
            {
                if (!JsonShape.IsString(array[i]) && array[i] is not JsonObject)
                {
                    problems.Add(new StructuralProblem("context.invalid_entry", $"/@context/{i}",
                        "Each @context entry must be a string or a context object."));
                }
            }
        }
        else
        {
            // VCDM requires @context to be an ordered array; a bare string or object is non-conformant.
            problems.Add(new StructuralProblem("context.not_array", "/@context", "@context must be an array."));
        }

        if (version == VcdmVersion.Unknown)
        {
            problems.Add(new StructuralProblem("version.unknown", "/@context/0",
                "The base @context URL did not match a known VCDM version (1.1 or 2.0)."));
        }
    }

    // A3: type is a string or non-empty array of strings, and includes the required base type.
    private static void ValidateType(JsonObject root, string baseType, List<StructuralProblem> problems)
    {
        var typeNode = root["type"];
        if (typeNode is null)
        {
            problems.Add(new StructuralProblem("type.missing", "/type", "type is required."));
            return;
        }

        IReadOnlyList<string>? types = null;
        if (JsonShape.IsString(typeNode))
        {
            types = [JsonShape.AsString(typeNode)!];
        }
        else if (typeNode is JsonArray array && array.Count > 0 && JsonShape.AllStrings(array))
        {
            types = JsonShape.ReadStringOrStringArray(array);
        }

        if (types is null)
        {
            problems.Add(new StructuralProblem("type.invalid_shape", "/type",
                "type must be a string or a non-empty array of strings."));
            return;
        }

        if (!types.Contains(baseType, StringComparer.Ordinal))
        {
            problems.Add(new StructuralProblem("type.missing_base", "/type", $"type must include '{baseType}'."));
        }
    }

    // H2: id, where present, is a single non-blank string that is a URL (an absolute URI). A present-but-null
    // value or a multi-valued (array) id is rejected too — the suite tests `id: null` and multi-valued ids.
    private static void ValidateId(JsonObject root, List<StructuralProblem> problems)
    {
        if (!root.ContainsKey("id"))
        {
            return;
        }

        var id = root["id"];
        if (!JsonShape.IsNonBlankString(id))
        {
            problems.Add(new StructuralProblem("id.invalid", "/id", "id must be a single non-empty string URL."));
        }
        else if (!JsonShape.IsAbsoluteUri(id))
        {
            problems.Add(new StructuralProblem("id.not_url", "/id", "id must be a URL (an absolute URI with a scheme)."));
        }
    }

    // H3: issuer is a non-blank string or an object; an object issuer requires a non-blank id.
    private static void ValidateIssuer(JsonObject root, List<StructuralProblem> problems)
    {
        var issuer = root["issuer"];
        switch (issuer)
        {
            case null:
                problems.Add(new StructuralProblem("issuer.missing", "/issuer", "issuer is required."));
                break;
            case JsonObject obj when !JsonShape.IsNonBlankString(obj["id"]):
                problems.Add(new StructuralProblem("issuer.object_missing_id", "/issuer/id",
                    "An object-form issuer must have a non-empty string id."));
                break;
            case JsonObject obj when !JsonShape.IsAbsoluteUri(obj["id"]):
                problems.Add(new StructuralProblem("issuer.id_not_url", "/issuer/id",
                    "An object-form issuer's id must be a URL (an absolute URI with a scheme)."));
                break;
            case JsonObject:
                break;
            default:
                if (!JsonShape.IsNonBlankString(issuer))
                {
                    problems.Add(new StructuralProblem("issuer.invalid_shape", "/issuer",
                        "issuer must be a non-empty string or an object with an id."));
                }
                else if (!JsonShape.IsAbsoluteUri(issuer))
                {
                    problems.Add(new StructuralProblem("issuer.not_url", "/issuer",
                        "issuer must be a URL (an absolute URI with a scheme)."));
                }

                break;
        }
    }

    // B1: credentialSubject is a non-empty object or non-empty array of objects.
    private static void ValidateCredentialSubject(JsonObject root, List<StructuralProblem> problems)
    {
        var subject = root["credentialSubject"];
        switch (subject)
        {
            case null:
                problems.Add(new StructuralProblem("subject.missing", "/credentialSubject",
                    "credentialSubject is required."));
                break;
            case JsonObject obj when obj.Count == 0:
                problems.Add(new StructuralProblem("subject.empty", "/credentialSubject",
                    "credentialSubject must not be empty."));
                break;
            case JsonObject obj:
                ValidateSubjectId(obj, "/credentialSubject", problems);
                break;
            case JsonArray array when array.Count == 0:
                problems.Add(new StructuralProblem("subject.empty", "/credentialSubject",
                    "credentialSubject must not be an empty array."));
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    switch (array[i])
                    {
                        case JsonObject { Count: 0 }:
                            problems.Add(new StructuralProblem("subject.empty", $"/credentialSubject/{i}",
                                "Each credentialSubject entry must not be empty."));
                            break;
                        case JsonObject entry:
                            ValidateSubjectId(entry, $"/credentialSubject/{i}", problems);
                            break;
                        default:
                            problems.Add(new StructuralProblem("subject.invalid_shape", $"/credentialSubject/{i}",
                                "Each credentialSubject entry must be an object."));
                            break;
                    }
                }

                break;
            default:
                problems.Add(new StructuralProblem("subject.invalid_shape", "/credentialSubject",
                    "credentialSubject must be an object or an array of objects."));
                break;
        }
    }

    // C1 + C2 + D1: version-correct validity members, strict dateTimeStamp, non-inverted window.
    private static void ValidateValidity(JsonObject root, VcdmVersion version, List<StructuralProblem> problems)
    {
        switch (version)
        {
            case VcdmVersion.V2_0:
                ForbidMember(root, "issuanceDate", "version.mismatch_dates_v2",
                    "VCDM 2.0 uses validFrom, not issuanceDate.", problems);
                ForbidMember(root, "expirationDate", "version.mismatch_dates_v2",
                    "VCDM 2.0 uses validUntil, not expirationDate.", problems);
                ValidateWindow(root, "validFrom", "validUntil", problems);
                break;

            case VcdmVersion.V1_1:
                if (root["issuanceDate"] is null)
                {
                    problems.Add(new StructuralProblem("version.missing_issuanceDate_v11", "/issuanceDate",
                        "VCDM 1.1 requires issuanceDate."));
                }

                ForbidMember(root, "validFrom", "version.mismatch_dates_v11",
                    "VCDM 1.1 uses issuanceDate, not validFrom.", problems);
                ForbidMember(root, "validUntil", "version.mismatch_dates_v11",
                    "VCDM 1.1 uses expirationDate, not validUntil.", problems);
                ValidateWindow(root, "issuanceDate", "expirationDate", problems);
                break;

            default:
                // Unknown version is already reported by ValidateContext; still check any present member's format.
                ValidateWindow(root, "validFrom", "validUntil", problems);
                ValidateWindow(root, "issuanceDate", "expirationDate", problems);
                break;
        }
    }

    private static void ValidateWindow(JsonObject root, string fromMember, string untilMember, List<StructuralProblem> problems)
    {
        var from = ValidateTimestamp(root, fromMember, problems);
        var until = ValidateTimestamp(root, untilMember, problems);
        if (from is not null && until is not null && until < from)
        {
            problems.Add(new StructuralProblem("validity.window_inverted", $"/{untilMember}",
                $"{untilMember} must not be earlier than {fromMember}."));
        }
    }

    private static DateTimeOffset? ValidateTimestamp(JsonObject root, string member, List<StructuralProblem> problems)
    {
        var node = root[member];
        if (node is null)
        {
            return null;
        }

        if (!JsonShape.IsString(node) || !Rfc3339.TryParse(JsonShape.AsString(node), out var value))
        {
            problems.Add(new StructuralProblem($"validity.{member}_invalid", $"/{member}",
                $"{member} must be an xsd:dateTimeStamp with a timezone offset."));
            return null;
        }

        return value;
    }

    private static void ForbidMember(JsonObject root, string member, string code, string message, List<StructuralProblem> problems)
    {
        if (root[member] is not null)
        {
            problems.Add(new StructuralProblem(code, $"/{member}", message));
        }
    }

    // H4: each entry of credentialStatus/credentialSchema/termsOfUse/evidence requires a type
    // (and, for credentialSchema, an id).
    private static void ValidateTypedEntries(JsonObject root, string member, bool requireId, List<StructuralProblem> problems)
    {
        var node = root[member];
        if (node is null)
        {
            return;
        }

        switch (node)
        {
            case JsonObject obj:
                ValidateTypedEntry(obj, member, $"/{member}", requireId, problems);
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    if (array[i] is JsonObject entry)
                    {
                        ValidateTypedEntry(entry, member, $"/{member}/{i}", requireId, problems);
                    }
                    else
                    {
                        problems.Add(new StructuralProblem($"{member}.invalid_shape", $"/{member}/{i}",
                            $"Each {member} entry must be an object."));
                    }
                }

                break;
            default:
                problems.Add(new StructuralProblem($"{member}.invalid_shape", $"/{member}",
                    $"{member} must be an object or an array of objects."));
                break;
        }
    }

    private static void ValidateTypedEntry(JsonObject entry, string member, string pointer, bool requireId, List<StructuralProblem> problems)
    {
        if (!JsonShape.IsNonBlankString(entry["type"]) && !JsonShape.IsNonBlankStringArray(entry["type"]))
        {
            problems.Add(new StructuralProblem($"{member}.missing_type", $"{pointer}/type",
                $"Each {member} entry requires a non-empty type."));
        }

        if (requireId && !JsonShape.IsNonBlankString(entry["id"]))
        {
            problems.Add(new StructuralProblem($"{member}.missing_id", $"{pointer}/id",
                $"Each {member} entry requires a non-empty string id."));
        }
        else if (entry.ContainsKey("id") && !JsonShape.IsAbsoluteUri(entry["id"]))
        {
            // A present id (whether or not the member requires one) must be a single URL — this also rejects
            // a null id, an array of ids, and a non-URI string.
            problems.Add(new StructuralProblem($"{member}.id_not_url", $"{pointer}/id",
                $"A {member} id must be a single URL (an absolute URI with a scheme)."));
        }
    }

    // A credentialSubject id, where present, is a single URL (absolute URI) — rejects null / array / non-URI.
    private static void ValidateSubjectId(JsonObject subject, string pointer, List<StructuralProblem> problems)
    {
        if (subject.ContainsKey("id") && !JsonShape.IsAbsoluteUri(subject["id"]))
        {
            problems.Add(new StructuralProblem("subject.id_not_url", $"{pointer}/id",
                "A credentialSubject id must be a single URL (an absolute URI with a scheme)."));
        }
    }

    // §5.3: relatedResource is one or more objects; each requires a URL id, a unique id across the list,
    // and at least one of digestSRI / digestMultibase. (Verifying the digest against the fetched bytes is a
    // separate, verifier-side concern, deferred from this structural pass.)
    private static void ValidateRelatedResource(JsonObject root, List<StructuralProblem> problems)
    {
        if (!root.ContainsKey("relatedResource"))
        {
            return;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        switch (root["relatedResource"])
        {
            case JsonObject obj:
                ValidateRelatedResourceEntry(obj, "/relatedResource", seen, problems);
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    if (array[i] is JsonObject entry)
                    {
                        ValidateRelatedResourceEntry(entry, $"/relatedResource/{i}", seen, problems);
                    }
                    else
                    {
                        problems.Add(new StructuralProblem("relatedResource.not_object", $"/relatedResource/{i}",
                            "Each relatedResource entry must be an object."));
                    }
                }

                break;
            default:
                problems.Add(new StructuralProblem("relatedResource.not_object", "/relatedResource",
                    "relatedResource must be an object or an array of objects."));
                break;
        }
    }

    private static void ValidateRelatedResourceEntry(JsonObject entry, string pointer, HashSet<string> seen, List<StructuralProblem> problems)
    {
        if (!JsonShape.IsNonBlankString(entry["id"]))
        {
            problems.Add(new StructuralProblem("relatedResource.missing_id", $"{pointer}/id",
                "Each relatedResource entry requires a non-empty string id."));
        }
        else if (!JsonShape.IsAbsoluteUri(entry["id"]))
        {
            problems.Add(new StructuralProblem("relatedResource.id_not_url", $"{pointer}/id",
                "A relatedResource id must be a URL (an absolute URI with a scheme)."));
        }
        else if (!seen.Add(JsonShape.AsString(entry["id"])!))
        {
            problems.Add(new StructuralProblem("relatedResource.duplicate_id", $"{pointer}/id",
                "Each relatedResource id must be unique across the list."));
        }

        if (!JsonShape.IsNonBlankString(entry["digestSRI"]) && !JsonShape.IsNonBlankString(entry["digestMultibase"]))
        {
            problems.Add(new StructuralProblem("relatedResource.missing_digest", pointer,
                "Each relatedResource entry must have a digestSRI or digestMultibase."));
        }
    }

    // §11.1: name / description, where present, is a string or a language value object (or an array of
    // them). A language value object is closed — only @value, @language and @direction are permitted.
    private static void ValidateNameAndDescription(JsonObject container, string basePointer, List<StructuralProblem> problems)
    {
        ValidateLanguageValue(container, "name", basePointer, problems);
        ValidateLanguageValue(container, "description", basePointer, problems);
    }

    private static void ValidateLanguageValue(JsonObject container, string member, string basePointer, List<StructuralProblem> problems)
    {
        var node = container[member];
        if (node is null || JsonShape.IsString(node))
        {
            return; // absent, or a plain string — always valid
        }

        switch (node)
        {
            case JsonObject obj:
                ValidateLanguageObject(obj, member, $"{basePointer}/{member}", problems);
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    if (array[i] is JsonObject entry)
                    {
                        ValidateLanguageObject(entry, member, $"{basePointer}/{member}/{i}", problems);
                    }
                    else if (!JsonShape.IsString(array[i]))
                    {
                        problems.Add(new StructuralProblem($"{member}.invalid_language_object", $"{basePointer}/{member}/{i}",
                            $"Each {member} entry must be a string or a language value object."));
                    }
                }

                break;
            default:
                problems.Add(new StructuralProblem($"{member}.invalid_language_object", $"{basePointer}/{member}",
                    $"{member} must be a string, a language value object, or an array of them."));
                break;
        }
    }

    private static void ValidateLanguageObject(JsonObject obj, string member, string pointer, List<StructuralProblem> problems)
    {
        if (!JsonShape.IsNonBlankString(obj["@value"]))
        {
            problems.Add(new StructuralProblem($"{member}.invalid_language_object", $"{pointer}/@value",
                $"A {member} language value object requires a non-empty string @value."));
        }

        foreach (var property in obj)
        {
            if (property.Key is not ("@value" or "@language" or "@direction"))
            {
                problems.Add(new StructuralProblem($"{member}.invalid_language_object", $"{pointer}/{property.Key}",
                    $"A {member} language value object may only contain @value, @language and @direction."));
            }
        }
    }

    // F8: presentation holder, where present, is a string or an object with an id.
    private static void ValidateHolder(JsonObject root, List<StructuralProblem> problems)
    {
        var holder = root["holder"];
        switch (holder)
        {
            case null:
                break;
            case JsonObject obj when !JsonShape.IsNonBlankString(obj["id"]):
                problems.Add(new StructuralProblem("holder.object_missing_id", "/holder/id",
                    "An object-form holder must have a non-empty string id."));
                break;
            case JsonObject:
                break;
            default:
                if (!JsonShape.IsNonBlankString(holder))
                {
                    problems.Add(new StructuralProblem("holder.invalid_shape", "/holder",
                        "holder must be a non-empty string or an object with an id."));
                }

                break;
        }
    }
}
