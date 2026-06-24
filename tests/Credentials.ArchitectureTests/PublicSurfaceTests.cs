using System.Reflection;
using System.Xml.Linq;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// Gates over the shippable libraries' public surface, inspected by metadata only
/// (<see cref="System.Reflection.MetadataLoadContext"/>) so the opt-in Credentials.Rdfc is examined
/// without loading its transitive Newtonsoft into this host.
/// </summary>
public sealed class PublicSurfaceTests
{
    private const BindingFlags MemberFlags =
        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    /// <summary>
    /// FR-051 / NFR-005 (F3): no DataProofsDotnet substrate type — draft or otherwise — may appear in
    /// any public/protected signature of the three libraries. The securing mechanisms confine every
    /// DataProofs type (DisclosureFrame, Jwk, Bbs2023Cryptosuite, ITypeMetadataResolver,
    /// DataProofsBuilder, JwsSigner, CoseAlgorithm, …) behind the neutral role API.
    /// </summary>
    [Fact]
    [FrTag("FR-051")]
    [FrTag("NFR-005")]
    public void PublicSurface_ExposesNoDataProofsType()
    {
        using var mlc = LibrarySurface.CreateLoadContext();
        var leaks = new List<string>();

        foreach (var dll in LibrarySurface.LibraryDllPaths)
        {
            var asm = mlc.LoadFromAssemblyPath(dll);
            foreach (var type in asm.GetExportedTypes())
            {
                foreach (var (referenced, memberLabel) in SignatureTypes(type))
                {
                    var ns = SafeNamespace(referenced);
                    if (ns is not null && ns.StartsWith("DataProofsDotnet", StringComparison.Ordinal))
                        leaks.Add($"{asm.GetName().Name}: {type.FullName}.{memberLabel} -> {referenced.FullName}");
                }
            }
        }

        leaks.Should().BeEmpty(
            "no DataProofsDotnet substrate type may leak onto the public surface (NFR-005/F3). Leaks:\n" + string.Join("\n", leaks));
    }

    /// <summary>
    /// NFR-009: complements CS1591-as-error (which catches <em>missing</em> docs at build time) by
    /// catching <em>empty</em> ones — every documented public member must have a non-whitespace
    /// <c>&lt;summary&gt;</c>. Also asserts each library actually emitted a non-trivial doc file.
    /// </summary>
    [Fact]
    [FrTag("NFR-009")]
    public void PublicSurface_EveryDocumentedMember_HasNonEmptySummary()
    {
        var publicTypeNames = PublicTypeDocNames();
        var empties = new List<string>();

        foreach (var xmlPath in LibrarySurface.LibraryXmlDocPaths)
        {
            File.Exists(xmlPath).Should().BeTrue($"the XML doc file '{xmlPath}' must be generated (GenerateDocumentationFile=true)");
            var doc = XDocument.Load(xmlPath);
            var members = doc.Root?.Element("members")?.Elements("member").ToList() ?? [];
            members.Should().NotBeEmpty($"'{Path.GetFileName(xmlPath)}' must document members");

            foreach (var member in members)
            {
                var name = member.Attribute("name")?.Value;
                if (name is null || name.Length < 2) continue;

                // Scope to the *public* surface: skip members whose declaring type is not exported
                // (e.g. the internal Rfc3339 regex helper, source-generator output under
                // System.Text.RegularExpressions.Generated). NFR-009 governs the public API.
                if (!publicTypeNames.Contains(DeclaringTypeDocName(name))) continue;

                // An <inheritdoc/> member legitimately carries no <summary> of its own.
                if (member.Element("inheritdoc") is not null) continue;

                var summary = member.Element("summary");
                if (summary is null || string.IsNullOrWhiteSpace(summary.Value))
                    empties.Add($"{Path.GetFileName(xmlPath)}: {name}");
            }
        }

        empties.Should().BeEmpty(
            "every documented public-surface member must have a non-empty <summary> (NFR-009). Empty/missing:\n" + string.Join("\n", empties));
    }

    /// <summary>The doc-comment type names (e.g. <c>Credentials.Status.StatusListManager</c>) of every exported type.</summary>
    private static HashSet<string> PublicTypeDocNames()
    {
        using var mlc = LibrarySurface.CreateLoadContext();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var dll in LibrarySurface.LibraryDllPaths)
            foreach (var type in mlc.LoadFromAssemblyPath(dll).GetExportedTypes())
                if (type.FullName is not null)
                    names.Add(type.FullName.Replace('+', '.'));
        return names;
    }

    /// <summary>
    /// Extracts the declaring-type doc name from a member doc-comment id. For <c>T:</c> the id body is
    /// itself the type; for <c>M:/P:/F:/E:</c> it is the body with any parameter list stripped, up to
    /// the last <c>.</c> (e.g. <c>M:N.Type.Method(System.String)</c> → <c>N.Type</c>).
    /// </summary>
    private static string DeclaringTypeDocName(string docId)
    {
        var kind = docId[0];
        var body = docId[2..];
        if (kind == 'T') return body;

        var paren = body.IndexOf('(');
        if (paren >= 0) body = body[..paren];
        var lastDot = body.LastIndexOf('.');
        return lastDot >= 0 ? body[..lastDot] : body;
    }

    private static IEnumerable<(Type Referenced, string MemberLabel)> SignatureTypes(Type type)
    {
        foreach (var t in LibrarySurface.Flatten(type.BaseType)) yield return (t, "<base>");
        foreach (var iface in type.GetInterfaces())
            foreach (var t in LibrarySurface.Flatten(iface)) yield return (t, "<interface>");

        foreach (var member in type.GetMembers(MemberFlags))
        {
            switch (member)
            {
                case FieldInfo f when IsVisible(f.IsPublic, f.IsFamily, f.IsFamilyOrAssembly):
                    foreach (var t in LibrarySurface.Flatten(f.FieldType)) yield return (t, f.Name);
                    break;
                case PropertyInfo p:
                    var pAccessor = p.GetMethod ?? p.SetMethod;
                    if (pAccessor is not null && IsVisible(pAccessor.IsPublic, pAccessor.IsFamily, pAccessor.IsFamilyOrAssembly))
                    {
                        foreach (var t in LibrarySurface.Flatten(p.PropertyType)) yield return (t, p.Name);
                        foreach (var ip in p.GetIndexParameters())
                            foreach (var t in LibrarySurface.Flatten(ip.ParameterType)) yield return (t, p.Name);
                    }
                    break;
                case MethodBase mb when IsVisible(mb.IsPublic, mb.IsFamily, mb.IsFamilyOrAssembly):
                    if (mb is MethodInfo mi)
                        foreach (var t in LibrarySurface.Flatten(mi.ReturnType)) yield return (t, mb.Name);
                    foreach (var prm in mb.GetParameters())
                        foreach (var t in LibrarySurface.Flatten(prm.ParameterType)) yield return (t, mb.Name);
                    break;
                case EventInfo e:
                    var eAccessor = e.AddMethod ?? e.RemoveMethod;
                    if (eAccessor is not null && IsVisible(eAccessor.IsPublic, eAccessor.IsFamily, eAccessor.IsFamilyOrAssembly))
                        foreach (var t in LibrarySurface.Flatten(e.EventHandlerType)) yield return (t, e.Name);
                    break;
            }
        }
    }

    private static bool IsVisible(bool isPublic, bool isFamily, bool isFamilyOrAssembly) => isPublic || isFamily || isFamilyOrAssembly;

    private static string? SafeNamespace(Type type)
    {
        try { return type.Namespace; }
        catch { return null; }
    }
}
