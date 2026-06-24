namespace Credentials.TestSupport;

/// <summary>
/// Marks a test method or class as providing coverage for one engineering requirement (an
/// <c>FR-nnn</c> / <c>NFR-nnn</c> id from the PRD §8 coverage table). The
/// <c>FrCoverage_EveryRequirement_HasAtLeastOneTest</c> gate scans the test sources for these tags
/// and fails CI when a defined requirement has no tagged test — so a new FR cannot land untested.
/// </summary>
/// <remarks>
/// This is a plain marker attribute (not an xUnit trait): the gate reads the literal
/// <c>[FrTag("FR-nnn")]</c> tokens from source, which is deterministic and needs no cross-assembly
/// reflection. A single representative test per requirement is enough; tagging every test is not
/// required.
/// </remarks>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
public sealed class FrTagAttribute : Attribute
{
    /// <summary>Creates the tag for the given requirement id (e.g. <c>"FR-011"</c>, <c>"NFR-005"</c>).</summary>
    /// <param name="requirementId">The requirement id this test covers.</param>
    public FrTagAttribute(string requirementId) => RequirementId = requirementId;

    /// <summary>The requirement id this test covers.</summary>
    public string RequirementId { get; }
}
