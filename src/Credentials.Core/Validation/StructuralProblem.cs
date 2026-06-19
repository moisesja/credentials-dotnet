namespace Credentials.Validation;

/// <summary>
/// One structural-conformance problem found by <see cref="StructuralValidator"/>: a stable
/// machine-readable <see cref="Code"/>, the <see cref="JsonPointer"/> (RFC 6901) locating the
/// offending member, and a human-readable <see cref="Message"/>. Messages are secret-free —
/// they describe shape, never claim values.
/// </summary>
/// <param name="Code">A stable, machine-readable problem code (e.g. <c>context.index0_mismatch</c>).</param>
/// <param name="JsonPointer">An RFC 6901 JSON Pointer to the offending member (e.g. <c>/@context/0</c>).</param>
/// <param name="Message">A short, secret-free, human-readable description.</param>
public sealed record StructuralProblem(string Code, string JsonPointer, string Message);
