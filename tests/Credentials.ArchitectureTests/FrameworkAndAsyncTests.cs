using System.Reflection;
using System.Runtime.Versioning;
using Credentials;
using Credentials.Roles;
using Credentials.TestSupport;
using FluentAssertions;
using Xunit;

namespace Credentials.ArchitectureTests;

/// <summary>
/// NFR-001 (the library targets net10.0) and NFR-004 (the role I/O methods are honestly async — they
/// return <see cref="System.Threading.Tasks.Task"/>/<see cref="System.Threading.Tasks.ValueTask"/>,
/// never a blocking signature dressed up after the fact).
/// </summary>
public sealed class FrameworkAndAsyncTests
{
    [Fact]
    [FrTag("NFR-001")]
    public void Library_TargetsNet10()
    {
        var framework = typeof(Credential).Assembly.GetCustomAttribute<TargetFrameworkAttribute>();
        framework.Should().NotBeNull();
        framework!.FrameworkName.Should().Contain("v10.0",
            "Credentials.Core must target net10.0 (NFR-001)");
    }

    [Theory]
    [FrTag("NFR-004")]
    [InlineData(typeof(IIssuer))]
    [InlineData(typeof(IHolder))]
    [InlineData(typeof(IVerifier))]
    public void RoleMethods_NamedAsync_ReturnTaskOrValueTask(Type roleInterface)
    {
        var offenders = new List<string>();

        foreach (var method in roleInterface.GetMethods())
        {
            if (!method.Name.EndsWith("Async", StringComparison.Ordinal)) continue;
            if (!IsAwaitableReturn(method.ReturnType))
                offenders.Add($"{roleInterface.Name}.{method.Name} -> {method.ReturnType.Name}");
        }

        offenders.Should().BeEmpty(
            "every *Async role method must return Task/ValueTask (NFR-004). Offenders:\n" + string.Join("\n", offenders));
    }

    private static bool IsAwaitableReturn(Type returnType)
    {
        var t = returnType.IsGenericType ? returnType.GetGenericTypeDefinition() : returnType;
        return t == typeof(Task)
            || t == typeof(ValueTask)
            || t == typeof(Task<>)
            || t == typeof(ValueTask<>);
    }
}
