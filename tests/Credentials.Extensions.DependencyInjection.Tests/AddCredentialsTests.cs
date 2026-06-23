using Credentials.Cryptography;
using Credentials.TestSupport;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Credentials.Extensions.DependencyInjection.Tests;

/// <summary>DI surface: <c>AddCredentials</c> wires the engine seams with defaults and binds options.</summary>
public sealed class AddCredentialsTests
{
    [Fact]
    [FrTag("FR-052")]
    public void Registers_default_crypto_seams()
    {
        using var provider = new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

        provider.GetRequiredService<IRandomSource>().Should().BeOfType<BclRandomSource>();
        provider.GetRequiredService<IDigestService>().Should().BeOfType<NetCryptoDigestService>();
    }

    [Fact]
    public void Builder_override_wins_over_the_default_seam()
    {
        var custom = new FakeRandomSource();

        using var provider = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().UseRandomSource(custom))
            .BuildServiceProvider();

        provider.GetRequiredService<IRandomSource>().Should().BeSameAs(custom);
    }

    [Fact]
    public void Configure_binds_options()
    {
        using var provider = new ServiceCollection()
            .AddCredentials(b => b.UseNetDid().Configure(o =>
            {
                o.ClockSkew = TimeSpan.FromSeconds(30);
                o.AcceptVcdm11 = false;
            }))
            .BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<CredentialsOptions>>().Value;
        options.ClockSkew.Should().Be(TimeSpan.FromSeconds(30));
        options.AcceptVcdm11.Should().BeFalse();
    }

    [Fact]
    public void Default_options_have_expected_defaults()
    {
        using var provider = new ServiceCollection().AddCredentials(b => b.UseNetDid()).BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<CredentialsOptions>>().Value;
        options.ClockSkew.Should().Be(TimeSpan.FromMinutes(2));
        options.AcceptVcdm11.Should().BeTrue();
    }

    [Fact]
    public void AddCredentials_validates_its_arguments()
    {
        var services = new ServiceCollection();
        ((Action)(() => services.AddCredentials(null!))).Should().Throw<ArgumentNullException>();
        ((Action)(() => ServiceCollectionExtensionsNull())).Should().Throw<ArgumentNullException>();
        return;

        static void ServiceCollectionExtensionsNull() =>
            CredentialsServiceCollectionExtensions.AddCredentials(null!, _ => { });
    }

    private sealed class FakeRandomSource : IRandomSource
    {
        public void Fill(Span<byte> destination) => destination.Clear();

        public byte[] GetBytes(int count) => new byte[count];
    }
}
