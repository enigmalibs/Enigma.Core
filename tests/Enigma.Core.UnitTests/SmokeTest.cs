using Xunit;

namespace Enigma.Core.UnitTests;

/// <summary>
/// Bootstrap smoke test: proves the MTP-native xUnit v3 toolchain builds and runs green.
/// <see cref="Enigma.Core"/> has no public types yet, so a trivial assertion suffices — the
/// <c>ProjectReference</c> already forces the library to compile. Replace/expand once real types exist.
/// </summary>
public sealed class SmokeTest
{
    [Fact]
    public void Toolchain_BuildsAndRuns() => Assert.True(true);
}
