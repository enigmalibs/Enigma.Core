using System;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.Utils;

public class RandomUtilsTests
{
    [Fact]
    public void GenerateRandomBytes_Zero_Throws()
        => Assert.Throws<ArgumentException>(() => RandomUtils.GenerateRandomBytes(0));

    [Fact]
    public void GenerateRandomBytes_Negative_Throws()
        => Assert.Throws<ArgumentException>(() => RandomUtils.GenerateRandomBytes(-1));

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(1024)]
    public void GenerateRandomBytes_PositiveSize_ReturnsExactLength(int size)
        => Assert.Equal(size, RandomUtils.GenerateRandomBytes(size).Length);
}
