using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.Hashing.Hmac;
using Xunit;

namespace Enigma.Core.UnitTests.Hashing;

/// <summary>
/// Null-argument guards for the hashing and HMAC services.
/// </summary>
public class HashingArgumentTests
{
    [Fact]
    public async Task ComputeHashAsync_NullInput_Throws()
    {
        var service = new HashServiceFactory().CreateSha256Service();
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.ComputeHashAsync(null!, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("input", ex.ParamName);
    }

    [Fact]
    public void ComputeHmac_NullData_Throws()
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();
        var ex = Assert.Throws<ArgumentNullException>(() => service.ComputeHmac(null!, new byte[16]));
        Assert.Equal("data", ex.ParamName);
    }

    [Fact]
    public void ComputeHmac_NullKey_Throws()
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();
        var ex = Assert.Throws<ArgumentNullException>(() => service.ComputeHmac(new byte[16], null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public async Task ComputeHmacAsync_NullInput_Throws()
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.ComputeHmacAsync(null!, new byte[16], cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("input", ex.ParamName);
    }

    [Fact]
    public async Task ComputeHmacAsync_NullKey_Throws()
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();
        using var input = new MemoryStream(new byte[] { 1, 2, 3 });
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.ComputeHmacAsync(input, null!, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("key", ex.ParamName);
    }

    // A non-positive buffer size must fail loudly at creation. Otherwise the streaming read loop
    // terminates before consuming the stream and the service silently returns the empty-message
    // digest / an HMAC tag over zero bytes (a wrong, and for HMAC insecure, result with no exception).
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void CreateHashService_NonPositiveBufferSize_Throws(int bufferSize)
    {
        var factory = new HashServiceFactory();
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateSha256Service(bufferSize));
        Assert.Equal("bufferSize", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void CreateHmacService_NonPositiveBufferSize_Throws(int bufferSize)
    {
        var factory = new HmacServiceFactory();
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateHmacSha256Service(bufferSize));
        Assert.Equal("bufferSize", ex.ParamName);
    }
}
