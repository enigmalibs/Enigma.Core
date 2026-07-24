using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.Hashing.Hash;

public class Sha3Tests
{
    // Regenerated NIST FIPS 202 short-message KATs for all four output sizes (bitLength,data,hash).
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task ComputeHash_KnownVector_MatchesExpectedAndHasCorrectLength(
        int bitLength, byte[] data, byte[] expectedHash)
    {
        var service = new HashServiceFactory().CreateSha3Service(bitLength);

        using var input = new MemoryStream(data);
        var hash = await service.ComputeHashAsync(input, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(bitLength / 8, hash.Length);
        Assert.Equal(expectedHash, hash);
    }

    [Fact]
    public async Task CreateSha3Service_DefaultsToSha3_256()
    {
        var service = new HashServiceFactory().CreateSha3Service();

        using var input = new MemoryStream([]);
        var hash = await service.ComputeHashAsync(input, cancellationToken: TestContext.Current.CancellationToken);

        // Default output size is 256 bits (32 bytes); empty-message SHA3-256 KAT.
        Assert.Equal(32, hash.Length);
        Assert.Equal(
            CsvData.Hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            hash);
    }

    [Theory]
    [InlineData(224)]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(512)]
    public async Task CreateSha3Service_SupportedSizes_ProduceCorrectDigestLength(int bitLength)
    {
        var service = new HashServiceFactory().CreateSha3Service(bitLength);

        using var input = new MemoryStream("data"u8.ToArray());
        var hash = await service.ComputeHashAsync(input, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(bitLength / 8, hash.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(255)]
    [InlineData(1024)]
    public void CreateSha3Service_UnsupportedBitLength_Throws(int bitLength)
    {
        var factory = new HashServiceFactory();
        var ex = Assert.Throws<ArgumentException>(() => factory.CreateSha3Service(bitLength));
        Assert.Equal("bitLength", ex.ParamName);
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("Hashing", "Hash", "sha3.csv")
            .Select(v => new object[] { int.Parse(v[0]), CsvData.Hex(v[1]), CsvData.Hex(v[2]) });
}
