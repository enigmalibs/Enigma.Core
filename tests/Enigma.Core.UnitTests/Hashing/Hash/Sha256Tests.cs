using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.Hashing.Hash;

public class Sha256Tests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task ComputeHash_KnownVector_MatchesExpected(byte[] data, byte[] expectedHash)
    {
        var service = new HashServiceFactory().CreateSha256Service();

        using var input = new MemoryStream(data);
        var hash = await service.ComputeHashAsync(input, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(expectedHash, hash);
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("Hashing", "Hash", "sha256.csv")
            .Select(v => new object[] { CsvData.Hex(v[0]), CsvData.Hex(v[1]) });
}
