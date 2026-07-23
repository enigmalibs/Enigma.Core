using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.Hashing.Hmac;

public class HmacSha256Tests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task Compute_KnownVector_MatchesExpected(byte[] key, byte[] data, byte[] expectedHmac)
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();

        // Synchronous path.
        var syncHmac = service.ComputeHmac(data, key);
        Assert.Equal(expectedHmac, syncHmac);

        // Asynchronous streaming path.
        using var input = new MemoryStream(data);
        var asyncHmac = await service.ComputeHmacAsync(input, key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(expectedHmac, asyncHmac);

        // Sync and async paths agree.
        Assert.Equal(syncHmac, asyncHmac);
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("Hashing", "Hmac", "hmac-sha256.csv")
            .Select(v => new object[] { CsvData.Hex(v[0]), CsvData.Hex(v[1]), CsvData.Hex(v[2]) });
}
