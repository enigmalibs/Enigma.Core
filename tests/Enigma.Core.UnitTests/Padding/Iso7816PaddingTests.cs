using System.Collections.Generic;
using System.Linq;
using Enigma.Core.Padding;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.Padding;

public class Iso7816PaddingTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void Pad_KnownVector_MatchesExpected(byte[] data, byte[] paddedData)
    {
        var service = new PaddingServiceFactory().CreateIso7816Service();

        var padded = service.Pad(data, 16);

        Assert.Equal(paddedData, padded);
    }

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void Unpad_KnownVector_MatchesExpected(byte[] data, byte[] paddedData)
    {
        var service = new PaddingServiceFactory().CreateIso7816Service();

        var unpaddedData = service.Unpad(paddedData, 16);

        Assert.Equal(data, unpaddedData);
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("Padding", "iso7816.csv")
            .Select(v => new object[]
            {
                CsvData.Hex(v[0]), // data
                CsvData.Hex(v[1]), // padded
            });
}
