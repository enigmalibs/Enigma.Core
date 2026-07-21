using Enigma.Core.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsFloatTests
{
    [Fact]
    public void WriteThenRead_Float_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteFloat(float.MaxValue);
        output.WriteFloat(float.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadFloat();
        Assert.Equal(float.MaxValue, result);
        result = input.ReadFloat();
        Assert.Equal(float.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_Float_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteFloatAsync(float.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteFloatAsync(float.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadFloatAsync(TestContext.Current.CancellationToken);
        Assert.Equal(float.MaxValue, result);
        result = await input.ReadFloatAsync(TestContext.Current.CancellationToken);
        Assert.Equal(float.MinValue, result);
    }
}
