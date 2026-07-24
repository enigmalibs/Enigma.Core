using Enigma.Core.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsBoolTests
{
    [Fact]
    public void WriteThenRead_Bool_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteBool(false);
        output.WriteBool(true);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadBool();
        Assert.False(result);
        result = input.ReadBool();
        Assert.True(result);
    }

    [Fact]
    public async Task WriteThenReadAsync_Bool_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteBoolAsync(false, TestContext.Current.CancellationToken);
        await output.WriteBoolAsync(true, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadBoolAsync(TestContext.Current.CancellationToken);
        Assert.False(result);
        result = await input.ReadBoolAsync(TestContext.Current.CancellationToken);
        Assert.True(result);
    }
}
