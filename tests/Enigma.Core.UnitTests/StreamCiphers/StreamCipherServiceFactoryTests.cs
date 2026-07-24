using System;
using Enigma.Core.Symmetric.StreamCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.StreamCiphers;

public class StreamCipherServiceFactoryTests
{
    private readonly IStreamCipherServiceFactory _factory = new StreamCipherServiceFactory();

    [Fact]
    public void Create_ReturnsStreamCipherService()
    {
        Assert.IsType<StreamCipherService>(_factory.CreateChaCha20Service());
        Assert.IsType<StreamCipherService>(_factory.CreateChaCha7539Service());
        Assert.IsType<StreamCipherService>(_factory.CreateSalsa20Service());
    }

    [Fact]
    public void Create_ReturnsFreshInstancePerCall()
    {
        Assert.NotSame(_factory.CreateChaCha20Service(), _factory.CreateChaCha20Service());
        Assert.NotSame(_factory.CreateChaCha7539Service(), _factory.CreateChaCha7539Service());
        Assert.NotSame(_factory.CreateSalsa20Service(), _factory.CreateSalsa20Service());
    }

    [Fact]
    public void Create_WithNonPositiveBufferSize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _factory.CreateChaCha20Service(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => _factory.CreateSalsa20Service(-1));
    }
}
