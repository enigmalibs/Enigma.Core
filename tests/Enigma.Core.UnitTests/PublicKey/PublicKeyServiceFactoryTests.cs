using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>The parameterless public-key factory creates fresh <see cref="PublicKeyService"/> instances.</summary>
public class PublicKeyServiceFactoryTests
{
    private readonly IPublicKeyServiceFactory _factory = new PublicKeyServiceFactory();

    [Fact]
    public void CreatePublicKeyService_ReturnsPublicKeyService()
        => Assert.IsType<PublicKeyService>(_factory.CreatePublicKeyService());

    [Fact]
    public void CreatePublicKeyService_ReturnsFreshInstancePerCall()
        => Assert.NotSame(_factory.CreatePublicKeyService(), _factory.CreatePublicKeyService());
}
