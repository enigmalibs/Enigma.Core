namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Default <see cref="IPublicKeyServiceFactory"/> implementation. RSA is the only algorithm, so the factory
/// takes no configuration; the padding scheme, OAEP hash and signature algorithm are chosen per call on the
/// returned service.
/// </summary>
public sealed class PublicKeyServiceFactory : IPublicKeyServiceFactory
{
    /// <inheritdoc />
    public IPublicKeyService CreatePublicKeyService() => new PublicKeyService();
}
