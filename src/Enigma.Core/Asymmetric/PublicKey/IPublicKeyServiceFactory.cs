namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Factory for creating <see cref="IPublicKeyService"/> instances. RSA is the only algorithm, so the
/// factory takes no configuration; the padding scheme, OAEP hash and signature algorithm are supplied per
/// call on the returned service.
/// </summary>
public interface IPublicKeyServiceFactory
{
    /// <summary>Creates an RSA public-key service.</summary>
    /// <returns>A public-key service.</returns>
    IPublicKeyService CreatePublicKeyService();
}
