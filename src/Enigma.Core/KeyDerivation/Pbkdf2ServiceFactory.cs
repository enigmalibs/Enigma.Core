namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Default <see cref="IPbkdf2ServiceFactory"/> implementation. Hands back a stateless
/// <see cref="Pbkdf2Service"/>; the PRF, iteration count and output length are supplied per call on the
/// returned service.
/// </summary>
public sealed class Pbkdf2ServiceFactory : IPbkdf2ServiceFactory
{
    /// <inheritdoc />
    public IPbkdf2Service CreatePbkdf2Service()
        => new Pbkdf2Service();
}
