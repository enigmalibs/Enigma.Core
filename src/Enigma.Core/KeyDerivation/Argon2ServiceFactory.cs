namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Default <see cref="IArgon2ServiceFactory"/> implementation. Hands back a stateless
/// <see cref="Argon2Service"/>; the variant, version and cost parameters are supplied per call on the
/// returned service.
/// </summary>
public sealed class Argon2ServiceFactory : IArgon2ServiceFactory
{
    /// <inheritdoc />
    public IArgon2Service CreateArgon2Service()
        => new Argon2Service();
}
