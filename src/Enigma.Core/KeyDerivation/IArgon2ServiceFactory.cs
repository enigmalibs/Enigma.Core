namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Factory for creating <see cref="IArgon2Service"/> instances. The variant, version and cost
/// parameters are supplied per call on the returned service.
/// </summary>
public interface IArgon2ServiceFactory
{
    /// <summary>Creates an Argon2 key-derivation service.</summary>
    /// <returns>A configured Argon2 service.</returns>
    IArgon2Service CreateArgon2Service();
}
