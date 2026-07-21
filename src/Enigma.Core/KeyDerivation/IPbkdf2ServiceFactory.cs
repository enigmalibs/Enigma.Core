namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Factory for creating <see cref="IPbkdf2Service"/> instances. The pseudorandom function, iteration
/// count and output length are supplied per call on the returned service.
/// </summary>
public interface IPbkdf2ServiceFactory
{
    /// <summary>Creates a PBKDF2 key-derivation service.</summary>
    /// <returns>A configured PBKDF2 service.</returns>
    IPbkdf2Service CreatePbkdf2Service();
}
