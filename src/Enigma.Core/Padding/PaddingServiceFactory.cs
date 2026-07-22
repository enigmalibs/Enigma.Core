namespace Enigma.Core.Padding;

/// <summary>
/// Factory that creates the various padding service implementations used in cryptographic operations:
/// no padding, PKCS#7, ISO/IEC 7816-4, ISO 10126-2, and ANSI X9.23. Each method returns an
/// <see cref="IPaddingService"/> implementing the corresponding standard padding scheme.
/// </summary>
public sealed class PaddingServiceFactory : IPaddingServiceFactory
{
    /// <inheritdoc />
    public IPaddingService CreateNoPaddingService() => new NoPaddingService();

    /// <inheritdoc />
    public IPaddingService CreatePkcs7Service() => new PaddingService(PaddingScheme.Pkcs7);

    /// <inheritdoc />
    public IPaddingService CreateIso7816Service() => new PaddingService(PaddingScheme.Iso7816);

    /// <inheritdoc />
    public IPaddingService CreateIso10126Service() => new PaddingService(PaddingScheme.Iso10126);

    /// <inheritdoc />
    public IPaddingService CreateX923Service() => new PaddingService(PaddingScheme.X923);
}
