using System;

namespace Enigma.Core.Padding;

/// <summary>
/// Factory that creates the various padding service implementations used in cryptographic operations:
/// no padding, PKCS#7, ISO/IEC 7816-4, ISO 10126-2, and ANSI X9.23. Each method returns an
/// <see cref="IPaddingService"/> implementing the corresponding standard padding scheme.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class PaddingServiceFactory : IPaddingServiceFactory
{
    /// <inheritdoc />
    public IPaddingService CreateNoPaddingService() => throw new NotImplementedException();

    /// <inheritdoc />
    public IPaddingService CreatePkcs7Service() => throw new NotImplementedException();

    /// <inheritdoc />
    public IPaddingService CreateIso7816Service() => throw new NotImplementedException();

    /// <inheritdoc />
    public IPaddingService CreateIso10126Service() => throw new NotImplementedException();

    /// <inheritdoc />
    public IPaddingService CreateX923Service() => throw new NotImplementedException();
}
