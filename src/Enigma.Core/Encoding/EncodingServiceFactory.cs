using System;

namespace Enigma.Core.Encoding;

/// <summary>
/// A factory for creating encoding services, one per supported textual encoding scheme.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the encoding implementation feature.
/// </remarks>
public sealed class EncodingServiceFactory : IEncodingServiceFactory
{
    /// <inheritdoc />
    public IEncodingService CreateBase64Service() => throw new NotImplementedException();

    /// <inheritdoc />
    public IEncodingService CreateBase32Service() => throw new NotImplementedException();

    /// <inheritdoc />
    public IEncodingService CreateHexService() => throw new NotImplementedException();
}
