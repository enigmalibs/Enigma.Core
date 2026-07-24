namespace Enigma.Core.Encoding;

/// <summary>
/// Default <see cref="IEncodingServiceFactory"/> implementation, creating the built-in Base64,
/// Base32 and hexadecimal encoders. Each call returns a fresh per-scheme service instance.
/// </summary>
public sealed class EncodingServiceFactory : IEncodingServiceFactory
{
    /// <inheritdoc />
    public IEncodingService CreateBase64Service() => new Base64Service();

    /// <inheritdoc />
    public IEncodingService CreateBase32Service() => new Base32Service();

    /// <inheritdoc />
    public IEncodingService CreateHexService() => new HexService();
}
