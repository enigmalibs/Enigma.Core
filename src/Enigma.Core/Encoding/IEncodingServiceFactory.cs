namespace Enigma.Core.Encoding;

/// <summary>
/// Factory for creating <see cref="IEncodingService"/> instances, one per supported textual encoding
/// scheme. The scheme is chosen when the service is created; the data to encode or decode is supplied per
/// call on the returned service.
/// </summary>
public interface IEncodingServiceFactory
{
    /// <summary>Creates an encoding service using Base64 (RFC 4648).</summary>
    /// <returns>A configured Base64 encoding service.</returns>
    IEncodingService CreateBase64Service();

    /// <summary>Creates an encoding service using Base32 (RFC 4648).</summary>
    /// <returns>A configured Base32 encoding service.</returns>
    IEncodingService CreateBase32Service();

    /// <summary>Creates an encoding service using hexadecimal (base-16) text.</summary>
    /// <returns>A configured hexadecimal encoding service.</returns>
    IEncodingService CreateHexService();
}
