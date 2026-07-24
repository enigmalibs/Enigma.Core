using System;
using Enigma.Core.Hashing.Hmac;

namespace Enigma.Core.Otp;

/// <summary>
/// Default <see cref="IHotpServiceFactory"/> implementation. Builds HOTP services (RFC 4226) over the
/// HMAC services supplied by an <see cref="IHmacServiceFactory"/> injected at construction. The digit
/// count and hash algorithm are fixed per created service; the secret and counter are supplied per call.
/// </summary>
public sealed class HotpServiceFactory : IHotpServiceFactory
{
    private readonly IHmacServiceFactory _hmacServiceFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="HotpServiceFactory"/> class.
    /// </summary>
    /// <param name="hmacServiceFactory">Factory used to create the HMAC services backing the HOTP generator.</param>
    /// <exception cref="ArgumentNullException"><paramref name="hmacServiceFactory"/> is <see langword="null"/>.</exception>
    public HotpServiceFactory(IHmacServiceFactory hmacServiceFactory)
    {
        _hmacServiceFactory = hmacServiceFactory ?? throw new ArgumentNullException(nameof(hmacServiceFactory));
    }

    /// <inheritdoc />
    public IHotpService CreateHotpService(int digits = 6, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1)
        => new HotpService(_hmacServiceFactory, digits, hashAlgorithm);
}
