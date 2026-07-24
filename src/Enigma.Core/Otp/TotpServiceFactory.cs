using System;

namespace Enigma.Core.Otp;

/// <summary>
/// Default <see cref="ITotpServiceFactory"/> implementation. Builds TOTP services (RFC 6238) over the
/// HOTP services supplied by an <see cref="IHotpServiceFactory"/> injected at construction. The digit
/// count, period and hash algorithm are fixed per created service; the secret and timestamp are supplied
/// per call.
/// </summary>
public sealed class TotpServiceFactory : ITotpServiceFactory
{
    private readonly IHotpServiceFactory _hotpServiceFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="TotpServiceFactory"/> class.
    /// </summary>
    /// <param name="hotpServiceFactory">Factory used to create the HOTP services backing the TOTP generator.</param>
    /// <exception cref="ArgumentNullException"><paramref name="hotpServiceFactory"/> is <see langword="null"/>.</exception>
    public TotpServiceFactory(IHotpServiceFactory hotpServiceFactory)
    {
        _hotpServiceFactory = hotpServiceFactory ?? throw new ArgumentNullException(nameof(hotpServiceFactory));
    }

    /// <inheritdoc />
    public ITotpService CreateTotpService(int digits = 6, int periodSeconds = 30, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1)
        => new TotpService(_hotpServiceFactory, digits, periodSeconds, hashAlgorithm);
}
