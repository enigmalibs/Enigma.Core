using System;
using Enigma.Core.Encoding;

namespace Enigma.Core.Otp;

/// <summary>
/// Default <see cref="IOtpProvisioningServiceFactory"/> implementation. Builds OTP provisioning services
/// over the Base32 encoder supplied by an <see cref="IEncodingServiceFactory"/> injected at construction.
/// </summary>
public sealed class OtpProvisioningServiceFactory : IOtpProvisioningServiceFactory
{
    private readonly IEncodingServiceFactory _encodingServiceFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="OtpProvisioningServiceFactory"/> class.
    /// </summary>
    /// <param name="encodingServiceFactory">Factory used to create the Base32 encoder backing the otpauth secret encoding.</param>
    /// <exception cref="ArgumentNullException"><paramref name="encodingServiceFactory"/> is <see langword="null"/>.</exception>
    public OtpProvisioningServiceFactory(IEncodingServiceFactory encodingServiceFactory)
    {
        _encodingServiceFactory = encodingServiceFactory ?? throw new ArgumentNullException(nameof(encodingServiceFactory));
    }

    /// <inheritdoc />
    public IOtpProvisioningService CreateOtpProvisioningService()
        => new OtpProvisioningService(_encodingServiceFactory);
}
