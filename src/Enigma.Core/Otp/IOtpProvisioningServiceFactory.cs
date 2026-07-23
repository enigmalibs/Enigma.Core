namespace Enigma.Core.Otp;

/// <summary>
/// Factory for creating <see cref="IOtpProvisioningService"/> instances. The Base32 encoder backing the
/// otpauth secret encoding is wired in at construction; the provisioning service itself is stateless, so
/// created instances are safe to reuse.
/// </summary>
public interface IOtpProvisioningServiceFactory
{
    /// <summary>Creates an OTP provisioning service.</summary>
    /// <returns>A configured provisioning service.</returns>
    IOtpProvisioningService CreateOtpProvisioningService();
}
