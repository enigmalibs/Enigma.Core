namespace Enigma.Core.Certificates;

/// <summary>
/// Factory for creating <see cref="IX509CertificateService"/> instances. X.509 is the only certificate
/// format, so the factory takes no configuration; the signature algorithm, validity period and trust
/// inputs are supplied per call on the returned service.
/// </summary>
public interface IX509CertificateServiceFactory
{
    /// <summary>Creates an X.509 certificate service.</summary>
    /// <returns>An X.509 certificate service.</returns>
    IX509CertificateService CreateX509CertificateService();
}
