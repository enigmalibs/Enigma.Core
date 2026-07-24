namespace Enigma.Core.Certificates;

/// <summary>
/// Default <see cref="IX509CertificateServiceFactory"/> implementation. X.509 is the only certificate format,
/// so the factory takes no configuration; the signature algorithm, validity period, extensions and trust
/// inputs are supplied per call on the returned service.
/// </summary>
public sealed class X509CertificateServiceFactory : IX509CertificateServiceFactory
{
    /// <inheritdoc />
    public IX509CertificateService CreateX509CertificateService() => new X509CertificateService();
}
