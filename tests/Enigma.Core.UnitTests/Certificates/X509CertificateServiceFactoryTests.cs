using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>The parameterless X.509 factory creates fresh <see cref="X509CertificateService"/> instances.</summary>
public class X509CertificateServiceFactoryTests
{
    private readonly IX509CertificateServiceFactory _factory = new X509CertificateServiceFactory();

    [Fact]
    public void CreateX509CertificateService_ReturnsX509CertificateService()
        => Assert.IsType<X509CertificateService>(_factory.CreateX509CertificateService());

    [Fact]
    public void CreateX509CertificateService_ReturnsFreshInstancePerCall()
        => Assert.NotSame(_factory.CreateX509CertificateService(), _factory.CreateX509CertificateService());
}
