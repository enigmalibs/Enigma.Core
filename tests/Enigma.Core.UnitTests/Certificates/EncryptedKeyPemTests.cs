using System;
using System.Security.Cryptography;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Password handling for encrypted private-key PEMs across generation, CSR and issuance: the correct passphrase
/// unlocks the key, a wrong or missing passphrase surfaces a <see cref="CryptographicException"/>, and the
/// unencrypted path (a <see langword="null"/> password) is exercised throughout the other certificate tests.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class EncryptedKeyPemTests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static char[] WrongPassword => "wrong password".ToCharArray();

    [Fact]
    public void GenerateSelfSigned_EncryptedKey_CorrectPassword_Succeeds()
    {
        var pem = keys.NewService().GenerateSelfSignedCertificate(
            "CN=Encrypted", keys.EncryptedPrivateKeyPem, NotBefore, NotAfter, password: keys.EncryptedKeyPassword);

        Assert.Contains("BEGIN CERTIFICATE", pem);
    }

    [Fact]
    public void GenerateSelfSigned_EncryptedKey_WrongPassword_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() => keys.NewService().GenerateSelfSignedCertificate(
            "CN=Encrypted", keys.EncryptedPrivateKeyPem, NotBefore, NotAfter, password: WrongPassword));
    }

    [Fact]
    public void GenerateSelfSigned_EncryptedKey_NoPassword_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() => keys.NewService().GenerateSelfSignedCertificate(
            "CN=Encrypted", keys.EncryptedPrivateKeyPem, NotBefore, NotAfter, password: null));
    }

    [Fact]
    public void GenerateCsr_EncryptedKey_CorrectPassword_Succeeds()
    {
        var service = keys.NewService();
        var csrPem = service.GenerateCertificateSigningRequest(
            "CN=Encrypted", keys.EncryptedPrivateKeyPem, password: keys.EncryptedKeyPassword);

        Assert.True(service.IsCertificateSigningRequestValid(csrPem));
    }

    [Fact]
    public void IssueCertificate_EncryptedIssuerKey_CorrectPassword_Succeeds()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate(
            "CN=Encrypted CA", keys.EncryptedPrivateKeyPem, NotBefore, NotAfter,
            password: keys.EncryptedKeyPassword,
            options: new X509CertificateOptions { IsCertificateAuthority = true, KeyUsage = X509KeyUsage.KeyCertSign });
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKeyPem);

        var leafPem = service.IssueCertificate(
            csrPem, caPem, keys.EncryptedPrivateKeyPem, NotBefore, NotAfter, password: keys.EncryptedKeyPassword);

        Assert.Equal(service.GetCertificateInfo(caPem).Subject, service.GetCertificateInfo(leafPem).Issuer);
    }

    [Fact]
    public void IssueCertificate_EncryptedIssuerKey_WrongPassword_ThrowsCryptographicException()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate(
            "CN=Encrypted CA", keys.EncryptedPrivateKeyPem, NotBefore, NotAfter,
            password: keys.EncryptedKeyPassword,
            options: new X509CertificateOptions { IsCertificateAuthority = true });
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKeyPem);

        Assert.Throws<CryptographicException>(() => service.IssueCertificate(
            csrPem, caPem, keys.EncryptedPrivateKeyPem, NotBefore, NotAfter, password: WrongPassword));
    }
}
