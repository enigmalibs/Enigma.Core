using System;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Password handling for encrypted private-key PEMs across generation, CSR and issuance. The passphrase is no
/// longer supplied per certificate call: it is consumed once, at <see cref="RsaKey.ImportPrivateKeyPem"/>, and
/// the resulting handle drives the certificate operations. So the correct passphrase unlocks a key that then
/// generates, requests and issues certificates normally, while a wrong or missing passphrase surfaces a
/// <see cref="CryptographicException"/> at the import — before any certificate operation is reached. The
/// unencrypted path (a <see langword="null"/> password) is exercised throughout the other certificate tests.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class EncryptedKeyPemTests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static char[] WrongPassword => "wrong password".ToCharArray();

    private RsaKey EncryptedKey() => RsaKey.ImportPrivateKeyPem(keys.EncryptedPrivateKeyPem, keys.EncryptedKeyPassword);

    [Fact]
    public void GenerateSelfSigned_EncryptedKey_CorrectPassword_Succeeds()
    {
        var pem = keys.NewService().GenerateSelfSignedCertificate(
            "CN=Encrypted", EncryptedKey(), NotBefore, NotAfter);

        Assert.Contains("BEGIN CERTIFICATE", pem);
    }

    [Fact]
    public void ImportEncryptedKey_WrongPassword_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() =>
            RsaKey.ImportPrivateKeyPem(keys.EncryptedPrivateKeyPem, WrongPassword));
    }

    [Fact]
    public void ImportEncryptedKey_NoPassword_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() =>
            RsaKey.ImportPrivateKeyPem(keys.EncryptedPrivateKeyPem, password: null));
    }

    [Fact]
    public void GenerateCsr_EncryptedKey_CorrectPassword_Succeeds()
    {
        var service = keys.NewService();
        var csrPem = service.GenerateCertificateSigningRequest("CN=Encrypted", EncryptedKey());

        Assert.True(service.IsCertificateSigningRequestValid(csrPem));
    }

    [Fact]
    public void IssueCertificate_EncryptedIssuerKey_CorrectPassword_Succeeds()
    {
        var service = keys.NewService();
        var issuerKey = EncryptedKey();
        var caPem = service.GenerateSelfSignedCertificate(
            "CN=Encrypted CA", issuerKey, NotBefore, NotAfter,
            options: new X509CertificateOptions { IsCertificateAuthority = true, KeyUsage = X509KeyUsage.KeyCertSign });
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);

        var leafPem = service.IssueCertificate(csrPem, caPem, issuerKey, NotBefore, NotAfter);

        Assert.Equal(service.GetCertificateInfo(caPem).Subject, service.GetCertificateInfo(leafPem).Issuer);
    }

    [Fact]
    public void EncryptedKey_ImportedOnce_ServesEveryCertificateOperation()
    {
        // The point of the migration: one import, then generation, CSR and issuance all run off the same handle
        // with no passphrase in sight. (Replaces the second wrong-password test, which asserted a wrong passphrase
        // at an issuance call site that no longer takes one — it had collapsed onto the import assertion above.)
        var service = keys.NewService();
        var issuerKey = EncryptedKey();

        var caPem = service.GenerateSelfSignedCertificate(
            "CN=Encrypted CA", issuerKey, NotBefore, NotAfter,
            options: new X509CertificateOptions { IsCertificateAuthority = true, KeyUsage = X509KeyUsage.KeyCertSign });
        var csrPem = service.GenerateCertificateSigningRequest("CN=Encrypted Requester", issuerKey);
        var leafPem = service.IssueCertificate(csrPem, caPem, issuerKey, NotBefore, NotAfter);

        Assert.True(service.IsCertificateSigningRequestValid(csrPem));
        Assert.Contains("CN=Encrypted Requester", service.GetCertificateInfo(leafPem).Subject);
        Assert.Equal(service.GetCertificateInfo(caPem).Subject, service.GetCertificateInfo(leafPem).Issuer);
    }
}
