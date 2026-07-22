using System;
using System.Security.Cryptography;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// CRL-based revocation over the PEM contract: <c>IsRevoked</c> parses the CRL, verifies it was signed by the
/// named issuer, and reports whether the certificate's serial is listed. Revocation is a distinct check —
/// <c>ValidateChain</c> deliberately performs none — and the signed CRL fixtures come from the test-side
/// <see cref="TestCrlBuilder"/> (CRL generation has no product API by design).
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class RevocationTests(CertificateKeyFixture keys)
{
    private static readonly X509CertificateOptions CaOptions = new()
    {
        IsCertificateAuthority = true,
        KeyUsage = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign,
    };

    private static DateTimeOffset Ago(int days) => DateTimeOffset.UtcNow.AddDays(-days);
    private static DateTimeOffset FromNow(int days) => DateTimeOffset.UtcNow.AddDays(days);

    // Root CA + a leaf issued directly by it, so a single root-signed CRL covers the whole (two-level) path.
    private (string rootPem, string leafPem) RootAndLeaf()
    {
        var service = keys.NewService();
        var rootPem = service.GenerateSelfSignedCertificate("CN=Root CA", keys.RootPrivateKeyPem, Ago(1), FromNow(3650), options: CaOptions);
        var csr = service.GenerateCertificateSigningRequest("CN=revocable.example.com", keys.LeafPrivateKeyPem);
        var leafPem = service.IssueCertificate(csr, rootPem, keys.RootPrivateKeyPem, Ago(1), FromNow(365));
        return (rootPem, leafPem);
    }

    [Fact]
    public void IsRevoked_RevokedLeaf_ReturnsTrue()
    {
        var (rootPem, leafPem) = RootAndLeaf();
        var crlPem = TestCrlBuilder.CreateCrl(rootPem, keys.RootPrivateKeyPem, leafPem);

        Assert.True(keys.NewService().IsRevoked(leafPem, crlPem, rootPem));
    }

    [Fact]
    public void IsRevoked_UnrevokedLeaf_AgainstEmptyCrl_ReturnsFalse()
    {
        var (rootPem, leafPem) = RootAndLeaf();
        var emptyCrlPem = TestCrlBuilder.CreateCrl(rootPem, keys.RootPrivateKeyPem);

        Assert.False(keys.NewService().IsRevoked(leafPem, emptyCrlPem, rootPem));
    }

    [Fact]
    public void IsRevoked_UnrevokedLeaf_AgainstCrlRevokingOthers_ReturnsFalse()
    {
        var (rootPem, leafPem) = RootAndLeaf();
        // A CRL that revokes a *different* certificate (the root itself) must not mark the leaf revoked.
        var crlPem = TestCrlBuilder.CreateCrl(rootPem, keys.RootPrivateKeyPem, rootPem);

        Assert.False(keys.NewService().IsRevoked(leafPem, crlPem, rootPem));
    }

    [Fact]
    public void IsRevoked_CrlSignedByWrongIssuer_ThrowsCryptographicException()
    {
        var (rootPem, leafPem) = RootAndLeaf();
        // A self-consistent CRL from an unrelated CA — its signature will not verify against the real root's key.
        var unrelatedRootPem = keys.NewService().GenerateSelfSignedCertificate(
            "CN=Unrelated Root CA", keys.UnrelatedRootPrivateKeyPem, Ago(1), FromNow(3650), options: CaOptions);
        var foreignCrlPem = TestCrlBuilder.CreateCrl(unrelatedRootPem, keys.UnrelatedRootPrivateKeyPem, leafPem);

        Assert.Throws<CryptographicException>(() => keys.NewService().IsRevoked(leafPem, foreignCrlPem, rootPem));
    }

    [Fact]
    public void IsRevoked_CrlSignedWithMismatchedKeyType_ThrowsCryptographicException()
    {
        var (rootPem, leafPem) = RootAndLeaf();
        // An Ed25519-signed CRL verified against the RSA issuer: the key-type mismatch must surface as a
        // CryptographicException, never a raw BouncyCastle/cast exception.
        var ed25519CrlPem = TestCrlBuilder.CreateEd25519SignedCrl(rootPem, leafPem);

        Assert.Throws<CryptographicException>(() => keys.NewService().IsRevoked(leafPem, ed25519CrlPem, rootPem));
    }

    [Fact]
    public void IsRevoked_MalformedCrlPem_Throws()
    {
        var (rootPem, leafPem) = RootAndLeaf();

        Assert.Throws<ArgumentException>(() => keys.NewService().IsRevoked(leafPem, "not a crl", rootPem));
    }

    [Fact]
    public void ValidateChain_PerformsNoRevocationCheck()
    {
        var (rootPem, leafPem) = RootAndLeaf();
        var crlPem = TestCrlBuilder.CreateCrl(rootPem, keys.RootPrivateKeyPem, leafPem);
        var service = keys.NewService();

        // The leaf is genuinely revoked by the CRL...
        Assert.True(service.IsRevoked(leafPem, crlPem, rootPem));
        // ...yet ValidateChain, which does no revocation checking, still reports the otherwise-valid chain as valid.
        Assert.True(service.ValidateChain(leafPem, [rootPem]));
    }
}
