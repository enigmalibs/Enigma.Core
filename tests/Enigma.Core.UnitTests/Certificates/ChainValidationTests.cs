using System;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// PKIX chain validation over the PEM contract, with the old single auto-classified trust collection split into
/// explicit <c>trustedRootPems</c> + <c>intermediatePems</c>. Validation checks signatures, the trust anchor, the
/// path and the validity window — but performs <em>no</em> revocation (that is <c>IsRevoked</c>'s job). A chain
/// that fails to build or validate returns <see langword="false"/> rather than throwing.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class ChainValidationTests(CertificateKeyFixture keys)
{
    private static readonly X509CertificateOptions CaOptions = new()
    {
        IsCertificateAuthority = true,
        KeyUsage = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign,
    };

    private static readonly X509CertificateOptions LeafOptions = new()
    {
        IsCertificateAuthority = false,
        KeyUsage = X509KeyUsage.DigitalSignature | X509KeyUsage.KeyEncipherment,
    };

    private static DateTimeOffset Ago(int days) => DateTimeOffset.UtcNow.AddDays(-days);
    private static DateTimeOffset FromNow(int days) => DateTimeOffset.UtcNow.AddDays(days);

    private string RootCa(string dn, string keyPem) =>
        keys.NewService().GenerateSelfSignedCertificate(dn, keyPem, Ago(1), FromNow(3650), options: CaOptions);

    private string Issue(string subjectDn, string subjectKeyPem, string issuerPem, string issuerKeyPem,
        DateTimeOffset notBefore, DateTimeOffset notAfter, X509CertificateOptions options)
    {
        var service = keys.NewService();
        var csr = service.GenerateCertificateSigningRequest(subjectDn, subjectKeyPem);
        return service.IssueCertificate(csr, issuerPem, issuerKeyPem, notBefore, notAfter, options: options);
    }

    [Fact]
    public void ValidateChain_FullChain_Succeeds()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var intermediate = Issue("CN=Intermediate CA", keys.IntermediatePrivateKeyPem, root, keys.RootPrivateKeyPem, Ago(1), FromNow(1825), CaOptions);
        var leaf = Issue("CN=leaf.example.com", keys.LeafPrivateKeyPem, intermediate, keys.IntermediatePrivateKeyPem, Ago(1), FromNow(365), LeafOptions);

        Assert.True(keys.NewService().ValidateChain(leaf, [root], [intermediate]));
    }

    [Fact]
    public void ValidateChain_TwoIntermediates_OrderIndependent_Succeeds()
    {
        // root -> int1 -> int2 -> leaf, built from four independent keys.
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var int1 = Issue("CN=Intermediate 1 CA", keys.IntermediatePrivateKeyPem, root, keys.RootPrivateKeyPem, Ago(1), FromNow(1825), CaOptions);
        var int2 = Issue("CN=Intermediate 2 CA", keys.UnrelatedRootPrivateKeyPem, int1, keys.IntermediatePrivateKeyPem, Ago(1), FromNow(1825), CaOptions);
        var leaf = Issue("CN=leaf.example.com", keys.LeafPrivateKeyPem, int2, keys.UnrelatedRootPrivateKeyPem, Ago(1), FromNow(365), LeafOptions);

        var service = keys.NewService();
        // Both leaf->root order and the common top-down CA-bundle order must validate — the service builds the
        // path, so intermediate ordering is irrelevant.
        Assert.True(service.ValidateChain(leaf, [root], [int2, int1]));
        Assert.True(service.ValidateChain(leaf, [root], [int1, int2]));
    }

    [Fact]
    public void ValidateChain_ImposterRootSameDnDifferentKey_Fails()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var intermediate = Issue("CN=Intermediate CA", keys.IntermediatePrivateKeyPem, root, keys.RootPrivateKeyPem, Ago(1), FromNow(1825), CaOptions);
        var leaf = Issue("CN=leaf.example.com", keys.LeafPrivateKeyPem, intermediate, keys.IntermediatePrivateKeyPem, Ago(1), FromNow(365), LeafOptions);

        // An imposter root that shares the real root's subject DN but uses a DIFFERENT key must NOT be trusted:
        // trust is cryptographic (the anchor must have signed the path), not name-based.
        var imposterRoot = RootCa("CN=Root CA", keys.UnrelatedRootPrivateKeyPem);

        Assert.False(keys.NewService().ValidateChain(leaf, [imposterRoot], [intermediate]));
    }

    [Fact]
    public void ValidateChain_LeafAgainstRootOnly_MissingIntermediate_Fails()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var intermediate = Issue("CN=Intermediate CA", keys.IntermediatePrivateKeyPem, root, keys.RootPrivateKeyPem, Ago(1), FromNow(1825), CaOptions);
        var leaf = Issue("CN=leaf.example.com", keys.LeafPrivateKeyPem, intermediate, keys.IntermediatePrivateKeyPem, Ago(1), FromNow(365), LeafOptions);

        // The intermediate is not supplied, so the path cannot be built.
        Assert.False(keys.NewService().ValidateChain(leaf, [root]));
    }

    [Fact]
    public void ValidateChain_SelfSignedRootAgainstItself_Succeeds()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);

        Assert.True(keys.NewService().ValidateChain(root, [root]));
    }

    [Fact]
    public void ValidateChain_UntrustedRoot_Fails()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var intermediate = Issue("CN=Intermediate CA", keys.IntermediatePrivateKeyPem, root, keys.RootPrivateKeyPem, Ago(1), FromNow(1825), CaOptions);
        var leaf = Issue("CN=leaf.example.com", keys.LeafPrivateKeyPem, intermediate, keys.IntermediatePrivateKeyPem, Ago(1), FromNow(365), LeafOptions);

        var unrelatedRoot = RootCa("CN=Unrelated Root CA", keys.UnrelatedRootPrivateKeyPem);

        Assert.False(keys.NewService().ValidateChain(leaf, [unrelatedRoot], [intermediate]));
    }

    [Fact]
    public void ValidateChain_ExpiredLeaf_Fails()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var expiredLeaf = Issue("CN=Expired Leaf", keys.LeafPrivateKeyPem, root, keys.RootPrivateKeyPem, Ago(1095), Ago(365), LeafOptions);

        Assert.False(keys.NewService().ValidateChain(expiredLeaf, [root]));
    }

    [Fact]
    public void ValidateChain_NotYetValidLeaf_Fails()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);
        var futureLeaf = Issue("CN=Future Leaf", keys.LeafPrivateKeyPem, root, keys.RootPrivateKeyPem, FromNow(365), FromNow(730), LeafOptions);

        Assert.False(keys.NewService().ValidateChain(futureLeaf, [root]));
    }

    [Fact]
    public void ValidateChain_EmptyTrustAnchors_Fails()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);

        Assert.False(keys.NewService().ValidateChain(root, []));
    }

    [Fact]
    public void ValidateChain_NullTrustAnchors_Throws()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);

        Assert.Throws<ArgumentNullException>(() => keys.NewService().ValidateChain(root, null!));
    }

    [Fact]
    public void ValidateChain_MalformedLeafPem_Throws()
    {
        var root = RootCa("CN=Root CA", keys.RootPrivateKeyPem);

        Assert.Throws<ArgumentException>(() => keys.NewService().ValidateChain("not a certificate", [root]));
    }
}
