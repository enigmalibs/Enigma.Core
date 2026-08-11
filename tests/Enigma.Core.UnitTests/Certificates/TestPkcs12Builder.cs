using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Test-only PKCS#12 helpers built with BouncyCastle directly, for fixtures the product API cannot produce
/// (a certificate-only archive with no key entry) and for cracking an exported archive open to observe the
/// chain (which <c>ImportPkcs12</c> does not surface). Confined to the test project; never touches the product surface.
/// </summary>
internal static class TestPkcs12Builder
{
    /// <summary>Builds a valid, MAC'd PKCS#12 archive containing only a certificate entry (no key entry).</summary>
    internal static byte[] CreateCertificateOnlyArchive(string certificatePem, char[] password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        store.SetCertificateEntry("cert-only", new X509CertificateEntry(ReadCertificate(certificatePem)));

        using var stream = new MemoryStream();
        store.Save(stream, password, new SecureRandom());
        return stream.ToArray();
    }

    /// <summary>
    /// Builds a valid, MAC'd PKCS#12 archive whose key entry holds an <b>Ed25519</b> private key rather than an RSA
    /// one, paired with an (unrelated) RSA certificate. <c>ImportPkcs12</c> returns an <c>RsaKey</c>, so such an
    /// archive has no representable key and must be rejected rather than mis-typed.
    /// </summary>
    internal static byte[] CreateNonRsaKeyArchive(string certificatePem, char[] password)
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();

        var store = new Pkcs12StoreBuilder().Build();
        store.SetKeyEntry("ed25519", new AsymmetricKeyEntry(keyPair.Private),
            [new X509CertificateEntry(ReadCertificate(certificatePem))]);

        using var stream = new MemoryStream();
        store.Save(stream, password, new SecureRandom());
        return stream.ToArray();
    }

    /// <summary>Loads an archive and returns the subject DNs of the first key entry's certificate chain (leaf first).</summary>
    internal static IReadOnlyList<string> ReadKeyEntryChainSubjects(byte[] pkcs12, char[] password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        using (var stream = new MemoryStream(pkcs12))
            store.Load(stream, password);

        foreach (var alias in store.Aliases)
        {
            if (!store.IsKeyEntry(alias))
                continue;

            var subjects = new List<string>();
            foreach (var entry in store.GetCertificateChain(alias))
                subjects.Add(entry.Certificate.SubjectDN.ToString());
            return subjects;
        }

        return [];
    }

    /// <summary>
    /// Reads a certificate's certified public key back out as a <c>PUBLIC KEY</c> (SubjectPublicKeyInfo) PEM, so a
    /// test can check a key handle against the certificate itself rather than against another copy of the handle.
    /// The product API deliberately exposes no certificate-to-public-key accessor, hence the test-side extraction.
    /// </summary>
    internal static string ReadCertificatePublicKeyPem(string certificatePem)
    {
        var publicKey = ReadCertificate(certificatePem).GetPublicKey();

        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(publicKey);
        return writer.ToString();
    }

    private static X509Certificate ReadCertificate(string pem)
    {
        using var reader = new StringReader(pem);
        return (X509Certificate)new PemReader(reader).ReadObject();
    }
}
