using System.Collections.Generic;
using System.IO;
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

    private static X509Certificate ReadCertificate(string pem)
    {
        using var reader = new StringReader(pem);
        return (X509Certificate)new PemReader(reader).ReadObject();
    }
}
