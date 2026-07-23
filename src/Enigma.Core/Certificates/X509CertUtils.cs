using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using SysBigInteger = System.Numerics.BigInteger;

namespace Enigma.Core.Certificates;

/// <summary>
/// Internal X.509 plumbing over BouncyCastle: PEM read/write for certificates and CSRs, RSA public-key
/// derivation, v3-extension emission from <see cref="X509CertificateOptions"/>, random serial generation,
/// and read-back of the descriptive fields into <see cref="CertificateInfo"/>. Kept entirely internal so
/// no BouncyCastle type reaches the public surface (principle 1); structural PEM problems surface as
/// <see cref="ArgumentException"/> at this boundary.
/// </summary>
internal static class X509CertUtils
{
    /// <summary>Parses <paramref name="distinguishedName"/> into an X.509 name, wrapping a malformed value.</summary>
    internal static X509Name ParseDistinguishedName(string distinguishedName, string paramName)
    {
        try
        {
            return new X509Name(distinguishedName);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or FormatException)
        {
            throw new ArgumentException($"The distinguished name '{distinguishedName}' is malformed.", paramName, ex);
        }
    }

    /// <summary>Derives the RSA public key that pairs with an RSA private key.</summary>
    internal static AsymmetricKeyParameter DerivePublicKey(AsymmetricKeyParameter privateKey)
    {
        if (privateKey is RsaPrivateCrtKeyParameters crt)
            return new RsaKeyParameters(isPrivate: false, crt.Modulus, crt.PublicExponent);

        throw new ArgumentException(
            "The private key is not an RSA private key with the parameters required to derive its public key.");
    }

    /// <summary>Generates a random 128-bit non-negative certificate serial number.</summary>
    internal static BcBigInteger GenerateSerialNumber(SecureRandom random)
        => BigIntegers.CreateRandomBigInteger(128, random);

    /// <summary>
    /// Adds the <c>BasicConstraints</c>, <c>KeyUsage</c> and <c>SubjectAlternativeName</c> extensions to a
    /// certificate generator according to <paramref name="options"/>. A <see langword="null"/> options
    /// argument, or a <see langword="null"/>/empty property, omits the corresponding extension.
    /// </summary>
    internal static void ApplyExtensions(X509V3CertificateGenerator generator, X509CertificateOptions? options)
    {
        if (options is null)
            return;

        if (options.IsCertificateAuthority is { } isCa)
            generator.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(isCa));

        if (options.KeyUsage is { } keyUsage)
            generator.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(ToBcKeyUsage(keyUsage)));

        if (options.SubjectAlternativeNames is { Count: > 0 } sans)
        {
            var names = new GeneralName[sans.Count];
            for (var i = 0; i < sans.Count; i++)
                names[i] = new GeneralName(GeneralName.DnsName, sans[i]);
            generator.AddExtension(X509Extensions.SubjectAlternativeName, critical: false, new GeneralNames(names));
        }
    }

    /// <summary>Serializes a certificate or CSR to a PEM string.</summary>
    internal static string WritePem(object pemObject)
    {
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(pemObject);
        return writer.ToString();
    }

    /// <summary>Parses an X.509 certificate from a PEM string.</summary>
    internal static X509Certificate ReadCertificate(string certificatePem, string paramName)
    {
        if (certificatePem is null) throw new ArgumentNullException(paramName);
        if (string.IsNullOrWhiteSpace(certificatePem))
            throw new ArgumentException("The certificate PEM must not be empty.", paramName);

        return ReadPemObject(certificatePem, paramName) switch
        {
            X509Certificate cert => cert,
            _ => throw new ArgumentException("The PEM does not contain an X.509 certificate.", paramName),
        };
    }

    /// <summary>Parses a PKCS#10 certificate signing request from a PEM string.</summary>
    internal static Pkcs10CertificationRequest ReadCsr(string csrPem, string paramName)
    {
        if (csrPem is null) throw new ArgumentNullException(paramName);
        if (string.IsNullOrWhiteSpace(csrPem))
            throw new ArgumentException("The certificate signing request PEM must not be empty.", paramName);

        return ReadPemObject(csrPem, paramName) switch
        {
            Pkcs10CertificationRequest csr => csr,
            _ => throw new ArgumentException("The PEM does not contain a PKCS#10 certificate signing request.", paramName),
        };
    }

    /// <summary>Parses an X.509 certificate revocation list from a PEM string.</summary>
    internal static X509Crl ReadCrl(string crlPem, string paramName)
    {
        if (crlPem is null) throw new ArgumentNullException(paramName);
        if (string.IsNullOrWhiteSpace(crlPem))
            throw new ArgumentException("The CRL PEM must not be empty.", paramName);

        return ReadPemObject(crlPem, paramName) switch
        {
            X509Crl crl => crl,
            _ => throw new ArgumentException("The PEM does not contain an X.509 certificate revocation list.", paramName),
        };
    }

    /// <summary>DER-encodes a certificate.</summary>
    internal static byte[] ToDer(X509Certificate certificate) => certificate.GetEncoded();

    /// <summary>Parses an X.509 certificate from DER-encoded bytes, wrapping malformed input as <see cref="ArgumentException"/>.</summary>
    internal static X509Certificate ReadCertificateFromDer(byte[] derEncodedCertificate, string paramName)
    {
        if (derEncodedCertificate is null) throw new ArgumentNullException(paramName);
        if (derEncodedCertificate.Length == 0)
            throw new ArgumentException("The DER-encoded certificate must not be empty.", paramName);

        X509Certificate? certificate;
        try
        {
            certificate = new X509CertificateParser().ReadCertificate(derEncodedCertificate);
        }
        // BouncyCastle surfaces malformed DER as this family (CertificateException for structural certificate
        // problems, IOException/ArgumentException/InvalidOperationException for ASN.1 decode failures).
        catch (Exception ex) when (ex is CertificateException or IOException or ArgumentException or InvalidOperationException)
        {
            throw new ArgumentException("The bytes are not a well-formed DER certificate.", paramName, ex);
        }

        return certificate ?? throw new ArgumentException("The bytes do not contain an X.509 certificate.", paramName);
    }

    /// <summary>
    /// Bundles a certificate + private key (+ optional chain) into a password-protected PKCS#12 archive under a
    /// fixed alias. An empty <paramref name="password"/> is honoured (produces a MAC'd archive with an empty passphrase).
    /// </summary>
    internal static byte[] ExportPkcs12(X509Certificate certificate, AsymmetricKeyParameter privateKey, char[] password, IReadOnlyList<X509Certificate> chain, SecureRandom random)
    {
        const string alias = "enigma";

        var entries = new X509CertificateEntry[1 + chain.Count];
        entries[0] = new X509CertificateEntry(certificate);
        for (var i = 0; i < chain.Count; i++)
            entries[i + 1] = new X509CertificateEntry(chain[i]);

        var store = new Pkcs12StoreBuilder().Build();
        store.SetKeyEntry(alias, new AsymmetricKeyEntry(privateKey), entries);

        using var stream = new MemoryStream();
        store.Save(stream, password, random);
        return stream.ToArray();
    }

    /// <summary>
    /// Extracts the first key entry's certificate + private key from a PKCS#12 archive. A read failure (wrong
    /// password or corrupt archive) surfaces as <see cref="CryptographicException"/>.
    /// </summary>
    internal static (X509Certificate certificate, AsymmetricKeyParameter privateKey) ImportPkcs12(byte[] pkcs12, char[] password, string paramName)
    {
        if (pkcs12 is null) throw new ArgumentNullException(paramName);
        if (pkcs12.Length == 0)
            throw new ArgumentException("The PKCS#12 archive must not be empty.", paramName);

        var store = new Pkcs12StoreBuilder().Build();
        try
        {
            using var stream = new MemoryStream(pkcs12);
            store.Load(stream, password);
        }
        // A MAC mismatch (wrong password) surfaces as IOException; well-formed DER of the wrong ASN.1 shape (not a PFX
        // SEQUENCE — e.g. a DER certificate handed here by mistake) surfaces as ArgumentException from the Pfx parser,
        // and a key-type surprise can surface as InvalidCastException. All mean "the archive could not be read", and
        // none may escape as a raw BouncyCastle-bearing exception. (The empty / no-key-entry ArgumentExceptions are
        // thrown outside this try, so they are not swallowed here.)
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException)
        {
            throw new CryptographicException(
                "The PKCS#12 archive could not be read; the password may be incorrect or the archive is corrupt.", ex);
        }

        foreach (var storeAlias in store.Aliases)
        {
            if (!store.IsKeyEntry(storeAlias))
                continue;

            var certificateChain = store.GetCertificateChain(storeAlias);
            if (certificateChain is { Length: > 0 })
                return (certificateChain[0].Certificate, store.GetKey(storeAlias).Key);
        }

        throw new ArgumentException("The PKCS#12 archive contains no key entry with a certificate.", paramName);
    }

    /// <summary>Reads the descriptive fields (identity, serial, validity, algorithm, version, thumbprint and the CA/KeyUsage/SAN extensions) from a certificate.</summary>
    internal static CertificateInfo ExtractInfo(X509Certificate certificate) => new()
    {
        Subject = certificate.SubjectDN.ToString(),
        Issuer = certificate.IssuerDN.ToString(),
        SerialNumber = ToSystemBigInteger(certificate.SerialNumber),
        NotBefore = ToDateTimeOffset(certificate.NotBefore),
        NotAfter = ToDateTimeOffset(certificate.NotAfter),
        SignatureAlgorithm = certificate.SigAlgName,
        Version = certificate.Version,
        Thumbprint = ComputeThumbprint(certificate),
        IsCertificateAuthority = certificate.GetBasicConstraints() >= 0,
        KeyUsage = FromBcKeyUsage(certificate.GetKeyUsage()),
        SubjectAlternativeNames = ExtractSubjectAlternativeNames(certificate),
    };

    // Maps the KeyUsage extension's bit array (index 0 = digitalSignature … index 8 = decipherOnly, the same
    // order as X509KeyUsage's flags) back to the BC-free enum; null when the certificate has no KeyUsage extension.
    private static X509KeyUsage? FromBcKeyUsage(bool[]? keyUsage)
    {
        if (keyUsage is null)
            return null;

        var flags = X509KeyUsage.None;
        if (IsSet(0)) flags |= X509KeyUsage.DigitalSignature;
        if (IsSet(1)) flags |= X509KeyUsage.NonRepudiation;
        if (IsSet(2)) flags |= X509KeyUsage.KeyEncipherment;
        if (IsSet(3)) flags |= X509KeyUsage.DataEncipherment;
        if (IsSet(4)) flags |= X509KeyUsage.KeyAgreement;
        if (IsSet(5)) flags |= X509KeyUsage.KeyCertSign;
        if (IsSet(6)) flags |= X509KeyUsage.CrlSign;
        if (IsSet(7)) flags |= X509KeyUsage.EncipherOnly;
        if (IsSet(8)) flags |= X509KeyUsage.DecipherOnly;
        return flags;

        bool IsSet(int index) => index < keyUsage.Length && keyUsage[index];
    }

    // Reads DNS/other names from the SubjectAlternativeName extension; empty when absent or unparseable.
    private static IReadOnlyList<string> ExtractSubjectAlternativeNames(X509Certificate certificate)
    {
        var extensionValue = certificate.GetExtensionValue(X509Extensions.SubjectAlternativeName);
        if (extensionValue is null)
            return [];

        try
        {
            var generalNames = GeneralNames.GetInstance(X509ExtensionUtilities.FromExtensionValue(extensionValue));
            var names = new List<string>();
            foreach (var name in generalNames.GetNames())
                names.Add(name.Name.ToString()!);
            return names;
        }
        // A structurally invalid SAN extension is treated as "no SANs". BouncyCastle surfaces ASN.1 decode
        // failures as this family: IOException (raw octet decoding) and ArgumentException / InvalidOperationException
        // (Asn1ParsingException derives from the latter) from GeneralNames.GetInstance. Anything else propagates.
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
        {
            return [];
        }
    }

    // Uppercase-hex SHA-256 over the DER encoding — the settled thumbprint definition.
    private static string ComputeThumbprint(X509Certificate certificate)
    {
        using var sha256 = SHA256.Create();
        var digest = sha256.ComputeHash(certificate.GetEncoded());
        // BitConverter yields uppercase hex on every target framework (Convert.ToHexString is unavailable on netstandard2.0).
        return BitConverter.ToString(digest).Replace("-", string.Empty);
    }

    // BouncyCastle serials are non-negative; parse the decimal form to avoid two's-complement/endianness pitfalls.
    private static SysBigInteger ToSystemBigInteger(BcBigInteger value) => SysBigInteger.Parse(value.ToString());

    // X.509 times are UTC wall-clock; interpret the decoded value as UTC (converting only a Local-kind value).
    private static DateTimeOffset ToDateTimeOffset(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Local
            ? value.ToUniversalTime()
            : DateTime.SpecifyKind(value, DateTimeKind.Utc);
        return new DateTimeOffset(utc);
    }

    // Maps the BC-free flags enum to the KeyUsage extension bit set.
    private static int ToBcKeyUsage(X509KeyUsage keyUsage)
    {
        var bits = 0;
        if ((keyUsage & X509KeyUsage.DigitalSignature) != 0) bits |= KeyUsage.DigitalSignature;
        if ((keyUsage & X509KeyUsage.NonRepudiation) != 0) bits |= KeyUsage.NonRepudiation;
        if ((keyUsage & X509KeyUsage.KeyEncipherment) != 0) bits |= KeyUsage.KeyEncipherment;
        if ((keyUsage & X509KeyUsage.DataEncipherment) != 0) bits |= KeyUsage.DataEncipherment;
        if ((keyUsage & X509KeyUsage.KeyAgreement) != 0) bits |= KeyUsage.KeyAgreement;
        if ((keyUsage & X509KeyUsage.KeyCertSign) != 0) bits |= KeyUsage.KeyCertSign;
        if ((keyUsage & X509KeyUsage.CrlSign) != 0) bits |= KeyUsage.CrlSign;
        if ((keyUsage & X509KeyUsage.EncipherOnly) != 0) bits |= KeyUsage.EncipherOnly;
        if ((keyUsage & X509KeyUsage.DecipherOnly) != 0) bits |= KeyUsage.DecipherOnly;
        return bits;
    }

    private static object ReadPemObject(string pem, string paramName)
    {
        object? obj;
        try
        {
            using var reader = new StringReader(pem);
            obj = new PemReader(reader).ReadObject();
        }
        // BouncyCastle surfaces malformed PEM/DER as this family: IOException (incl. Asn1Exception) for octet/base64
        // decoding, and ArgumentException / InvalidOperationException / FormatException from structural parsing.
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException or FormatException)
        {
            throw new ArgumentException("The PEM is malformed.", paramName, ex);
        }

        return obj ?? throw new ArgumentException("The PEM contains no readable object.", paramName);
    }
}
