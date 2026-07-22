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
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
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

    /// <summary>Reads the descriptive fields (subject/issuer/serial/validity/algorithm/version/thumbprint) from a certificate.</summary>
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
    };

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
