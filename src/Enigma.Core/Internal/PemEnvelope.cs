using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
// Org.BouncyCastle.OpenSsl and Org.BouncyCastle.Utilities.IO.Pem both publish a PemReader, so the unqualified
// name is ambiguous: the OpenSSL one decodes a PEM straight to a key object, while the low-level one exposes the
// raw envelope (label + DER content) that the read dispatch below keys on. Both are needed, so both are aliased.
using OpenSslPemReader = Org.BouncyCastle.OpenSsl.PemReader;
using PemEnvelopeReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;
using PemEnvelopeWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;
using PemObject = Org.BouncyCastle.Utilities.IO.Pem.PemObject;
// BouncyCastle 2.7.0 moved PasswordException into Org.BouncyCastle.OpenSsl; the Security namespace keeps an
// [Obsolete] base of the same name, which would fail the zero-warning build if it were bound by accident.
using PasswordException = Org.BouncyCastle.OpenSsl.PasswordException;
using PemException = Org.BouncyCastle.OpenSsl.PemException;
using IPasswordFinder = Org.BouncyCastle.OpenSsl.IPasswordFinder;

namespace Enigma.Core.Internal;

/// <summary>
/// The library's single PEM envelope implementation: it writes and reads <c>PUBLIC KEY</c>,
/// <c>PRIVATE KEY</c> and PBES2-encrypted <c>ENCRYPTED PRIVATE KEY</c> PEMs for <em>any</em> key family
/// BouncyCastle can encode — RSA, ML-DSA, ML-KEM — because it only ever handles the generic
/// <see cref="AsymmetricKeyParameter"/> / <see cref="PrivateKeyInfo"/> abstractions and never an
/// algorithm-specific type.
/// </summary>
/// <remarks>
/// <para>
/// Kept entirely internal so no BouncyCastle type reaches the public surface (principle 1): keys cross the
/// public API as raw bytes or PEM text, and passphrases only as <see cref="char"/> arrays.
/// </para>
/// <para>
/// This type exists so that the encryption scheme, the PBKDF2 iteration count and the BouncyCastle
/// exception mapping are declared exactly once in the assembly. Structural PEM problems surface as
/// <see cref="ArgumentException"/> carrying the calling API's parameter name; decryption failures — a wrong
/// or missing passphrase — surface as <see cref="CryptographicException"/>. No BouncyCastle exception
/// escapes.
/// </para>
/// </remarks>
internal static class PemEnvelope
{
    /// <summary>PEM label of a SubjectPublicKeyInfo envelope.</summary>
    internal const string PublicKeyLabel = "PUBLIC KEY";

    /// <summary>PEM label of an unencrypted PKCS#8 PrivateKeyInfo envelope.</summary>
    internal const string PrivateKeyLabel = "PRIVATE KEY";

    /// <summary>PEM label of a PKCS#8 EncryptedPrivateKeyInfo envelope.</summary>
    internal const string EncryptedPrivateKeyLabel = "ENCRYPTED PRIVATE KEY";

    /// <summary>
    /// PBKDF2 iteration count for an encrypted private-key PEM. 600 000 matches OWASP's current guidance for
    /// PBKDF2-HMAC-SHA256 and costs roughly 0.6 s per import — a one-time cost paid when a key is read.
    /// </summary>
    internal const int Pbkdf2IterationCount = 600_000;

    // PBES2 salt length. 16 bytes is the PKCS#5 recommendation and what OpenSSL emits.
    private const int SaltSizeBytes = 16;

    private const string PasswordRequiredMessage = "The private-key PEM is encrypted; a password is required.";
    private const string DecryptionFailedMessage =
        "The private-key PEM could not be decrypted; the password may be incorrect.";

    /// <summary>Wraps DER bytes in a PEM envelope carrying <paramref name="label"/>.</summary>
    internal static string WritePem(string label, byte[] der)
    {
        using var writer = new StringWriter();
        new PemEnvelopeWriter(writer).WriteObject(new PemObject(label, der));
        return writer.ToString();
    }

    /// <summary>Reads the label (the text after <c>-----BEGIN </c>) of a PEM envelope.</summary>
    internal static string ReadPemLabel(string pem, string paramName) => ReadEnvelope(pem, paramName).Type;

    /// <summary>Reads the DER payload of a PEM envelope, base64-decoded.</summary>
    internal static byte[] ReadPemContent(string pem, string paramName) => ReadEnvelope(pem, paramName).Content;

    /// <summary>Serializes a public key to a <c>PUBLIC KEY</c> (SubjectPublicKeyInfo) PEM.</summary>
    internal static string WritePublicKeyPem(AsymmetricKeyParameter publicKey)
        => WritePem(PublicKeyLabel, SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded());

    /// <summary>
    /// Serializes an already-built PKCS#8 <see cref="PrivateKeyInfo"/> to a PEM string: an unencrypted
    /// <c>PRIVATE KEY</c> PEM when <paramref name="password"/> is <see langword="null"/>, otherwise a PBES2
    /// <c>ENCRYPTED PRIVATE KEY</c> PEM (PBKDF2-HMAC-SHA256 + AES-256-CBC).
    /// </summary>
    /// <remarks>
    /// This overload exists for the post-quantum families, which must pin the private-key encoding format on the
    /// key parameters <em>before</em> the PrivateKeyInfo is built; callers with nothing to pin can hand over the
    /// key itself through the <see cref="WritePrivateKeyPem(AsymmetricKeyParameter, char[])"/> overload.
    /// The caller's password array is used as-is and is never cleared here — the caller owns its lifetime.
    /// </remarks>
    internal static string WritePrivateKeyPem(PrivateKeyInfo keyInfo, char[]? password)
    {
        if (password is null)
            return WritePem(PrivateKeyLabel, keyInfo.GetDerEncoded());

        var random = new SecureRandom();
        var salt = new byte[SaltSizeBytes];
        random.NextBytes(salt);

        var encrypted = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            NistObjectIdentifiers.IdAes256Cbc,
            PkcsObjectIdentifiers.IdHmacWithSha256,
            password,
            salt,
            Pbkdf2IterationCount,
            random,
            keyInfo);

        return WritePem(EncryptedPrivateKeyLabel, encrypted.GetDerEncoded());
    }

    /// <summary>
    /// Serializes a private key to a PEM string, unencrypted or PBES2-encrypted exactly as
    /// <see cref="WritePrivateKeyPem(PrivateKeyInfo, char[])"/> does.
    /// </summary>
    internal static string WritePrivateKeyPem(AsymmetricKeyParameter privateKey, char[]? password)
        => WritePrivateKeyPem(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey), password);

    /// <summary>Parses a public key from a PEM string, whatever the key family.</summary>
    internal static AsymmetricKeyParameter ReadPublicKey(string pem, string paramName)
    {
        RequireNonEmpty(pem, paramName);

        var obj = ReadMappingFailures(() =>
        {
            using var reader = new StringReader(pem);
            return new OpenSslPemReader(reader).ReadObject();
        }, paramName);

        // The traditional OpenSSL RSA envelope decodes to a key pair rather than a bare key, so a public key can
        // arrive either way. Arm order matters: a key pair's Private half is not a valid answer here.
        return obj switch
        {
            AsymmetricKeyParameter { IsPrivate: false } key => key,
            AsymmetricCipherKeyPair pair => pair.Public,
            _ => throw new ArgumentException("The PEM does not contain a public key.", paramName),
        };
    }

    /// <summary>Parses a private key from an optionally encrypted PEM string, whatever the key family.</summary>
    internal static AsymmetricKeyParameter ReadPrivateKey(string pem, char[]? password, string paramName)
    {
        RequireNonEmpty(pem, paramName);

        // Dispatch on the envelope label. BouncyCastle's OpenSSL reader cannot decrypt a PKCS#8
        // EncryptedPrivateKeyInfo (it raises PemException regardless of the password), so that envelope takes the
        // explicit PBES2 path below; everything else — PKCS#8 PRIVATE KEY, the traditional OpenSSL forms — goes
        // through the OpenSSL reader, which handles its own Proc-Type/DEK-Info decryption.
        var obj = string.Equals(ReadPemLabel(pem, paramName), EncryptedPrivateKeyLabel, StringComparison.Ordinal)
            ? ReadEncryptedPrivateKey(pem, password, paramName)
            : ReadMappingFailures(() =>
            {
                using var reader = new StringReader(pem);
                // A password finder is only wired in when a passphrase is supplied; an unencrypted PEM needs none.
                var pemReader = password is null
                    ? new OpenSslPemReader(reader)
                    : new OpenSslPemReader(reader, new CharArrayPasswordFinder(password));
                return pemReader.ReadObject();
            }, paramName);

        // As in ReadPublicKey, the traditional OpenSSL RSA envelope decodes to a key pair; unwrap it first.
        return obj switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter { IsPrivate: true } key => key,
            _ => throw new ArgumentException("The PEM does not contain a private key.", paramName),
        };
    }

    private static object? ReadEncryptedPrivateKey(string pem, char[]? password, string paramName)
    {
        // Checked before BouncyCastle is involved: with no passphrase the envelope simply cannot be opened, and
        // this is the one path where the reader would otherwise report a decryption failure instead.
        if (password is null)
            throw new CryptographicException(PasswordRequiredMessage);

        var content = ReadPemContent(pem, paramName);

        return ReadMappingFailures(() =>
        {
            var encryptedKeyInfo = ParseEncryptedPrivateKeyInfo(content, paramName);
            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password, encryptedKeyInfo);
            return PrivateKeyFactory.CreateKey(keyInfo);
        }, paramName);
    }

    // BouncyCastle reports a payload that is not a well-formed EncryptedPrivateKeyInfo as a bare ArgumentException
    // with no parameter name; re-wrapping it keeps the "malformed PEM names the offending parameter" contract.
    private static EncryptedPrivateKeyInfo ParseEncryptedPrivateKeyInfo(byte[] content, string paramName)
    {
        try
        {
            return EncryptedPrivateKeyInfo.GetInstance(content);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("The private-key PEM is malformed.", paramName, ex);
        }
    }

    /// <summary>
    /// Runs a BouncyCastle PEM read and maps its failure modes onto the library's exception contract. This is the
    /// only such mapping, and the branch order is load-bearing.
    /// </summary>
    private static object? ReadMappingFailures(Func<object?> read, string paramName)
    {
        try
        {
            return read();
        }
        // Must come first: PasswordException derives from IOException (via the obsolete Security base), not from
        // PemException, so the IOException arm below would otherwise swallow it and report a malformed PEM.
        catch (PasswordException ex)
        {
            throw new CryptographicException(PasswordRequiredMessage, ex);
        }
        // The wrong-password case on the explicit PBES2 path ("pad block corrupted").
        catch (InvalidCipherTextException ex)
        {
            throw new CryptographicException(DecryptionFailedMessage, ex);
        }
        // The wrong-password and missing-password cases on the OpenSSL reader path.
        catch (PemException ex)
        {
            throw new CryptographicException(DecryptionFailedMessage, ex);
        }
        // Everything structural: a truncated envelope, invalid base64, and deliberately also
        // Org.BouncyCastle.OpenSsl.EncryptionException (an IOException raised for an unrecognised DEK-Info
        // cipher) — an unknown cipher header is a defect in the PEM, not a failed decryption. Keep this arm
        // separate from the PemException arm above.
        catch (IOException ex)
        {
            throw new ArgumentException("The private-key PEM is malformed.", paramName, ex);
        }
    }

    private static PemObject ReadEnvelope(string pem, string paramName)
    {
        RequireNonEmpty(pem, paramName);

        PemObject? envelope;
        try
        {
            using var reader = new StringReader(pem);
            envelope = new PemEnvelopeReader(reader).ReadPemObject();
        }
        catch (IOException ex)
        {
            throw new ArgumentException("The PEM is malformed.", paramName, ex);
        }

        // The low-level reader returns null rather than throwing when the text carries no PEM boundary at all.
        return envelope ?? throw new ArgumentException("The PEM is malformed.", paramName);
    }

    private static void RequireNonEmpty(string pem, string paramName)
    {
        if (string.IsNullOrWhiteSpace(pem))
            throw new ArgumentException("The PEM must not be empty.", paramName);
    }

    // Adapts a char[] passphrase to BouncyCastle's IPasswordFinder. GetPassword returns a clone because the PEM
    // reader may clear the array it receives; the caller's original passphrase must stay intact.
    private sealed class CharArrayPasswordFinder : IPasswordFinder
    {
        private readonly char[] _password;

        internal CharArrayPasswordFinder(char[] password) => _password = password;

        public char[] GetPassword() => (char[])_password.Clone();
    }
}
