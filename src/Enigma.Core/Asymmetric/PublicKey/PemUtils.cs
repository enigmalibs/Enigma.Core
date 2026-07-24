using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Internal PEM parsing and serialization for RSA keys, backed by BouncyCastle's OpenSSL PEM reader/writer.
/// Kept entirely internal so no BouncyCastle type (nor a public <c>PemUtils</c>/<c>PemPasswordFinder</c>) ever
/// reaches the public surface (principle 1): keys cross the API only as PEM strings and passphrases only as
/// <see cref="char"/> arrays. Structural PEM problems surface as <see cref="ArgumentException"/>; decryption
/// failures (e.g. a wrong password) surface as <see cref="CryptographicException"/>.
/// </summary>
internal static class PemUtils
{
    // AES-256-CBC is the default cipher for an encrypted private-key PEM. BouncyCastle's high-level PEM writer
    // pairs this with the traditional OpenSSL "RSA PRIVATE KEY" envelope (Proc-Type/DEK-Info); PKCS#8
    // "ENCRYPTED PRIVATE KEY" output only supports legacy PBE ciphers in this library version.
    private const string EncryptedPemAlgorithm = "AES-256-CBC";

    /// <summary>Parses an RSA public key from a PEM string.</summary>
    internal static AsymmetricKeyParameter ParsePublicKey(string publicKeyPem)
    {
        if (publicKeyPem is null) throw new ArgumentNullException(nameof(publicKeyPem));
        if (string.IsNullOrWhiteSpace(publicKeyPem))
            throw new ArgumentException("The public-key PEM must not be empty.", nameof(publicKeyPem));

        object? obj;
        try
        {
            using var reader = new StringReader(publicKeyPem);
            obj = new PemReader(reader).ReadObject();
        }
        catch (IOException ex)
        {
            throw new ArgumentException("The public-key PEM is malformed.", nameof(publicKeyPem), ex);
        }

        return obj switch
        {
            AsymmetricKeyParameter { IsPrivate: false } key => key,
            AsymmetricCipherKeyPair pair => pair.Public,
            _ => throw new ArgumentException("The PEM does not contain a valid RSA public key.", nameof(publicKeyPem)),
        };
    }

    /// <summary>Parses an RSA private key from a (optionally encrypted) PEM string.</summary>
    internal static AsymmetricKeyParameter ParsePrivateKey(string privateKeyPem, char[]? password)
    {
        if (privateKeyPem is null) throw new ArgumentNullException(nameof(privateKeyPem));
        if (string.IsNullOrWhiteSpace(privateKeyPem))
            throw new ArgumentException("The private-key PEM must not be empty.", nameof(privateKeyPem));

        object? obj;
        try
        {
            using var reader = new StringReader(privateKeyPem);
            // A password finder is only wired in when a passphrase is supplied; an unencrypted PEM needs none.
            var pemReader = password is null
                ? new PemReader(reader)
                : new PemReader(reader, new CharArrayPasswordFinder(password));
            obj = pemReader.ReadObject();
        }
        catch (PasswordException ex)
        {
            throw new CryptographicException("The private-key PEM is encrypted; a password is required.", ex);
        }
        catch (InvalidCipherTextException ex)
        {
            throw new CryptographicException("The private-key PEM could not be decrypted; the password may be incorrect.", ex);
        }
        catch (PemException ex)
        {
            throw new CryptographicException("The private-key PEM could not be decrypted; the password may be incorrect.", ex);
        }
        catch (IOException ex)
        {
            throw new ArgumentException("The private-key PEM is malformed.", nameof(privateKeyPem), ex);
        }

        return obj switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter { IsPrivate: true } key => key,
            _ => throw new ArgumentException("The PEM does not contain a valid RSA private key.", nameof(privateKeyPem)),
        };
    }

    /// <summary>Serializes an RSA public key to a <c>PUBLIC KEY</c> PEM string.</summary>
    internal static string WritePublicKeyPem(AsymmetricKeyParameter publicKey)
    {
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(publicKey);
        return writer.ToString();
    }

    /// <summary>
    /// Serializes an RSA private key to a PEM string: an unencrypted PKCS#8 <c>PRIVATE KEY</c> PEM when
    /// <paramref name="password"/> is <see langword="null"/>, or an AES-256-CBC-encrypted private-key PEM otherwise.
    /// </summary>
    internal static string WritePrivateKeyPem(AsymmetricKeyParameter privateKey, char[]? password)
    {
        using var writer = new StringWriter();
        var pemWriter = new PemWriter(writer);
        if (password is null)
            pemWriter.WriteObject(new Pkcs8Generator(privateKey));
        else
            // The caller's array is used directly and is not cleared here — the caller owns its lifetime.
            pemWriter.WriteObject(privateKey, EncryptedPemAlgorithm, password, new SecureRandom());
        return writer.ToString();
    }

    // Adapts a char[] passphrase to BouncyCastle's IPasswordFinder. GetPassword returns a clone because the
    // PEM reader may clear the array it receives; the caller's original passphrase must stay intact.
    private sealed class CharArrayPasswordFinder : IPasswordFinder
    {
        private readonly char[] _password;

        internal CharArrayPasswordFinder(char[] password) => _password = password;

        public char[] GetPassword() => (char[])_password.Clone();
    }
}
