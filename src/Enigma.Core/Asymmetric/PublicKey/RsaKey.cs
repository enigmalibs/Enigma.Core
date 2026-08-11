using System;
using Enigma.Core.Internal;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// A parsed RSA key — public-only, or a private key from which the public half is derivable. Import a PEM once
/// and hand the resulting handle to <see cref="IPublicKeyService"/> as often as needed, instead of re-parsing a
/// PEM string (and re-supplying its passphrase) on every call.
/// </summary>
/// <remarks>
/// <para>
/// Instances are created by <see cref="ImportPublicKeyPem"/> / <see cref="ImportPrivateKeyPem"/> and are
/// <b>immutable</b>: a handle carries the key it was built from and nothing else, so it is safe to cache in a
/// field and to use concurrently from several threads.
/// </para>
/// <para>
/// <b>Private key material cannot be wiped.</b> The underlying key components are held as arbitrary-precision
/// integers in managed memory; they are immutable objects that may be copied by the garbage collector, so there
/// is no address a <c>Dispose</c> could reliably overwrite. This type is therefore deliberately
/// <b>not</b> <see cref="IDisposable"/> — offering one would be security theatre. Treat the lifetime of a
/// private handle as the lifetime of the secret, and keep it as short as the application allows.
/// </para>
/// <para>
/// The caller owns the lifetime of any passphrase array passed to <see cref="ImportPrivateKeyPem"/> or
/// <see cref="ExportPrivateKeyPem"/>: the library uses it in place and never clears it.
/// </para>
/// <para>
/// No BouncyCastle type appears on this type's public surface (principle 1). A structurally invalid PEM, or a
/// PEM holding the wrong kind of key, surfaces as <see cref="ArgumentException"/>; a wrong or missing
/// passphrase surfaces as <see cref="System.Security.Cryptography.CryptographicException"/>.
/// </para>
/// </remarks>
public sealed class RsaKey
{
    private RsaKey(RsaKeyParameters key)
    {
        BcKey = key;
        KeySizeBits = key.Modulus.BitLength;
    }

    // The single construction point inside the assembly: the two importers below, and (from the breaking phase
    // of this work) PublicKeyService.GenerateRsaKey, which wraps a freshly generated key pair's private half.
    // Deliberately plain internal — the isolation guard treats protected internal as exposed surface.
    internal static RsaKey FromBcKey(RsaKeyParameters key) => new(key);

    /// <summary>The parsed BouncyCastle key, for <see cref="PublicKeyService"/> to wire into a cipher or signer.</summary>
    internal RsaKeyParameters BcKey { get; }

    /// <summary>The size of the RSA modulus, in bits (for example 2048 or 3072).</summary>
    public int KeySizeBits { get; }

    /// <summary>
    /// <see langword="true"/> when this handle carries a private key — and so can sign and decrypt — and
    /// <see langword="false"/> when it carries only a public key.
    /// </summary>
    /// <remarks>
    /// A private handle also serves every public-key operation, because the public half is derived from the
    /// private key's components; a public-only handle serves only those.
    /// </remarks>
    public bool HasPrivateKey => BcKey.IsPrivate;

    /// <summary>Imports an RSA public key from a <c>PUBLIC KEY</c> PEM string.</summary>
    /// <param name="pem">The PEM-encoded public key.</param>
    /// <returns>A handle over the parsed public key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="pem"/> is empty, malformed, or does not contain an RSA public key.
    /// </exception>
    public static RsaKey ImportPublicKeyPem(string pem)
    {
        if (pem is null) throw new ArgumentNullException(nameof(pem));

        if (PemEnvelope.ReadPublicKey(pem, nameof(pem)) is not RsaKeyParameters { IsPrivate: false } key)
            throw new ArgumentException("The PEM does not contain an RSA public key.", nameof(pem));

        return FromBcKey(key);
    }

    /// <summary>
    /// Imports an RSA private key from a PEM string, supplying its passphrase once. Three private-key PEM forms
    /// are accepted: unencrypted PKCS#8 (<c>PRIVATE KEY</c>), PBES2-encrypted PKCS#8
    /// (<c>ENCRYPTED PRIVATE KEY</c>), and the traditional OpenSSL envelope (<c>RSA PRIVATE KEY</c>, with or
    /// without <c>Proc-Type</c>/<c>DEK-Info</c> encryption headers).
    /// </summary>
    /// <param name="pem">The PEM-encoded private key.</param>
    /// <param name="password">
    /// The passphrase protecting <paramref name="pem"/>, or <see langword="null"/> when it is unencrypted. The
    /// array is used as-is and is never cleared by the library.
    /// </param>
    /// <returns>A handle over the parsed private key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="pem"/> is empty, malformed, or does not contain an RSA private key.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// <paramref name="pem"/> is encrypted and <paramref name="password"/> is missing or incorrect.
    /// </exception>
    public static RsaKey ImportPrivateKeyPem(string pem, char[]? password = null)
    {
        if (pem is null) throw new ArgumentNullException(nameof(pem));

        if (PemEnvelope.ReadPrivateKey(pem, password, nameof(pem)) is not RsaKeyParameters { IsPrivate: true } key)
            throw new ArgumentException("The PEM does not contain an RSA private key.", nameof(pem));

        return FromBcKey(key);
    }

    /// <summary>
    /// Exports the public key as a <c>PUBLIC KEY</c> (SubjectPublicKeyInfo) PEM string. A private handle exports
    /// its public half.
    /// </summary>
    /// <returns>The PEM-encoded public key.</returns>
    /// <exception cref="InvalidOperationException">
    /// This handle carries a private key that does not include the public exponent, so no public half can be
    /// derived from it.
    /// </exception>
    public string ExportPublicKeyPem()
    {
        if (!BcKey.IsPrivate)
            return PemEnvelope.WritePublicKeyPem(BcKey);

        // A CRT key carries the public exponent alongside the private components, which is what makes the public
        // half derivable; a bare private key (modulus + private exponent only) does not.
        if (BcKey is not RsaPrivateCrtKeyParameters crt)
            throw new InvalidOperationException(
                "The public key cannot be derived from this private key: it does not carry the public exponent.");

        return PemEnvelope.WritePublicKeyPem(new RsaKeyParameters(isPrivate: false, crt.Modulus, crt.PublicExponent));
    }

    /// <summary>
    /// Exports the private key as a PEM string: an unencrypted PKCS#8 <c>PRIVATE KEY</c> PEM when
    /// <paramref name="password"/> is <see langword="null"/>, or a PBES2 <c>ENCRYPTED PRIVATE KEY</c> PEM
    /// (PBKDF2-HMAC-SHA256, AES-256-CBC) otherwise.
    /// </summary>
    /// <param name="password">
    /// The passphrase to protect the exported key with, or <see langword="null"/> to write it unencrypted. The
    /// array is used as-is and is never cleared by the library.
    /// </param>
    /// <returns>The PEM-encoded private key.</returns>
    /// <exception cref="InvalidOperationException">This handle carries only a public key.</exception>
    public string ExportPrivateKeyPem(char[]? password = null)
    {
        if (!BcKey.IsPrivate)
            throw new InvalidOperationException(
                "This key holds only a public key; there is no private key to export.");

        return PemEnvelope.WritePrivateKeyPem(BcKey, password);
    }
}
