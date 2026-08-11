using System;
using Enigma.Core.Internal;
using Org.BouncyCastle.Crypto;

namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// The RSA-facing adapter over <see cref="PemEnvelope"/>, the library's single PEM implementation. It adds only
/// the <see cref="ArgumentNullException"/> guard the PEM-string API contract requires and forwards the calling
/// parameter's name, so a malformed PEM is reported against the argument the caller actually passed.
/// </summary>
/// <remarks>
/// Kept entirely internal so no BouncyCastle type (nor a public <c>PemUtils</c>) reaches the public surface
/// (principle 1). The encryption scheme, the read dispatch and the BouncyCastle exception mapping all live in
/// <see cref="PemEnvelope"/> and are deliberately not restated here: structural PEM problems surface as
/// <see cref="ArgumentException"/>, decryption failures (a wrong or missing password) as
/// <see cref="System.Security.Cryptography.CryptographicException"/>.
/// </remarks>
internal static class PemUtils
{
    /// <summary>Parses an RSA public key from a PEM string.</summary>
    internal static AsymmetricKeyParameter ParsePublicKey(string publicKeyPem)
    {
        if (publicKeyPem is null) throw new ArgumentNullException(nameof(publicKeyPem));

        return PemEnvelope.ReadPublicKey(publicKeyPem, nameof(publicKeyPem));
    }

    /// <summary>
    /// Parses an RSA private key from an optionally encrypted PEM string. All three private-key forms are
    /// accepted: unencrypted PKCS#8, PBES2-encrypted PKCS#8, and the traditional OpenSSL envelope.
    /// </summary>
    internal static AsymmetricKeyParameter ParsePrivateKey(string privateKeyPem, char[]? password)
    {
        if (privateKeyPem is null) throw new ArgumentNullException(nameof(privateKeyPem));

        return PemEnvelope.ReadPrivateKey(privateKeyPem, password, nameof(privateKeyPem));
    }

    /// <summary>Serializes an RSA public key to a <c>PUBLIC KEY</c> PEM string.</summary>
    internal static string WritePublicKeyPem(AsymmetricKeyParameter publicKey)
        => PemEnvelope.WritePublicKeyPem(publicKey);

    /// <summary>
    /// Serializes an RSA private key to a PEM string: an unencrypted PKCS#8 <c>PRIVATE KEY</c> PEM when
    /// <paramref name="password"/> is <see langword="null"/>, or a PBES2 <c>ENCRYPTED PRIVATE KEY</c> PEM
    /// otherwise. The caller's password array is used as-is and is never cleared here.
    /// </summary>
    internal static string WritePrivateKeyPem(AsymmetricKeyParameter privateKey, char[]? password)
        => PemEnvelope.WritePrivateKeyPem(privateKey, password);
}
