namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Provides RSA public-key cryptography: encryption (PKCS#1 v1.5 and OAEP) and signing
/// (RSASSA-PKCS1-v1_5). Keys are supplied as <see cref="RsaKey"/> handles — a PEM is parsed once, by
/// <see cref="RsaKey.ImportPublicKeyPem"/> / <see cref="RsaKey.ImportPrivateKeyPem"/>, and the resulting
/// handle is reused across as many operations as needed.
/// </summary>
/// <remarks>
/// <para>
/// A passphrase is supplied exactly once, when an encrypted private-key PEM is imported; no operation on this
/// service takes one. A handle carrying a private key serves the public operations too (its public half is
/// derived from the private key), so the single handle returned by <see cref="GenerateRsaKey"/> covers both
/// directions; a public-only handle passed to a private operation is an
/// <see cref="System.ArgumentException"/>.
/// </para>
/// <para>
/// RSA can only process data smaller than the modulus (minus padding overhead), so all operations work on
/// in-memory <see cref="byte"/> arrays rather than streams.
/// </para>
/// </remarks>
public interface IPublicKeyService
{
    /// <summary>Generates a fresh RSA key and returns it as a handle carrying both halves.</summary>
    /// <param name="keySizeBits">The RSA modulus size in bits. Larger keys are stronger but slower; 2048 is the recommended minimum. Defaults to 2048.</param>
    /// <returns>
    /// A handle over the generated private key, from which the public half is derived. Serialize either half with
    /// <see cref="RsaKey.ExportPublicKeyPem"/> / <see cref="RsaKey.ExportPrivateKeyPem"/>.
    /// </returns>
    /// <exception cref="System.ArgumentException"><paramref name="keySizeBits"/> is not greater than zero.</exception>
    RsaKey GenerateRsaKey(int keySizeBits = 2048);

    /// <summary>Encrypts data with an RSA public key using PKCS#1 v1.5 padding.</summary>
    /// <param name="data">The plaintext to encrypt. Must be short enough for the key size and padding.</param>
    /// <param name="key">The RSA key. A handle carrying a private key is accepted; its public half is used.</param>
    /// <returns>The ciphertext.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="data"/> or <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The data is too large for the key.</exception>
    byte[] EncryptPkcs1(byte[] data, RsaKey key);

    /// <summary>Decrypts PKCS#1 v1.5-padded ciphertext with an RSA private key.</summary>
    /// <param name="ciphertext">The ciphertext produced by <see cref="EncryptPkcs1"/>.</param>
    /// <param name="key">The RSA key. Must carry a private key.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="ciphertext"/> or <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException"><paramref name="key"/> carries only a public key.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The ciphertext is corrupt, or was produced with a different key or padding.</exception>
    byte[] DecryptPkcs1(byte[] ciphertext, RsaKey key);

    /// <summary>Encrypts data with an RSA public key using OAEP padding.</summary>
    /// <param name="data">The plaintext to encrypt. Must be short enough for the key size and padding.</param>
    /// <param name="key">The RSA key. A handle carrying a private key is accepted; its public half is used.</param>
    /// <param name="hash">The hash function backing the OAEP padding. Defaults to <see cref="RsaOaepHash.Sha256"/>.</param>
    /// <returns>The ciphertext.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="data"/> or <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="hash"/> is not a defined <see cref="RsaOaepHash"/> value.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The data is too large for the key and padding.</exception>
    byte[] EncryptOaep(byte[] data, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256);

    /// <summary>Decrypts OAEP-padded ciphertext with an RSA private key.</summary>
    /// <param name="ciphertext">The ciphertext produced by <see cref="EncryptOaep"/>.</param>
    /// <param name="key">The RSA key. Must carry a private key.</param>
    /// <param name="hash">The hash function backing the OAEP padding. Must match the value used to encrypt. Defaults to <see cref="RsaOaepHash.Sha256"/>.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="ciphertext"/> or <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException"><paramref name="key"/> carries only a public key.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="hash"/> is not a defined <see cref="RsaOaepHash"/> value.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The ciphertext is corrupt, or was produced with a different key or hash.</exception>
    byte[] DecryptOaep(byte[] ciphertext, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256);

    /// <summary>Signs data with an RSA private key (RSASSA-PKCS1-v1_5).</summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="key">The RSA key. Must carry a private key.</param>
    /// <param name="algorithm">The signature algorithm (hash + RSA). Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <returns>The signature.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="data"/> or <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException"><paramref name="key"/> carries only a public key.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="algorithm"/> is not a defined <see cref="RsaSignatureAlgorithm"/> value.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Signing failed.</exception>
    byte[] Sign(byte[] data, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);

    /// <summary>Verifies an RSA signature (RSASSA-PKCS1-v1_5) against the data.</summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature produced by <see cref="Sign"/>.</param>
    /// <param name="key">The RSA key. A handle carrying a private key is accepted; its public half is used.</param>
    /// <param name="algorithm">The signature algorithm (hash + RSA). Must match the value used to sign. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <returns><see langword="true"/> if the signature is valid for the data; otherwise <see langword="false"/>.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="data"/>, <paramref name="signature"/> or <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="algorithm"/> is not a defined <see cref="RsaSignatureAlgorithm"/> value.</exception>
    bool Verify(byte[] data, byte[] signature, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
}
