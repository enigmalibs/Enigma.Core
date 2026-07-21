namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Provides RSA public-key cryptography: encryption (PKCS#1 v1.5 and OAEP) and signing
/// (RSASSA-PKCS1-v1_5). Keys are supplied as PEM-encoded text — an <c>RSA PUBLIC KEY</c>/<c>PUBLIC KEY</c>
/// PEM for public operations and an (optionally encrypted) <c>PRIVATE KEY</c> PEM for private operations.
/// Where a private-key PEM is encrypted, the passphrase is passed directly as a <see cref="char"/> array.
/// </summary>
/// <remarks>
/// RSA can only process data smaller than the modulus (minus padding overhead), so all operations work on
/// in-memory <see cref="byte"/> arrays rather than streams.
/// </remarks>
public interface IPublicKeyService
{
    /// <summary>Encrypts data with an RSA public key using PKCS#1 v1.5 padding.</summary>
    /// <param name="data">The plaintext to encrypt. Must be short enough for the key size and padding.</param>
    /// <param name="publicKeyPem">The RSA public key, PEM-encoded.</param>
    /// <returns>The ciphertext.</returns>
    byte[] EncryptPkcs1(byte[] data, string publicKeyPem);

    /// <summary>Decrypts PKCS#1 v1.5-padded ciphertext with an RSA private key.</summary>
    /// <param name="ciphertext">The ciphertext produced by <see cref="EncryptPkcs1"/>.</param>
    /// <param name="privateKeyPem">The RSA private key, PEM-encoded.</param>
    /// <param name="password">The passphrase protecting an encrypted private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The recovered plaintext.</returns>
    byte[] DecryptPkcs1(byte[] ciphertext, string privateKeyPem, char[]? password = null);

    /// <summary>Encrypts data with an RSA public key using OAEP padding.</summary>
    /// <param name="data">The plaintext to encrypt. Must be short enough for the key size and padding.</param>
    /// <param name="publicKeyPem">The RSA public key, PEM-encoded.</param>
    /// <param name="hash">The hash function backing the OAEP padding. Defaults to <see cref="RsaOaepHash.Sha256"/>.</param>
    /// <returns>The ciphertext.</returns>
    byte[] EncryptOaep(byte[] data, string publicKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256);

    /// <summary>Decrypts OAEP-padded ciphertext with an RSA private key.</summary>
    /// <param name="ciphertext">The ciphertext produced by <see cref="EncryptOaep"/>.</param>
    /// <param name="privateKeyPem">The RSA private key, PEM-encoded.</param>
    /// <param name="hash">The hash function backing the OAEP padding. Must match the value used to encrypt. Defaults to <see cref="RsaOaepHash.Sha256"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The recovered plaintext.</returns>
    byte[] DecryptOaep(byte[] ciphertext, string privateKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256, char[]? password = null);

    /// <summary>Signs data with an RSA private key (RSASSA-PKCS1-v1_5).</summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="privateKeyPem">The RSA private key, PEM-encoded.</param>
    /// <param name="algorithm">The signature algorithm (hash + RSA). Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The signature.</returns>
    byte[] Sign(byte[] data, string privateKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null);

    /// <summary>Verifies an RSA signature (RSASSA-PKCS1-v1_5) against the data.</summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature produced by <see cref="Sign"/>.</param>
    /// <param name="publicKeyPem">The RSA public key, PEM-encoded.</param>
    /// <param name="algorithm">The signature algorithm (hash + RSA). Must match the value used to sign. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <returns><see langword="true"/> if the signature is valid for the data; otherwise <see langword="false"/>.</returns>
    bool Verify(byte[] data, byte[] signature, string publicKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
}
