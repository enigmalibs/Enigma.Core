namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Converts ML-DSA (FIPS 204) keys between the raw <see cref="byte"/> arrays used by
/// <see cref="IMLDsaService"/> and PEM text: <c>PUBLIC KEY</c>, <c>PRIVATE KEY</c> and PBES2-encrypted
/// <c>ENCRYPTED PRIVATE KEY</c> envelopes.
/// </summary>
/// <remarks>
/// <para>
/// This service performs no signing or verification — it is purely a serialization concern, deliberately kept
/// apart from <see cref="IMLDsaService"/>. Unlike the raw <see cref="byte"/> API, reading a PEM also recovers the
/// <see cref="MLDsaParameterSet"/>, because the PKCS#8 / SubjectPublicKeyInfo envelope names the algorithm OID.
/// The parameter set is therefore a per-call argument here rather than fixed by the factory.
/// </para>
/// <para>
/// Private-key bytes are always the <b>expanded</b> FIPS 204 encoding in both directions — exactly what
/// <see cref="IMLDsaService.GenerateKeyPair"/> returns and what <see cref="IMLDsaService.Sign"/> accepts. A
/// seed-format PEM is expanded on read, so the bytes handed back are always directly usable.
/// </para>
/// </remarks>
public interface IMLDsaPemService
{
    /// <summary>
    /// Generates a fresh ML-DSA key pair and returns both keys as PEM-encoded text. Use this rather than
    /// <see cref="ToPrivateKeyPem"/> when you want a <see cref="MLPrivateKeyPemFormat.Seed"/>-format private key:
    /// the seed exists only at generation time and cannot be recovered from an expanded key afterwards.
    /// </summary>
    /// <param name="parameterSet">The ML-DSA parameter set (security level) to generate.</param>
    /// <param name="password">
    /// A passphrase used to encrypt the returned private-key PEM (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC), or
    /// <see langword="null"/> to return the private key unencrypted. The array is not cleared by this method — the
    /// caller owns clearing it.
    /// </param>
    /// <param name="format">
    /// Which representation of the private key to store. Defaults to <see cref="MLPrivateKeyPemFormat.Seed"/>,
    /// the smallest form.
    /// </param>
    /// <returns>
    /// A <c>PUBLIC KEY</c> PEM, and a <c>PRIVATE KEY</c> PEM when <paramref name="password"/> is
    /// <see langword="null"/> or an <c>ENCRYPTED PRIVATE KEY</c> PEM otherwise.
    /// </returns>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// <paramref name="parameterSet"/> or <paramref name="format"/> is not a defined enum value.
    /// </exception>
    (string publicKeyPem, string privateKeyPem) GenerateKeyPairPem(
        MLDsaParameterSet parameterSet,
        char[]? password = null,
        MLPrivateKeyPemFormat format = MLPrivateKeyPemFormat.Seed);

    /// <summary>Serializes an ML-DSA public key to a <c>PUBLIC KEY</c> PEM string.</summary>
    /// <param name="publicKey">The public key, in its FIPS 204 encoding.</param>
    /// <param name="parameterSet">The parameter set <paramref name="publicKey"/> belongs to.</param>
    /// <returns>The <c>PUBLIC KEY</c> PEM.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="publicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException"><paramref name="publicKey"/> is not a valid key for <paramref name="parameterSet"/>.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="parameterSet"/> is not a defined enum value.</exception>
    string ToPublicKeyPem(byte[] publicKey, MLDsaParameterSet parameterSet);

    /// <summary>
    /// Serializes an ML-DSA private key to a PEM string: an unencrypted <c>PRIVATE KEY</c> PEM when
    /// <paramref name="password"/> is <see langword="null"/>, or a PBES2-encrypted
    /// <c>ENCRYPTED PRIVATE KEY</c> PEM otherwise.
    /// </summary>
    /// <remarks>
    /// This always writes the <b>expanded</b> key encoding (<see cref="MLPrivateKeyPemFormat.ExpandedKey"/>), and
    /// deliberately takes no format argument: a FIPS 204 expanded private key does not contain its generation
    /// seed, so no seed-bearing format is producible from one. Call
    /// <see cref="GenerateKeyPairPem"/> instead if you need <see cref="MLPrivateKeyPemFormat.Seed"/> output.
    /// </remarks>
    /// <param name="privateKey">The private key, in its expanded FIPS 204 encoding, as returned by <see cref="IMLDsaService.GenerateKeyPair"/>.</param>
    /// <param name="parameterSet">The parameter set <paramref name="privateKey"/> belongs to.</param>
    /// <param name="password">
    /// A passphrase used to encrypt the PEM (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC), or <see langword="null"/>
    /// for an unencrypted PEM. The array is not cleared by this method — the caller owns clearing it.
    /// </param>
    /// <returns>The private-key PEM.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="privateKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException"><paramref name="privateKey"/> is not a valid key for <paramref name="parameterSet"/>.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="parameterSet"/> is not a defined enum value.</exception>
    string ToPrivateKeyPem(byte[] privateKey, MLDsaParameterSet parameterSet, char[]? password = null);

    /// <summary>Parses an ML-DSA public key from a <c>PUBLIC KEY</c> PEM string.</summary>
    /// <param name="pem">The PEM text.</param>
    /// <returns>The public key in its FIPS 204 encoding, and the parameter set recovered from the algorithm OID.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException">
    /// <paramref name="pem"/> is empty, malformed, or does not contain an ML-DSA public key — including when it
    /// contains a private key, a key of another algorithm, or an ML-DSA parameter set this library does not expose.
    /// </exception>
    (byte[] publicKey, MLDsaParameterSet parameterSet) FromPublicKeyPem(string pem);

    /// <summary>Parses an ML-DSA private key from an optionally encrypted private-key PEM string.</summary>
    /// <param name="pem">The PEM text: a <c>PRIVATE KEY</c> or <c>ENCRYPTED PRIVATE KEY</c> envelope.</param>
    /// <param name="password">
    /// The passphrase protecting an encrypted PEM, or <see langword="null"/> if the PEM is not encrypted. The
    /// array is not cleared by this method — the caller owns clearing it.
    /// </param>
    /// <returns>
    /// The private key in its <b>expanded</b> FIPS 204 encoding — a seed-format PEM is expanded here, so the bytes
    /// are directly usable by <see cref="IMLDsaService.Sign"/> — and the parameter set recovered from the
    /// algorithm OID.
    /// </returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentException">
    /// <paramref name="pem"/> is empty, malformed, or does not contain an ML-DSA private key — including when it
    /// contains a public key, a key of another algorithm, or an ML-DSA parameter set this library does not expose.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// <paramref name="pem"/> is encrypted and <paramref name="password"/> is <see langword="null"/> or wrong.
    /// </exception>
    (byte[] privateKey, MLDsaParameterSet parameterSet) FromPrivateKeyPem(string pem, char[]? password = null);
}
