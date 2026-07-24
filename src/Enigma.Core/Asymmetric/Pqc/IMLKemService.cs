namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Establishes shared secrets with ML-KEM (Module-Lattice Key-Encapsulation Mechanism, FIPS 203 —
/// formerly CRYSTALS-Kyber). The parameter set is fixed when the service is created by the factory. Keys
/// and ciphertexts are exchanged as raw <see cref="byte"/> arrays in their FIPS 203 encoding.
/// </summary>
public interface IMLKemService
{
    /// <summary>Generates a fresh ML-KEM key pair for the service's parameter set.</summary>
    /// <returns>
    /// The encoded public (encapsulation) and private (decapsulation) keys. The private key is the
    /// <b>expanded</b> FIPS 203 decapsulation-key encoding (not the seed), so it is directly usable by
    /// <see cref="Decapsulate"/>.
    /// </returns>
    (byte[] publicKey, byte[] privateKey) GenerateKeyPair();

    /// <summary>Encapsulates a fresh shared secret against a recipient's public key.</summary>
    /// <param name="publicKey">The recipient's ML-KEM public key, as produced by <see cref="GenerateKeyPair"/>.</param>
    /// <returns>
    /// The ciphertext to send to the recipient and the shared secret to retain. The recipient recovers the
    /// same shared secret by passing the ciphertext to <see cref="Decapsulate"/>.
    /// </returns>
    (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey);

    /// <summary>Decapsulates a ciphertext to recover the shared secret.</summary>
    /// <param name="ciphertext">The ciphertext produced by <see cref="Encapsulate"/>.</param>
    /// <param name="privateKey">The ML-KEM private key matching the public key used to encapsulate.</param>
    /// <returns>The shared secret, identical to the one produced by <see cref="Encapsulate"/>.</returns>
    byte[] Decapsulate(byte[] ciphertext, byte[] privateKey);
}
