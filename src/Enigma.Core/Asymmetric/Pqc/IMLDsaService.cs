namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Generates and verifies digital signatures with ML-DSA (Module-Lattice Digital Signature Algorithm,
/// FIPS 204 — formerly CRYSTALS-Dilithium). The parameter set is fixed when the service is created by the
/// factory. Keys and signatures are exchanged as raw <see cref="byte"/> arrays in their FIPS 204 encoding.
/// </summary>
public interface IMLDsaService
{
    /// <summary>Generates a fresh ML-DSA key pair for the service's parameter set.</summary>
    /// <returns>
    /// The encoded public and private keys. The public key is the standard FIPS 204 verification key; the private
    /// key is the <b>expanded</b> secret-key encoding (not the 32-byte seed), so it is directly usable by
    /// <see cref="Sign"/> without seed re-derivation.
    /// </returns>
    (byte[] publicKey, byte[] privateKey) GenerateKeyPair();

    /// <summary>Signs a message with an ML-DSA private key.</summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="privateKey">The ML-DSA private key, as produced by <see cref="GenerateKeyPair"/>.</param>
    /// <returns>The signature.</returns>
    byte[] Sign(byte[] message, byte[] privateKey);

    /// <summary>Verifies an ML-DSA signature against the message.</summary>
    /// <param name="message">The message that was signed.</param>
    /// <param name="signature">The signature produced by <see cref="Sign"/>.</param>
    /// <param name="publicKey">The ML-DSA public key matching the signing key.</param>
    /// <returns><see langword="true"/> if the signature is valid for the message; otherwise <see langword="false"/>.</returns>
    bool Verify(byte[] message, byte[] signature, byte[] publicKey);
}
