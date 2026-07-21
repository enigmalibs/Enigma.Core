namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Block cipher modes of operation supported by <see cref="IBlockCipherService"/>. The mode determines
/// how successive blocks are processed and how (or whether) an IV/nonce and padding are used.
/// </summary>
public enum BlockCipherMode
{
    /// <summary>
    /// Electronic Code Book. Each block is encrypted independently with the same key; requires padding
    /// and uses no IV. Not recommended for more than a single block, as identical plaintext blocks
    /// produce identical ciphertext blocks.
    /// </summary>
    Ecb,

    /// <summary>
    /// Cipher Block Chaining. Each plaintext block is XORed with the previous ciphertext block before
    /// encryption; requires a random, unique IV and padding.
    /// </summary>
    Cbc,

    /// <summary>
    /// Counter mode (CTR). Turns the block cipher into a stream cipher by encrypting successive counter
    /// values; requires an IV/nonce and needs no padding.
    /// </summary>
    Ctr,

    /// <summary>
    /// Galois/Counter Mode. Authenticated encryption combining CTR-mode encryption with a Galois-field
    /// MAC; requires an IV/nonce, needs no padding, and produces an authentication tag
    /// (see <see cref="GcmMacSize"/>).
    /// </summary>
    Gcm,
}
