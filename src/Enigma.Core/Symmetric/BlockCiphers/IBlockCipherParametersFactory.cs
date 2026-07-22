using Org.BouncyCastle.Crypto;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Internal factory that translates the caller's BouncyCastle-free arguments (key, IV/nonce, mode, GCM
/// tag size and optional associated data) into the concrete BouncyCastle <see cref="ICipherParameters"/>
/// used to initialize a cipher. Kept internal so no BouncyCastle parameter type reaches the public
/// surface (principle 1); associated data is carried into <c>AeadParameters</c> here.
/// </summary>
internal interface IBlockCipherParametersFactory
{
    /// <summary>
    /// Builds the cipher parameters for <paramref name="mode"/>.
    /// </summary>
    /// <param name="mode">The block cipher mode of operation.</param>
    /// <param name="key">The secret key.</param>
    /// <param name="iv">The IV/nonce; ignored for ECB, required for CBC/CTR/GCM.</param>
    /// <param name="gcmMacSizeBits">The GCM authentication tag size in bits (used only for GCM).</param>
    /// <param name="associatedData">Optional associated data (used only for GCM).</param>
    /// <returns>Cipher parameters ready to initialize the cipher for the mode.</returns>
    ICipherParameters Create(
        BlockCipherMode mode,
        byte[] key,
        byte[]? iv,
        int gcmMacSizeBits,
        byte[]? associatedData);
}
