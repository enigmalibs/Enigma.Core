using Enigma.Core.Padding;
using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Internal factory that translates the BouncyCastle-free <see cref="PaddingScheme"/> into the concrete
/// BouncyCastle <see cref="IBlockCipherPadding"/> used to wrap a padded block cipher. Kept internal so
/// the BouncyCastle padding type never reaches the public surface (principle 1).
/// </summary>
internal interface IBlockCipherPaddingFactory
{
    /// <summary>
    /// Creates the BouncyCastle padder for <paramref name="scheme"/>, ready for use. ISO 10126-2 is
    /// seeded with a secure random source; X9.23 is deliberately left zero-filling.
    /// </summary>
    /// <param name="scheme">The padding scheme; must not be <see cref="PaddingScheme.None"/>.</param>
    /// <returns>A configured BouncyCastle block cipher padding.</returns>
    IBlockCipherPadding Create(PaddingScheme scheme);
}
