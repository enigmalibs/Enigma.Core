using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Default <see cref="IBlockCipherParametersFactory"/> implementation. ECB uses a bare
/// <see cref="KeyParameter"/>; CBC and CTR wrap it in <see cref="ParametersWithIV"/>; GCM builds an
/// <see cref="AeadParameters"/> carrying the tag size and (when supplied) the associated data.
/// </summary>
internal sealed class BlockCipherParametersFactory : IBlockCipherParametersFactory
{
    /// <inheritdoc />
    public ICipherParameters Create(
        BlockCipherMode mode,
        byte[] key,
        byte[]? iv,
        int gcmMacSizeBits,
        byte[]? associatedData)
    {
        switch (mode)
        {
            case BlockCipherMode.Ecb:
                return new KeyParameter(key);

            case BlockCipherMode.Cbc:
            case BlockCipherMode.Ctr:
                return new ParametersWithIV(new KeyParameter(key), iv);

            case BlockCipherMode.Gcm:
                // gcmMacSizeBits is validated by the service before this point, but re-validate here so
                // the internal factory is safe to call directly.
                if (!GcmMacSize.IsValid(gcmMacSizeBits))
                    throw new ArgumentException(GcmMacSize.RangeDescription, nameof(gcmMacSizeBits));

                return associatedData is null
                    ? new AeadParameters(new KeyParameter(key), gcmMacSizeBits, iv)
                    : new AeadParameters(new KeyParameter(key), gcmMacSizeBits, iv, associatedData);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown block cipher mode.");
        }
    }
}
