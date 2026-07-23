using System;
using Enigma.Core.Padding;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Default <see cref="IBlockCipherPaddingFactory"/> implementation. Mirrors the scheme→padder mapping
/// used by <see cref="PaddingService"/>: ISO 10126-2 must be seeded with a secure random source before
/// use (its <c>AddPadding</c> dereferences the random source), whereas X9.23 is left unseeded so it
/// zero-fills. PKCS#7 and ISO 7816-4 are deterministic.
/// </summary>
internal sealed class BlockCipherPaddingFactory : IBlockCipherPaddingFactory
{
    /// <inheritdoc />
    public IBlockCipherPadding Create(PaddingScheme scheme) => scheme switch
    {
        PaddingScheme.Pkcs7 => new Pkcs7Padding(),
        PaddingScheme.Iso7816 => new ISO7816d4Padding(),
        PaddingScheme.Iso10126 => InitIso10126(),
        PaddingScheme.X923 => new X923Padding(),
        _ => throw new ArgumentException($"Unsupported padding scheme {scheme}", nameof(scheme)),
    };

    private static IBlockCipherPadding InitIso10126()
    {
        var padding = new ISO10126d2Padding();
        padding.Init(new SecureRandom());
        return padding;
    }
}
