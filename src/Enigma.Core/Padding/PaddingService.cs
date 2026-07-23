using System;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Padding;

/// <summary>
/// Provides padding and unpadding functionality for block cipher operations, following a configured
/// <see cref="PaddingScheme"/>.
/// </summary>
/// <remarks>
/// Instances are created by <see cref="PaddingServiceFactory"/> only; the scheme is chosen there. The
/// underlying padding implementation is wired internally, so no BouncyCastle type appears on the
/// public surface.
/// </remarks>
public sealed class PaddingService : IPaddingService
{
    private readonly PaddingScheme _scheme;

    // Internal so only the factory (same assembly) can construct a service; the PaddingScheme -> BC
    // padding mapping (and any BouncyCastle type it touches) never becomes part of the public API
    // surface (principle 1 — BouncyCastle stays hidden).
    internal PaddingService(PaddingScheme scheme) => _scheme = scheme;

    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (blockSize is < 1 or > byte.MaxValue)
            throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

        var paddingLength = blockSize - data.Length % blockSize;
        var paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, paddedData, 0, data.Length);

        var padder = CreatePadding();
        padder.AddPadding(paddedData, data.Length);

        return paddedData;
    }

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (blockSize is < 1 or > byte.MaxValue)
            throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));
        if (data.Length % blockSize != 0 || data.Length < blockSize)
            throw new ArgumentException($"Invalid padded data length {data.Length}");

        var padder = CreatePadding();
        var paddingLength = padder.PadCount(data);

        var unpaddedData = new byte[data.Length - paddingLength];
        Array.Copy(data, 0, unpaddedData, 0, data.Length - paddingLength);

        return unpaddedData;
    }

    // Internal seam: translate the BouncyCastle-free PaddingScheme into the concrete BouncyCastle
    // padder. ISO 10126-2 draws its filler bytes from a secure random source, so it must be seeded
    // before AddPadding is called; X9.23 is left with no random source so it zero-fills (matching the
    // ported x923 known-answer vectors). PKCS#7 and ISO 7816-4 are deterministic and need no seeding.
    private IBlockCipherPadding CreatePadding() => _scheme switch
    {
        PaddingScheme.Pkcs7 => new Pkcs7Padding(),
        PaddingScheme.Iso7816 => new ISO7816d4Padding(),
        PaddingScheme.Iso10126 => InitIso10126(),
        PaddingScheme.X923 => new X923Padding(),
        _ => throw new ArgumentException($"Unsupported padding scheme {_scheme}", nameof(_scheme)),
    };

    private static IBlockCipherPadding InitIso10126()
    {
        var padding = new ISO10126d2Padding();
        padding.Init(new SecureRandom());
        return padding;
    }
}
