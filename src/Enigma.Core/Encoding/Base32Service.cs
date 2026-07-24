using System;
using System.Collections.Generic;
using System.Text;

namespace Enigma.Core.Encoding;

/// <summary>
/// Encodes and decodes binary data using Base32 (RFC 4648).
/// <see cref="Encode"/> produces canonical, padded output; <see cref="Decode"/> is tolerant of
/// letter case, embedded whitespace, and missing padding (the conventions used by authenticator
/// apps when exchanging shared secrets).
/// </summary>
public sealed class Base32Service : IEncodingService
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const char PaddingChar = '=';

    private static readonly int[] ReverseLookup = BuildReverseLookup();

    private static int[] BuildReverseLookup()
    {
        var table = new int[128];
        for (var i = 0; i < table.Length; i++)
            table[i] = -1;
        for (var i = 0; i < Alphabet.Length; i++)
        {
            var c = Alphabet[i];
            table[c] = i;
            table[char.ToLowerInvariant(c)] = i;
        }
        return table;
    }

    /// <inheritdoc />
    public string Encode(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (data.Length == 0) return string.Empty;

        // 5 input bytes (40 bits) map to 8 Base32 characters.
        var sb = new StringBuilder((data.Length + 4) / 5 * 8);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(Alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }

        if (bitsLeft > 0)
            sb.Append(Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);

        while (sb.Length % 8 != 0)
            sb.Append(PaddingChar);

        return sb.ToString();
    }

    /// <inheritdoc />
    public byte[] Decode(string encoded)
    {
        if (encoded is null) throw new ArgumentNullException(nameof(encoded));

        var output = new List<byte>(encoded.Length * 5 / 8 + 1);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var c in encoded)
        {
            if (c == PaddingChar || char.IsWhiteSpace(c))
                continue;
            if (c >= ReverseLookup.Length || ReverseLookup[c] < 0)
                throw new FormatException($"Invalid Base32 character '{c}'.");

            buffer = (buffer << 5) | ReverseLookup[c];
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }

        return output.ToArray();
    }
}
