using System;
using System.Collections.Generic;
using Enigma.Core.Checksum;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// An independent, test-only CRC reference implementation: bit-by-bit (eight shifts per input byte),
/// with <b>no lookup table</b>, taking the <b>normal</b> (MSB-first) polynomial and reflecting input
/// bytes and the output register explicitly.
/// </summary>
/// <remarks>
/// It is deliberately not shaped like the product engine. The product code folds a byte at a time
/// through a table built from the <i>reflected</i> polynomial; this one shifts a bit at a time through
/// the normal polynomial. A wrong table, or a reflection applied in the wrong place in
/// <c>CrcTable</c>, therefore cannot be mirrored here — the two implementations can only agree by
/// both being right. <c>ChecksumFuzzTests</c> additionally pins the oracle itself against the seven
/// published check values, so a broken oracle cannot silently bless a broken engine.
/// </remarks>
internal sealed class BitwiseCrcOracle
{
    private readonly int _width;
    private readonly uint _polynomial;
    private readonly uint _init;
    private readonly bool _reflectIn;
    private readonly bool _reflectOut;
    private readonly uint _xorOut;

    private BitwiseCrcOracle(int width, uint polynomial, uint init, bool reflectIn, bool reflectOut, uint xorOut)
    {
        _width = width;
        _polynomial = polynomial;
        _init = init;
        _reflectIn = reflectIn;
        _reflectOut = reflectOut;
        _xorOut = xorOut;
    }

    /// <summary>Computes the CRC of <paramref name="data"/> from the catalogue parameters.</summary>
    internal uint Compute(byte[] data)
    {
        var mask = _width == 32 ? uint.MaxValue : (1u << _width) - 1u;
        var topBit = 1u << (_width - 1);

        var register = _init & mask;

        foreach (var b in data)
        {
            var value = _reflectIn ? Reflect(b, 8) : b;
            register ^= (value << (_width - 8)) & mask;

            for (var bit = 0; bit < 8; bit++)
                register = (register & topBit) != 0u
                    ? ((register << 1) ^ _polynomial) & mask
                    : (register << 1) & mask;
        }

        if (_reflectOut)
            register = Reflect(register, _width);

        return (register ^ _xorOut) & mask;
    }

    private static uint Reflect(uint value, int width)
    {
        var reflected = 0u;
        for (var bit = 0; bit < width; bit++)
            if ((value & (1u << bit)) != 0u)
                reflected |= 1u << (width - 1 - bit);
        return reflected;
    }

    // The catalogue parameters, in normal (unreflected) polynomial form — the published shape, not
    // the shape CrcParameters stores. Transcribed from the CRC catalogue, not from the product code.
    private static readonly Dictionary<string, BitwiseCrcOracle> Oracles = new()
    {
        [ChecksumVariants.Crc16Arc] = new(16, 0x8005u, 0x0000u, true, true, 0x0000u),
        [ChecksumVariants.Crc16CcittFalse] = new(16, 0x1021u, 0xFFFFu, false, false, 0x0000u),
        [ChecksumVariants.Crc16Xmodem] = new(16, 0x1021u, 0x0000u, false, false, 0x0000u),
        [ChecksumVariants.Crc16Modbus] = new(16, 0x8005u, 0xFFFFu, true, true, 0x0000u),
        [ChecksumVariants.Crc16Kermit] = new(16, 0x1021u, 0x0000u, true, true, 0x0000u),
        [ChecksumVariants.Crc32IsoHdlc] = new(32, 0x04C11DB7u, 0xFFFFFFFFu, true, true, 0xFFFFFFFFu),
        [ChecksumVariants.Crc32C] = new(32, 0x1EDC6F41u, 0xFFFFFFFFu, true, true, 0xFFFFFFFFu),
    };

    /// <summary>Gets the oracle for a variant key from <see cref="ChecksumVariants"/>.</summary>
    internal static BitwiseCrcOracle For(string variant) => Oracles[variant];
}

/// <summary>
/// The seven shipped variants as string keys, so a <c>[Theory]</c> can name one in an
/// <c>[InlineData]</c>, together with the factory call and the published check value that go with it.
/// Lives beside the oracle because every table-driven test needs both halves of the pair.
/// </summary>
internal static class ChecksumVariants
{
    internal const string Crc16Arc = "CRC-16/ARC";
    internal const string Crc16CcittFalse = "CRC-16/CCITT-FALSE";
    internal const string Crc16Xmodem = "CRC-16/XMODEM";
    internal const string Crc16Modbus = "CRC-16/MODBUS";
    internal const string Crc16Kermit = "CRC-16/KERMIT";
    internal const string Crc32IsoHdlc = "CRC-32/ISO-HDLC";
    internal const string Crc32C = "CRC-32C";

    /// <summary>Every variant key, in the order the factory declares them.</summary>
    internal static readonly string[] All =
    [
        Crc16Arc, Crc16CcittFalse, Crc16Xmodem, Crc16Modbus, Crc16Kermit, Crc32IsoHdlc, Crc32C,
    ];

    /// <summary>The published check value of each variant over the ASCII bytes of "123456789".</summary>
    private static readonly Dictionary<string, uint> CheckValues = new()
    {
        [Crc16Arc] = 0xBB3Du,
        [Crc16CcittFalse] = 0x29B1u,
        [Crc16Xmodem] = 0x31C3u,
        [Crc16Modbus] = 0x4B37u,
        [Crc16Kermit] = 0x2189u,
        [Crc32IsoHdlc] = 0xCBF43926u,
        [Crc32C] = 0xE3069283u,
    };

    /// <summary>The catalogue check value for a variant.</summary>
    internal static uint CheckValue(string variant) => CheckValues[variant];

    /// <summary>The ASCII bytes of "123456789" — the catalogue's check-value input.</summary>
    internal static byte[] CheckInput() => "123456789"u8.ToArray();

    /// <summary>Creates the library service for a variant key.</summary>
    internal static IChecksumService Create(string variant, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        var factory = new ChecksumServiceFactory();
        return variant switch
        {
            Crc16Arc => factory.CreateCrc16ArcService(bufferSize),
            Crc16CcittFalse => factory.CreateCrc16CcittFalseService(bufferSize),
            Crc16Xmodem => factory.CreateCrc16XmodemService(bufferSize),
            Crc16Modbus => factory.CreateCrc16ModbusService(bufferSize),
            Crc16Kermit => factory.CreateCrc16KermitService(bufferSize),
            Crc32IsoHdlc => factory.CreateCrc32IsoHdlcService(bufferSize),
            Crc32C => factory.CreateCrc32CService(bufferSize),
            _ => throw new ArgumentOutOfRangeException(nameof(variant), variant, "Unknown CRC variant."),
        };
    }
}
