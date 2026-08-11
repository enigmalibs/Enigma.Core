namespace Enigma.Core.Checksum;

/// <summary>
/// One CRC variant's parameter set, in the canonical catalogue form (width, polynomial, initial
/// register value, reflection, final XOR). Internal: the parameter sets are an implementation
/// detail, selected on the caller's behalf by <see cref="ChecksumServiceFactory"/>.
/// </summary>
/// <remarks>
/// <see cref="Polynomial"/> is stored in the form the table generator consumes — the <b>reflected</b>
/// polynomial for reflected variants, the <b>normal</b> (MSB-first) polynomial otherwise — so
/// <see cref="CrcTable"/> never has to reflect it. Adding a variant is one static field here plus one
/// factory method; nothing else changes.
/// </remarks>
internal sealed class CrcParameters
{
    private CrcParameters(string name, int width, uint polynomial, uint init, bool reflected, uint xorOut)
    {
        Name = name;
        Width = width;
        Polynomial = polynomial;
        Init = init;
        Reflected = reflected;
        XorOut = xorOut;
    }

    /// <summary>The variant's catalogue name, used in diagnostic text.</summary>
    internal string Name { get; }

    /// <summary>The register width in bits: 16 or 32.</summary>
    internal int Width { get; }

    /// <summary>
    /// The generator polynomial, already in the form the table generator wants: reflected (LSB-first)
    /// when <see cref="Reflected"/> is <see langword="true"/>, normal (MSB-first) otherwise.
    /// </summary>
    internal uint Polynomial { get; }

    /// <summary>The initial register value.</summary>
    internal uint Init { get; }

    /// <summary>Whether input bytes and the output register are bit-reflected (refin == refout).</summary>
    internal bool Reflected { get; }

    /// <summary>The value XOR-ed into the register at finalisation.</summary>
    internal uint XorOut { get; }

    /// <summary>CRC-16/ARC — also known as CRC-16, CRC-IBM, CRC-16/LHA, CRC-16/ZMODEM. Check 0xBB3D.</summary>
    internal static readonly CrcParameters Crc16Arc =
        new("CRC-16/ARC", 16, 0xA001u, 0x0000u, reflected: true, 0x0000u);

    /// <summary>CRC-16/IBM-3740 — commonly published as "CRC-16/CCITT-FALSE". Check 0x29B1.</summary>
    internal static readonly CrcParameters Crc16CcittFalse =
        new("CRC-16/IBM-3740", 16, 0x1021u, 0xFFFFu, reflected: false, 0x0000u);

    /// <summary>CRC-16/XMODEM — also known as CRC-16/ZMODEM, CRC-16/ACORN. Check 0x31C3.</summary>
    internal static readonly CrcParameters Crc16Xmodem =
        new("CRC-16/XMODEM", 16, 0x1021u, 0x0000u, reflected: false, 0x0000u);

    /// <summary>CRC-16/MODBUS — the Modbus serial-line frame check. Check 0x4B37.</summary>
    internal static readonly CrcParameters Crc16Modbus =
        new("CRC-16/MODBUS", 16, 0xA001u, 0xFFFFu, reflected: true, 0x0000u);

    /// <summary>CRC-16/KERMIT — also known as CRC-16/CCITT, CRC-16/CCITT-TRUE, CRC-16/V-41-LSB. Check 0x2189.</summary>
    internal static readonly CrcParameters Crc16Kermit =
        new("CRC-16/KERMIT", 16, 0x8408u, 0x0000u, reflected: true, 0x0000u);

    /// <summary>CRC-32/ISO-HDLC — the zip/gzip/PNG/Ethernet CRC-32. Check 0xCBF43926.</summary>
    internal static readonly CrcParameters Crc32IsoHdlc =
        new("CRC-32/ISO-HDLC", 32, 0xEDB88320u, 0xFFFFFFFFu, reflected: true, 0xFFFFFFFFu);

    /// <summary>CRC-32C (Castagnoli) — iSCSI, SCTP, ext4 metadata. Check 0xE3069283.</summary>
    internal static readonly CrcParameters Crc32C =
        new("CRC-32C", 32, 0x82F63B78u, 0xFFFFFFFFu, reflected: true, 0xFFFFFFFFu);
}
