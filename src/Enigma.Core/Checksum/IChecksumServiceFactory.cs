namespace Enigma.Core.Checksum;

/// <summary>
/// Factory for creating <see cref="IChecksumService"/> instances, one per supported CRC variant.
/// </summary>
/// <remarks>
/// <para>
/// Every method names its variant explicitly — there is deliberately no <c>CreateCrc16Service</c> or
/// <c>CreateCrc32Service</c>. "CRC-16" and "CRC-32" each name a family of mutually incompatible
/// parameter sets, so a bare method would have to bind silently to one of them and produce a value
/// the caller's counterpart cannot verify. The familiar aliases are documented on each method.
/// </para>
/// <para>
/// The factory selects only the variant; the data to checksum is supplied per call on the returned
/// service. See <see cref="IChecksumService"/> for why a CRC is never a substitute for a
/// cryptographic integrity check.
/// </para>
/// </remarks>
public interface IChecksumServiceFactory
{
    /// <summary>
    /// Creates a checksum service for <b>CRC-16/ARC</b> — polynomial 0x8005 reflected, init 0x0000,
    /// no final XOR. Also published as CRC-16, CRC-IBM, CRC-16/LHA and CRC-16/ZMODEM. Check value
    /// (over <c>"123456789"</c>): <c>0xBB3D</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 2-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc16ArcService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a checksum service for <b>CRC-16/IBM-3740</b> — polynomial 0x1021, init 0xFFFF, not
    /// reflected, no final XOR. Widely published under the name "CRC-16/CCITT-FALSE". Check value
    /// (over <c>"123456789"</c>): <c>0x29B1</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 2-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc16CcittFalseService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a checksum service for <b>CRC-16/XMODEM</b> — polynomial 0x1021, init 0x0000, not
    /// reflected, no final XOR. Also published as CRC-16/ZMODEM and CRC-16/ACORN. Check value (over
    /// <c>"123456789"</c>): <c>0x31C3</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 2-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc16XmodemService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a checksum service for <b>CRC-16/MODBUS</b> — polynomial 0x8005 reflected, init
    /// 0xFFFF, no final XOR. The Modbus serial-line frame check. Check value (over
    /// <c>"123456789"</c>): <c>0x4B37</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 2-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc16ModbusService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a checksum service for <b>CRC-16/KERMIT</b> — polynomial 0x1021 reflected, init
    /// 0x0000, no final XOR. Also published as CRC-16/CCITT, CRC-16/CCITT-TRUE and CRC-16/V-41-LSB.
    /// Check value (over <c>"123456789"</c>): <c>0x2189</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 2-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc16KermitService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a checksum service for <b>CRC-32/ISO-HDLC</b> — polynomial 0x04C11DB7 reflected, init
    /// 0xFFFFFFFF, final XOR 0xFFFFFFFF. This is the CRC-32 used by zip, gzip, PNG and Ethernet, and
    /// the one meant by an unqualified "CRC-32". Check value (over <c>"123456789"</c>):
    /// <c>0xCBF43926</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 4-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc32IsoHdlcService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a checksum service for <b>CRC-32C</b> (Castagnoli) — polynomial 0x1EDC6F41 reflected,
    /// init 0xFFFFFFFF, final XOR 0xFFFFFFFF. Used by iSCSI, SCTP and ext4 metadata; incompatible
    /// with CRC-32/ISO-HDLC. Check value (over <c>"123456789"</c>): <c>0xE3069283</c>.
    /// </summary>
    /// <param name="bufferSize">Size of the internal stream-read buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured checksum service producing a 4-byte checksum.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="bufferSize"/> is not positive.</exception>
    IChecksumService CreateCrc32CService(int bufferSize = CryptoDefaults.StreamBufferSize);
}
