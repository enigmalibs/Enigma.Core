namespace Enigma.Core.Checksum;

/// <summary>
/// Default <see cref="IChecksumServiceFactory"/> implementation. Selects the CRC variant and hands a
/// configured <see cref="Crc16Service"/> or <see cref="Crc32Service"/> back as an
/// <see cref="IChecksumService"/>. Each call returns a fresh service instance.
/// </summary>
public sealed class ChecksumServiceFactory : IChecksumServiceFactory
{
    /// <inheritdoc />
    public IChecksumService CreateCrc16ArcService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc16Service(CrcParameters.Crc16Arc, bufferSize);

    /// <inheritdoc />
    public IChecksumService CreateCrc16CcittFalseService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc16Service(CrcParameters.Crc16CcittFalse, bufferSize);

    /// <inheritdoc />
    public IChecksumService CreateCrc16XmodemService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc16Service(CrcParameters.Crc16Xmodem, bufferSize);

    /// <inheritdoc />
    public IChecksumService CreateCrc16ModbusService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc16Service(CrcParameters.Crc16Modbus, bufferSize);

    /// <inheritdoc />
    public IChecksumService CreateCrc16KermitService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc16Service(CrcParameters.Crc16Kermit, bufferSize);

    /// <inheritdoc />
    public IChecksumService CreateCrc32IsoHdlcService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc32Service(CrcParameters.Crc32IsoHdlc, bufferSize);

    /// <inheritdoc />
    public IChecksumService CreateCrc32CService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new Crc32Service(CrcParameters.Crc32C, bufferSize);
}
