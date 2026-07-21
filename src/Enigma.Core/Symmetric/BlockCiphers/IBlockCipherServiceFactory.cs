namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Factory for creating <see cref="IBlockCipherService"/> instances, one per block cipher algorithm.
/// The mode of operation, key, IV/nonce and padding are supplied per call on the returned service; the
/// factory selects only the underlying algorithm.
/// </summary>
/// <remarks>
/// Block ciphers encrypt fixed-size blocks of data (typically 64 or 128 bits). The chosen
/// <see cref="BlockCipherMode"/> determines how those blocks are chained and whether an IV/nonce and
/// padding are required.
/// </remarks>
public interface IBlockCipherServiceFactory
{
    /// <summary>Creates a block cipher service for the AES algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateAesService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the DES algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateDesService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the Triple DES (3DES / DESede) algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateTripleDesService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the Blowfish algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateBlowfishService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the Twofish algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateTwofishService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the Serpent algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateSerpentService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the Camellia algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateCamelliaService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the CAST-128 (CAST5) algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateCast128Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the IDEA algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateIdeaService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the SEED algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateSeedService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the ARIA algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateAriaService(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a block cipher service for the SM4 algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service.</returns>
    IBlockCipherService CreateSm4Service(int bufferSize = CryptoDefaults.StreamBufferSize);
}
