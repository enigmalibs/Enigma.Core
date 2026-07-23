namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Default <see cref="IBlockCipherServiceFactory"/> implementation. Selects the underlying algorithm by
/// binding the matching engine constructor into a <see cref="BlockCipherService"/>; the mode of
/// operation, key, IV/nonce, padding and GCM tag size are supplied per call on the returned service.
/// </summary>
public sealed class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    private readonly IBlockCipherEngineFactory _engineFactory = new BlockCipherEngineFactory();

    /// <inheritdoc />
    public IBlockCipherService CreateAesService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateAesEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateDesService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateDesEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateTripleDesService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateTripleDesEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateBlowfishService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateBlowfishEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateTwofishService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateTwofishEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateSerpentService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateSerpentEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCamelliaService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateCamelliaEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCast128Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateCast128Engine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateIdeaService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateIdeaEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateSeedService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateSeedEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateAriaService(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateAriaEngine, bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateSm4Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new BlockCipherService(_engineFactory.CreateSm4Engine, bufferSize);
}
