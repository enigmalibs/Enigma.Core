using System;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// A factory for creating block cipher services, one per supported algorithm.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    /// <inheritdoc />
    public IBlockCipherService CreateAesService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateDesService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateTripleDesService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateBlowfishService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateTwofishService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateSerpentService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateCamelliaService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateCast128Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateIdeaService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateSeedService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateAriaService(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IBlockCipherService CreateSm4Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();
}
