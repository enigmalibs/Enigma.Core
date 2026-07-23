using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Default <see cref="IBlockCipherEngineFactory"/> implementation. Each method returns a fresh
/// BouncyCastle engine instance; CAST-128 maps to BouncyCastle's <see cref="Cast5Engine"/> and
/// Triple DES to <see cref="DesEdeEngine"/>.
/// </summary>
internal sealed class BlockCipherEngineFactory : IBlockCipherEngineFactory
{
    /// <inheritdoc />
    public IBlockCipher CreateAesEngine() => new AesEngine();

    /// <inheritdoc />
    public IBlockCipher CreateDesEngine() => new DesEngine();

    /// <inheritdoc />
    public IBlockCipher CreateTripleDesEngine() => new DesEdeEngine();

    /// <inheritdoc />
    public IBlockCipher CreateBlowfishEngine() => new BlowfishEngine();

    /// <inheritdoc />
    public IBlockCipher CreateTwofishEngine() => new TwofishEngine();

    /// <inheritdoc />
    public IBlockCipher CreateSerpentEngine() => new SerpentEngine();

    /// <inheritdoc />
    public IBlockCipher CreateCamelliaEngine() => new CamelliaEngine();

    /// <inheritdoc />
    public IBlockCipher CreateCast128Engine() => new Cast5Engine();

    /// <inheritdoc />
    public IBlockCipher CreateIdeaEngine() => new IdeaEngine();

    /// <inheritdoc />
    public IBlockCipher CreateSeedEngine() => new SeedEngine();

    /// <inheritdoc />
    public IBlockCipher CreateAriaEngine() => new AriaEngine();

    /// <inheritdoc />
    public IBlockCipher CreateSm4Engine() => new SM4Engine();
}
