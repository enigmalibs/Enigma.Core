using Org.BouncyCastle.Crypto;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Internal factory that creates the raw block cipher engines backing each supported algorithm. Kept
/// internal so the BouncyCastle <see cref="IBlockCipher"/> engine type never reaches the public
/// surface (principle 1); the public <see cref="IBlockCipherServiceFactory"/> binds one of these engine
/// constructors into each <see cref="BlockCipherService"/>.
/// </summary>
internal interface IBlockCipherEngineFactory
{
    /// <summary>Creates an AES engine (128-bit block).</summary>
    IBlockCipher CreateAesEngine();

    /// <summary>Creates a DES engine (64-bit block).</summary>
    IBlockCipher CreateDesEngine();

    /// <summary>Creates a Triple DES (DESede) engine (64-bit block).</summary>
    IBlockCipher CreateTripleDesEngine();

    /// <summary>Creates a Blowfish engine (64-bit block).</summary>
    IBlockCipher CreateBlowfishEngine();

    /// <summary>Creates a Twofish engine (128-bit block).</summary>
    IBlockCipher CreateTwofishEngine();

    /// <summary>Creates a Serpent engine (128-bit block).</summary>
    IBlockCipher CreateSerpentEngine();

    /// <summary>Creates a Camellia engine (128-bit block).</summary>
    IBlockCipher CreateCamelliaEngine();

    /// <summary>Creates a CAST-128 (CAST5) engine (64-bit block).</summary>
    IBlockCipher CreateCast128Engine();

    /// <summary>Creates an IDEA engine (64-bit block).</summary>
    IBlockCipher CreateIdeaEngine();

    /// <summary>Creates a SEED engine (128-bit block).</summary>
    IBlockCipher CreateSeedEngine();

    /// <summary>Creates an ARIA engine (128-bit block).</summary>
    IBlockCipher CreateAriaEngine();

    /// <summary>Creates an SM4 engine (128-bit block).</summary>
    IBlockCipher CreateSm4Engine();
}
