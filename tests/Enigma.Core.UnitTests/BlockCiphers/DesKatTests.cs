using System.Collections.Generic;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>DES known-answer tests for CBC, ECB and CTR (64-bit block) against the ported vectors.</summary>
public class DesKatTests
{
    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateDesService();

    [Theory]
    [MemberData(nameof(CbcVectors))]
    public Task Cbc_Encrypt(byte[] key, byte[] iv, byte[] data, byte[] enc)
        => BlockCipherKat.AssertEncrypt(Service(), key, iv, BlockCipherMode.Cbc, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(CbcVectors))]
    public Task Cbc_Decrypt(byte[] key, byte[] iv, byte[] data, byte[] enc)
        => BlockCipherKat.AssertDecrypt(Service(), key, iv, BlockCipherMode.Cbc, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(EcbVectors))]
    public Task Ecb_Encrypt(byte[] key, byte[] data, byte[] enc)
        => BlockCipherKat.AssertEncrypt(Service(), key, null, BlockCipherMode.Ecb, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(EcbVectors))]
    public Task Ecb_Decrypt(byte[] key, byte[] data, byte[] enc)
        => BlockCipherKat.AssertDecrypt(Service(), key, null, BlockCipherMode.Ecb, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(CtrVectors))]
    public Task Ctr_Encrypt(byte[] key, byte[] iv, byte[] data, byte[] enc)
        => BlockCipherKat.AssertEncrypt(Service(), key, iv, BlockCipherMode.Ctr, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(CtrVectors))]
    public Task Ctr_Decrypt(byte[] key, byte[] iv, byte[] data, byte[] enc)
        => BlockCipherKat.AssertDecrypt(Service(), key, iv, BlockCipherMode.Ctr, data, enc, TestContext.Current.CancellationToken);

    public static IEnumerable<object[]> CbcVectors() => BlockCipherKat.IvVectors("des-cbc.csv");
    public static IEnumerable<object[]> EcbVectors() => BlockCipherKat.EcbVectors("des-ecb.csv");
    public static IEnumerable<object[]> CtrVectors() => BlockCipherKat.IvVectors("des-ctr.csv");
}
