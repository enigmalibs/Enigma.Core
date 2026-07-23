using System.Collections.Generic;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.StreamCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.StreamCiphers;

/// <summary>Salsa20 (64-bit nonce) known-answer tests against the ported vectors.</summary>
public class Salsa20Tests
{
    private static IStreamCipherService Service() => new StreamCipherServiceFactory().CreateSalsa20Service();

    [Theory]
    [MemberData(nameof(Vectors))]
    public Task Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] enc)
        => StreamCipherKat.AssertEncrypt(Service(), key, nonce, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(Vectors))]
    public Task Decrypt(byte[] key, byte[] nonce, byte[] data, byte[] enc)
        => StreamCipherKat.AssertDecrypt(Service(), key, nonce, data, enc, TestContext.Current.CancellationToken);

    public static IEnumerable<object[]> Vectors() => StreamCipherKat.Vectors("salsa20.csv");
}
