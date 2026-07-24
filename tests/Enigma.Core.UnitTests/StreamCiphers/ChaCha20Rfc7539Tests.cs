using System.Collections.Generic;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.StreamCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.StreamCiphers;

/// <summary>ChaCha20-RFC7539 (96-bit nonce, 32-bit counter) known-answer tests against the ported vectors.</summary>
public class ChaCha20Rfc7539Tests
{
    private static IStreamCipherService Service() => new StreamCipherServiceFactory().CreateChaCha7539Service();

    [Theory]
    [MemberData(nameof(Vectors))]
    public Task Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] enc)
        => StreamCipherKat.AssertEncrypt(Service(), key, nonce, data, enc, TestContext.Current.CancellationToken);

    [Theory]
    [MemberData(nameof(Vectors))]
    public Task Decrypt(byte[] key, byte[] nonce, byte[] data, byte[] enc)
        => StreamCipherKat.AssertDecrypt(Service(), key, nonce, data, enc, TestContext.Current.CancellationToken);

    public static IEnumerable<object[]> Vectors() => StreamCipherKat.Vectors("chacha20rfc7539.csv");
}
