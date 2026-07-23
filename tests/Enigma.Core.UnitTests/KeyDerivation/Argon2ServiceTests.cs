using System;
using System.Collections.Generic;
using Enigma.Core.KeyDerivation;
using Xunit;

namespace Enigma.Core.UnitTests.KeyDerivation;

public class Argon2ServiceTests
{
    // Argon2id vectors ported from the source suite. The old memoryPowOfTwo=5 becomes an absolute
    // memorySizeKb=32 (2^5 KiB); WithMemoryAsKB(32) must reproduce WithMemoryPowOfTwo(5), so matching
    // these vectors proves the KiB mapping is correct.
    [Theory]
    [MemberData(nameof(GetVectors))]
    public void DeriveKey_KnownVector_MatchesExpected(byte[] password, byte[] salt, byte[] expectedKey)
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();

        var key = service.DeriveKey(
            password,
            salt,
            iterations: 3,
            memorySizeKb: 32,
            degreeOfParallelism: 4,
            keySizeBytes: 32,
            Argon2Variant.Argon2id,
            Argon2Version.Version13);

        Assert.Equal(expectedKey, key);
    }

    public static IEnumerable<object[]> GetVectors()
    {
        // 32-byte password (all 0x01), 16-byte salt (all 0x02).
        yield return new object[]
        {
            Convert.FromHexString("0101010101010101010101010101010101010101010101010101010101010101"),
            Convert.FromHexString("02020202020202020202020202020202"),
            Convert.FromHexString("03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e"),
        };
        // Empty password, 16-byte salt (all 0x02).
        yield return new object[]
        {
            Array.Empty<byte>(),
            Convert.FromHexString("02020202020202020202020202020202"),
            Convert.FromHexString("0a34f1abde67086c82e785eaf17c68382259a264f4e61b91cd2763cb75ac189a"),
        };
    }

    // Version10 and Version13 must map to distinct BouncyCastle version constants (0x10 vs 0x13), not
    // a raw (int) cast of the enum ordinals (0 vs 1). If the mapping were a cast, both would request
    // invalid versions; with the explicit map, the two produce valid but different output.
    [Fact]
    public void DeriveKey_DifferentVersions_ProduceDifferentKeys()
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var password = Convert.FromHexString("0101010101010101010101010101010101010101010101010101010101010101");
        var salt = Convert.FromHexString("02020202020202020202020202020202");

        var v10 = service.DeriveKey(password, salt, 3, 32, 4, 32, Argon2Variant.Argon2id, Argon2Version.Version10);
        var v13 = service.DeriveKey(password, salt, 3, 32, 4, 32, Argon2Variant.Argon2id, Argon2Version.Version13);

        Assert.NotEqual(v10, v13);
    }

    // The caller owns the password array: DeriveKey must not mutate or clear it.
    [Fact]
    public void DeriveKey_DoesNotMutatePassword()
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var password = Convert.FromHexString("0101010101010101010101010101010101010101010101010101010101010101");
        var original = (byte[])password.Clone();

        service.DeriveKey(password, new byte[16], 3, 32, 4, 32);

        Assert.Equal(original, password);
    }

    [Fact]
    public void DeriveKey_NullPassword_Throws()
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var ex = Assert.Throws<ArgumentNullException>(
            () => service.DeriveKey(null!, new byte[16], 3, 32, 4, 32));
        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    public void DeriveKey_NullSalt_Throws()
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var ex = Assert.Throws<ArgumentNullException>(
            () => service.DeriveKey(new byte[8], null!, 3, 32, 4, 32));
        Assert.Equal("salt", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveIterations_Throws(int iterations)
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var ex = Assert.Throws<ArgumentException>(
            () => service.DeriveKey(new byte[8], new byte[16], iterations, 32, 4, 32));
        Assert.Equal("iterations", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveMemory_Throws(int memorySizeKb)
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var ex = Assert.Throws<ArgumentException>(
            () => service.DeriveKey(new byte[8], new byte[16], 3, memorySizeKb, 4, 32));
        Assert.Equal("memorySizeKb", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveParallelism_Throws(int degreeOfParallelism)
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var ex = Assert.Throws<ArgumentException>(
            () => service.DeriveKey(new byte[8], new byte[16], 3, 32, degreeOfParallelism, 32));
        Assert.Equal("degreeOfParallelism", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveKeySize_Throws(int keySizeBytes)
    {
        var service = new Argon2ServiceFactory().CreateArgon2Service();
        var ex = Assert.Throws<ArgumentException>(
            () => service.DeriveKey(new byte[8], new byte[16], 3, 32, 4, keySizeBytes));
        Assert.Equal("keySizeBytes", ex.ParamName);
    }
}
