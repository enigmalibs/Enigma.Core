using System;
using System.Collections.Generic;
using System.Linq;
using Enigma.Core.KeyDerivation;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.KeyDerivation;

public class Pbkdf2ServiceTests
{
    // The sibling namespace Enigma.Core.UnitTests.Encoding shadows the simple name System.Text.Encoding
    // in this namespace, so encode through a global::-qualified helper.
    private static byte[] Utf8(string value) => global::System.Text.Encoding.UTF8.GetBytes(value);

    // The CSV vectors were generated under the old default PRF (HMAC-SHA1) at 50,000 iterations for a
    // 32-byte key, with the column-0 value used as an ASCII password (UTF-8-encoded to bytes). The
    // default PRF is now HMAC-SHA256, so HmacSha1 must be passed explicitly to reproduce them.
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void DeriveKey_KnownVector_MatchesExpected(byte[] password, byte[] salt, byte[] expectedKey)
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();

        var key = service.DeriveKey(password, salt, iterations: 50_000, keySizeBytes: 32, Pbkdf2Prf.HmacSha1);

        Assert.Equal(expectedKey, key);
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("KeyDerivation", "pbkdf2.csv")
            .Select(v => new object[]
            {
                Utf8(v[0]),        // password: column-0 ASCII string, UTF-8-encoded
                CsvData.Hex(v[1]), // salt
                CsvData.Hex(v[2]), // expected key
            });

    // Canonical PBKDF2-HMAC-SHA256 vectors (password="password", salt="salt", dkLen=32) — RFC 8018.
    [Theory]
    [InlineData(1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")]
    [InlineData(2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")]
    [InlineData(4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")]
    public void DeriveKey_HmacSha256_MatchesKnownVectors(int iterations, string expectedHex)
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();

        var key = service.DeriveKey(
            Utf8("password"),
            Utf8("salt"),
            iterations,
            keySizeBytes: 32,
            Pbkdf2Prf.HmacSha256);

        Assert.Equal(Convert.FromHexString(expectedHex), key);
    }

    // The default PRF is HMAC-SHA256: a default call must equal an explicit HmacSha256 call.
    [Fact]
    public void DeriveKey_DefaultPrf_EqualsExplicitHmacSha256()
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var password = Utf8("password");
        var salt = Utf8("salt");

        var withDefault = service.DeriveKey(password, salt, iterations: 10_000, keySizeBytes: 32);
        var withSha256 = service.DeriveKey(password, salt, iterations: 10_000, keySizeBytes: 32, Pbkdf2Prf.HmacSha256);

        Assert.Equal(withSha256, withDefault);
    }

    // Each PRF is wired to a distinct digest (including the restored HmacSha384), so the same inputs
    // yield four distinct keys.
    [Fact]
    public void DeriveKey_DifferentPrfs_ProduceDifferentKeys()
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var password = Utf8("password");
        var salt = Utf8("salt");
        var prfs = new[] { Pbkdf2Prf.HmacSha1, Pbkdf2Prf.HmacSha256, Pbkdf2Prf.HmacSha384, Pbkdf2Prf.HmacSha512 };

        var keys = prfs
            .Select(prf => Convert.ToHexString(service.DeriveKey(password, salt, iterations: 1_000, keySizeBytes: 32, prf)))
            .ToList();

        Assert.Equal(prfs.Length, keys.Distinct().Count());
    }

    // PBKDF2-HMAC-SHA384 (the restored PRF) must derive a correct, non-empty key of the requested size.
    [Fact]
    public void DeriveKey_HmacSha384_ProducesRequestedLengthKey()
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();

        var key = service.DeriveKey(
            Utf8("password"),
            Utf8("salt"),
            iterations: 1_000,
            keySizeBytes: 48,
            Pbkdf2Prf.HmacSha384);

        Assert.Equal(48, key.Length);
        Assert.NotEqual(new byte[48], key);
    }

    // The caller owns the password array: DeriveKey must not mutate or clear it.
    [Fact]
    public void DeriveKey_DoesNotMutatePassword()
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var password = Utf8("password");
        var original = (byte[])password.Clone();

        service.DeriveKey(password, Utf8("salt"), iterations: 1_000, keySizeBytes: 32);

        Assert.Equal(original, password);
    }

    [Fact]
    public void DeriveKey_NullPassword_Throws()
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var ex = Assert.Throws<ArgumentNullException>(
            () => service.DeriveKey(null!, new byte[16], iterations: 1_000, keySizeBytes: 32));
        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    public void DeriveKey_NullSalt_Throws()
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var ex = Assert.Throws<ArgumentNullException>(
            () => service.DeriveKey(new byte[8], null!, iterations: 1_000, keySizeBytes: 32));
        Assert.Equal("salt", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveIterations_Throws(int iterations)
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var ex = Assert.Throws<ArgumentException>(
            () => service.DeriveKey(new byte[8], new byte[16], iterations, keySizeBytes: 32));
        Assert.Equal("iterations", ex.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveKeySize_Throws(int keySizeBytes)
    {
        var service = new Pbkdf2ServiceFactory().CreatePbkdf2Service();
        var ex = Assert.Throws<ArgumentException>(
            () => service.DeriveKey(new byte[8], new byte[16], iterations: 1_000, keySizeBytes));
        Assert.Equal("keySizeBytes", ex.ParamName);
    }
}
