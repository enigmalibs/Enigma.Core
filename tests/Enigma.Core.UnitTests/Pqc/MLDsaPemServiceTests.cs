using System;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// The ML-DSA PEM contract: every private-key format round-trips to a key that actually signs, serializing and
/// re-reading raw key bytes is byte-identical, the parameter set is recovered from the algorithm OID (encrypted
/// PEMs included), the emitted labels are exactly the three PKCS#8 / SPKI ones, and the format argument visibly
/// changes the stored representation. Backs PHASE01 acceptance criteria 5-10.
/// </summary>
public class MLDsaPemServiceTests
{
    private static readonly IMLDsaPemService Pem = new MLDsaPemServiceFactory().CreateMLDsaPemService();
    private static readonly IMLDsaServiceFactory DsaFactory = new MLDsaServiceFactory();

    private const string Passphrase = "correct horse battery staple";

    // Encrypting a PEM runs 600 000 PBKDF2 iterations (~0.6 s), so the tests that only need *an* encrypted PEM
    // share one rather than paying for it repeatedly.
    private static readonly Lazy<(string PublicKeyPem, string PrivateKeyPem)> SharedEncryptedPair =
        new(() => Pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65, Passphrase.ToCharArray()));

    // Fully qualified: the test assembly has its own Enigma.Core.UnitTests.Encoding namespace, which shadows
    // System.Text.Encoding here.
    private static byte[] Message(string text) => System.Text.Encoding.UTF8.GetBytes(text);

    // The FIPS 204 encoded lengths, distinct per parameter set — matching them proves both that the right
    // security level came back and that a private key is the expanded encoding rather than a seed.
    private static int PublicKeyLength(MLDsaParameterSet set) => set switch
    {
        MLDsaParameterSet.MLDsa44 => 1312,
        MLDsaParameterSet.MLDsa65 => 1952,
        _ => 2592,
    };

    private static int ExpandedPrivateKeyLength(MLDsaParameterSet set) => set switch
    {
        MLDsaParameterSet.MLDsa44 => 2560,
        MLDsaParameterSet.MLDsa65 => 4032,
        _ => 4896,
    };

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44, MLPrivateKeyPemFormat.Seed)]
    [InlineData(MLDsaParameterSet.MLDsa44, MLPrivateKeyPemFormat.ExpandedKey)]
    [InlineData(MLDsaParameterSet.MLDsa44, MLPrivateKeyPemFormat.SeedAndExpandedKey)]
    [InlineData(MLDsaParameterSet.MLDsa65, MLPrivateKeyPemFormat.Seed)]
    [InlineData(MLDsaParameterSet.MLDsa65, MLPrivateKeyPemFormat.ExpandedKey)]
    [InlineData(MLDsaParameterSet.MLDsa65, MLPrivateKeyPemFormat.SeedAndExpandedKey)]
    [InlineData(MLDsaParameterSet.MLDsa87, MLPrivateKeyPemFormat.Seed)]
    [InlineData(MLDsaParameterSet.MLDsa87, MLPrivateKeyPemFormat.ExpandedKey)]
    [InlineData(MLDsaParameterSet.MLDsa87, MLPrivateKeyPemFormat.SeedAndExpandedKey)]
    public void GenerateKeyPairPem_EveryFormat_RoundTripsToASigningKey(
        MLDsaParameterSet parameterSet, MLPrivateKeyPemFormat format)
    {
        var (publicKeyPem, privateKeyPem) = Pem.GenerateKeyPairPem(parameterSet, format: format);

        var (privateKey, privateKeyParameterSet) = Pem.FromPrivateKeyPem(privateKeyPem);
        var (publicKey, publicKeyParameterSet) = Pem.FromPublicKeyPem(publicKeyPem);

        // Whatever the PEM stored, the bytes handed back are the expanded FIPS 204 encoding.
        Assert.Equal(ExpandedPrivateKeyLength(parameterSet), privateKey.Length);
        Assert.Equal(PublicKeyLength(parameterSet), publicKey.Length);
        Assert.Equal(parameterSet, privateKeyParameterSet);
        Assert.Equal(parameterSet, publicKeyParameterSet);

        // ...and they are directly usable by the signing service, with no seed re-derivation by the caller.
        var dsa = DsaFactory.CreateMLDsaService(parameterSet);
        var message = Message($"ML-DSA {parameterSet} / {format} PEM round trip");
        Assert.True(dsa.Verify(message, dsa.Sign(message, privateKey), publicKey));
    }

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44)]
    [InlineData(MLDsaParameterSet.MLDsa65)]
    [InlineData(MLDsaParameterSet.MLDsa87)]
    public void ToPem_FromPem_ReturnsByteIdenticalKeys(MLDsaParameterSet parameterSet)
    {
        var (publicKey, privateKey) = DsaFactory.CreateMLDsaService(parameterSet).GenerateKeyPair();

        var (roundTrippedPrivateKey, privateKeyParameterSet) =
            Pem.FromPrivateKeyPem(Pem.ToPrivateKeyPem(privateKey, parameterSet));
        var (roundTrippedPublicKey, publicKeyParameterSet) =
            Pem.FromPublicKeyPem(Pem.ToPublicKeyPem(publicKey, parameterSet));

        Assert.Equal(privateKey, roundTrippedPrivateKey);
        Assert.Equal(publicKey, roundTrippedPublicKey);
        Assert.Equal(parameterSet, privateKeyParameterSet);
        Assert.Equal(parameterSet, publicKeyParameterSet);
    }

    [Fact]
    public void FromPrivateKeyPem_SeedFormat_ExpandsToAStableKey()
    {
        // A seed-only PEM carries no expanded key, so reading one re-derives it. Re-serializing those bytes and
        // reading them back must land on exactly the same key: the expansion is deterministic, which is what makes
        // Seed a lossless default rather than a lossy shortcut.
        var (_, seedPem) = Pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65, format: MLPrivateKeyPemFormat.Seed);

        var (expanded, _) = Pem.FromPrivateKeyPem(seedPem);
        var (reRead, _) = Pem.FromPrivateKeyPem(Pem.ToPrivateKeyPem(expanded, MLDsaParameterSet.MLDsa65));

        Assert.Equal(expanded, reRead);
    }

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44)]
    [InlineData(MLDsaParameterSet.MLDsa65)]
    [InlineData(MLDsaParameterSet.MLDsa87)]
    public void FromPrivateKeyPem_EncryptedPem_RecoversParameterSetAndKey(MLDsaParameterSet parameterSet)
    {
        var password = Passphrase.ToCharArray();
        var (_, privateKeyPem) = Pem.GenerateKeyPairPem(parameterSet, password);

        var (privateKey, recovered) = Pem.FromPrivateKeyPem(privateKeyPem, password);

        Assert.Equal(parameterSet, recovered);
        Assert.Equal(ExpandedPrivateKeyLength(parameterSet), privateKey.Length);
    }

    [Fact]
    public void EncryptedPem_RoundTrips_AndNeverClearsTheCallersPassword()
    {
        var password = Passphrase.ToCharArray();

        // Both write paths and the read path see the same array; none of them may clear it.
        var (publicKeyPem, generatedPrivateKeyPem) =
            Pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65, password);
        Assert.Equal(Passphrase, new string(password));

        var (privateKey, _) = Pem.FromPrivateKeyPem(generatedPrivateKeyPem, password);
        Assert.Equal(Passphrase, new string(password));

        var reEncryptedPem = Pem.ToPrivateKeyPem(privateKey, MLDsaParameterSet.MLDsa65, password);
        Assert.Equal(Passphrase, new string(password));

        var (reReadPrivateKey, _) = Pem.FromPrivateKeyPem(reEncryptedPem, password);
        Assert.Equal(Passphrase, new string(password));
        Assert.Equal(privateKey, reReadPrivateKey);

        // The decrypted key still signs against the public half.
        var dsa = DsaFactory.CreateMLDsaService(MLDsaParameterSet.MLDsa65);
        var (publicKey, _) = Pem.FromPublicKeyPem(publicKeyPem);
        var message = Message("encrypted ML-DSA PEM round trip");
        Assert.True(dsa.Verify(message, dsa.Sign(message, reReadPrivateKey), publicKey));
    }

    [Fact]
    public void GenerateKeyPairPem_EmitsExactlyTheExpectedLabels()
    {
        var (publicKeyPem, privateKeyPem) = Pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65);

        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", publicKeyPem, StringComparison.Ordinal);
        Assert.Contains("-----END PUBLIC KEY-----", publicKeyPem, StringComparison.Ordinal);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", privateKeyPem, StringComparison.Ordinal);
        Assert.Contains("-----END PRIVATE KEY-----", privateKeyPem, StringComparison.Ordinal);
    }

    [Fact]
    public void EncryptedPrivateKeyPem_IsPkcs8_NotALegacyOpenSslHybrid()
    {
        var (_, encryptedPrivateKeyPem) = SharedEncryptedPair.Value;

        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", encryptedPrivateKeyPem, StringComparison.Ordinal);
        Assert.Contains("-----END ENCRYPTED PRIVATE KEY-----", encryptedPrivateKeyPem, StringComparison.Ordinal);

        // The traditional OpenSSL encryption headers must be absent: their presence would mean the writer had
        // emitted a malformed hybrid envelope (a PKCS#8 body wearing Proc-Type/DEK-Info headers).
        Assert.DoesNotContain("Proc-Type", encryptedPrivateKeyPem, StringComparison.Ordinal);
        Assert.DoesNotContain("DEK-Info", encryptedPrivateKeyPem, StringComparison.Ordinal);
    }

    [Fact]
    public void ToPublicKeyPem_And_ToPrivateKeyPem_EmitExactlyTheExpectedLabels()
    {
        var (publicKey, privateKey) = DsaFactory.CreateMLDsaService(MLDsaParameterSet.MLDsa65).GenerateKeyPair();

        Assert.StartsWith("-----BEGIN PUBLIC KEY-----",
            Pem.ToPublicKeyPem(publicKey, MLDsaParameterSet.MLDsa65), StringComparison.Ordinal);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----",
            Pem.ToPrivateKeyPem(privateKey, MLDsaParameterSet.MLDsa65), StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateKeyPairPem_FormatDeterminesTheStoredRepresentation()
    {
        // Pins that the format argument is actually honoured: the three representations of an ML-DSA-65 private key
        // differ by an order of magnitude, so the sizes alone distinguish them. The exact character counts depend on
        // the platform's line endings, hence thresholds rather than equalities.
        var seed = Pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65, format: MLPrivateKeyPemFormat.Seed).privateKeyPem;
        var expanded = Pem.GenerateKeyPairPem(
            MLDsaParameterSet.MLDsa65, format: MLPrivateKeyPemFormat.ExpandedKey).privateKeyPem;
        var both = Pem.GenerateKeyPairPem(
            MLDsaParameterSet.MLDsa65, format: MLPrivateKeyPemFormat.SeedAndExpandedKey).privateKeyPem;

        Assert.True(seed.Length < 200, $"A Seed-format ML-DSA-65 PEM should be tiny, but was {seed.Length} chars.");
        Assert.True(expanded.Length > 5000,
            $"An ExpandedKey-format ML-DSA-65 PEM should be over 5000 chars, but was {expanded.Length}.");
        Assert.True(both.Length > expanded.Length,
            $"SeedAndExpandedKey ({both.Length}) should be larger than ExpandedKey ({expanded.Length}).");
    }

    [Fact]
    public void GenerateKeyPairPem_DefaultsToSeedFormat_Unencrypted()
    {
        // The default overload must pick Seed (the library's default, not BouncyCastle's) and no encryption.
        var (_, privateKeyPem) = Pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65);

        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", privateKeyPem, StringComparison.Ordinal);
        Assert.True(privateKeyPem.Length < 200,
            $"The default format should be Seed, but the PEM was {privateKeyPem.Length} chars.");
    }
}
