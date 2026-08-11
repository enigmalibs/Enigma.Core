using System;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// The ML-KEM PEM contract: every private-key format round-trips to a key that actually decapsulates, serializing
/// and re-reading raw key bytes is byte-identical, the parameter set is recovered from the algorithm OID (encrypted
/// PEMs included), the emitted labels are exactly the three PKCS#8 / SPKI ones, and the format argument visibly
/// changes the stored representation. Mirrors <see cref="MLDsaPemServiceTests"/>; backs PHASE02 acceptance
/// criteria 2 and 3.
/// </summary>
public class MLKemPemServiceTests
{
    private static readonly IMLKemPemService Pem = new MLKemPemServiceFactory().CreateMLKemPemService();
    private static readonly IMLKemServiceFactory KemFactory = new MLKemServiceFactory();

    private const string Passphrase = "correct horse battery staple";

    // Encrypting a PEM runs 600 000 PBKDF2 iterations (~0.6 s), so the tests that only need *an* encrypted PEM
    // share one rather than paying for it repeatedly.
    private static readonly Lazy<(string PublicKeyPem, string PrivateKeyPem)> SharedEncryptedPair =
        new(() => Pem.GenerateKeyPairPem(MLKemParameterSet.MLKem768, Passphrase.ToCharArray()));

    // The FIPS 203 encoded lengths, distinct per parameter set — matching them proves both that the right security
    // level came back and that a private key is the expanded decapsulation key rather than a seed.
    private static int PublicKeyLength(MLKemParameterSet set) => set switch
    {
        MLKemParameterSet.MLKem512 => 800,
        MLKemParameterSet.MLKem768 => 1184,
        _ => 1568,
    };

    private static int ExpandedPrivateKeyLength(MLKemParameterSet set) => set switch
    {
        MLKemParameterSet.MLKem512 => 1632,
        MLKemParameterSet.MLKem768 => 2400,
        _ => 3168,
    };

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, MLPrivateKeyPemFormat.Seed)]
    [InlineData(MLKemParameterSet.MLKem512, MLPrivateKeyPemFormat.ExpandedKey)]
    [InlineData(MLKemParameterSet.MLKem512, MLPrivateKeyPemFormat.SeedAndExpandedKey)]
    [InlineData(MLKemParameterSet.MLKem768, MLPrivateKeyPemFormat.Seed)]
    [InlineData(MLKemParameterSet.MLKem768, MLPrivateKeyPemFormat.ExpandedKey)]
    [InlineData(MLKemParameterSet.MLKem768, MLPrivateKeyPemFormat.SeedAndExpandedKey)]
    [InlineData(MLKemParameterSet.MLKem1024, MLPrivateKeyPemFormat.Seed)]
    [InlineData(MLKemParameterSet.MLKem1024, MLPrivateKeyPemFormat.ExpandedKey)]
    [InlineData(MLKemParameterSet.MLKem1024, MLPrivateKeyPemFormat.SeedAndExpandedKey)]
    public void GenerateKeyPairPem_EveryFormat_RoundTripsToADecapsulatingKey(
        MLKemParameterSet parameterSet, MLPrivateKeyPemFormat format)
    {
        var (publicKeyPem, privateKeyPem) = Pem.GenerateKeyPairPem(parameterSet, format: format);

        var (privateKey, privateKeyParameterSet) = Pem.FromPrivateKeyPem(privateKeyPem);
        var (publicKey, publicKeyParameterSet) = Pem.FromPublicKeyPem(publicKeyPem);

        // Whatever the PEM stored, the bytes handed back are the expanded FIPS 203 encoding.
        Assert.Equal(ExpandedPrivateKeyLength(parameterSet), privateKey.Length);
        Assert.Equal(PublicKeyLength(parameterSet), publicKey.Length);
        Assert.Equal(parameterSet, privateKeyParameterSet);
        Assert.Equal(parameterSet, publicKeyParameterSet);

        // ...and the two halves genuinely belong together: the secret encapsulated against the recovered public
        // key is the one the recovered private key decapsulates. ML-KEM never throws for a well-formed but wrong
        // key (FIPS 203 implicit rejection returns a different secret), so this equality is the real proof.
        var kem = KemFactory.CreateMLKemService(parameterSet);
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
        Assert.Equal(sharedSecret, kem.Decapsulate(ciphertext, privateKey));
    }

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public void ToPem_FromPem_ReturnsByteIdenticalKeys(MLKemParameterSet parameterSet)
    {
        var (publicKey, privateKey) = KemFactory.CreateMLKemService(parameterSet).GenerateKeyPair();

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
        var (_, seedPem) = Pem.GenerateKeyPairPem(MLKemParameterSet.MLKem768, format: MLPrivateKeyPemFormat.Seed);

        var (expanded, _) = Pem.FromPrivateKeyPem(seedPem);
        var (reRead, _) = Pem.FromPrivateKeyPem(Pem.ToPrivateKeyPem(expanded, MLKemParameterSet.MLKem768));

        Assert.Equal(expanded, reRead);
    }

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public void FromPrivateKeyPem_EncryptedPem_RecoversParameterSetAndKey(MLKemParameterSet parameterSet)
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
            Pem.GenerateKeyPairPem(MLKemParameterSet.MLKem768, password);
        Assert.Equal(Passphrase, new string(password));

        var (privateKey, _) = Pem.FromPrivateKeyPem(generatedPrivateKeyPem, password);
        Assert.Equal(Passphrase, new string(password));

        var reEncryptedPem = Pem.ToPrivateKeyPem(privateKey, MLKemParameterSet.MLKem768, password);
        Assert.Equal(Passphrase, new string(password));

        var (reReadPrivateKey, _) = Pem.FromPrivateKeyPem(reEncryptedPem, password);
        Assert.Equal(Passphrase, new string(password));
        Assert.Equal(privateKey, reReadPrivateKey);

        // The decrypted key still decapsulates against the public half.
        var kem = KemFactory.CreateMLKemService(MLKemParameterSet.MLKem768);
        var (publicKey, _) = Pem.FromPublicKeyPem(publicKeyPem);
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
        Assert.Equal(sharedSecret, kem.Decapsulate(ciphertext, reReadPrivateKey));
    }

    [Fact]
    public void GenerateKeyPairPem_EmitsExactlyTheExpectedLabels()
    {
        var (publicKeyPem, privateKeyPem) = Pem.GenerateKeyPairPem(MLKemParameterSet.MLKem768);

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
        var (publicKey, privateKey) = KemFactory.CreateMLKemService(MLKemParameterSet.MLKem768).GenerateKeyPair();

        Assert.StartsWith("-----BEGIN PUBLIC KEY-----",
            Pem.ToPublicKeyPem(publicKey, MLKemParameterSet.MLKem768), StringComparison.Ordinal);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----",
            Pem.ToPrivateKeyPem(privateKey, MLKemParameterSet.MLKem768), StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateKeyPairPem_FormatDeterminesTheStoredRepresentation()
    {
        // Pins that the format argument is actually honoured: the three representations of an ML-KEM-768 private
        // key differ by more than an order of magnitude, so the sizes alone distinguish them. The exact character
        // counts depend on the platform's line endings, hence thresholds rather than equalities.
        var seed = Pem.GenerateKeyPairPem(MLKemParameterSet.MLKem768, format: MLPrivateKeyPemFormat.Seed).privateKeyPem;
        var expanded = Pem.GenerateKeyPairPem(
            MLKemParameterSet.MLKem768, format: MLPrivateKeyPemFormat.ExpandedKey).privateKeyPem;
        var both = Pem.GenerateKeyPairPem(
            MLKemParameterSet.MLKem768, format: MLPrivateKeyPemFormat.SeedAndExpandedKey).privateKeyPem;

        Assert.True(seed.Length < 250, $"A Seed-format ML-KEM-768 PEM should be tiny, but was {seed.Length} chars.");
        Assert.True(expanded.Length > 2000,
            $"An ExpandedKey-format ML-KEM-768 PEM should be over 2000 chars, but was {expanded.Length}.");
        Assert.True(both.Length > expanded.Length,
            $"SeedAndExpandedKey ({both.Length}) should be larger than ExpandedKey ({expanded.Length}).");
    }

    [Fact]
    public void GenerateKeyPairPem_DefaultsToSeedFormat_Unencrypted()
    {
        // The default overload must pick Seed (the library's default, not BouncyCastle's) and no encryption.
        var (_, privateKeyPem) = Pem.GenerateKeyPairPem(MLKemParameterSet.MLKem768);

        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", privateKeyPem, StringComparison.Ordinal);
        Assert.True(privateKeyPem.Length < 250,
            $"The default format should be Seed, but the PEM was {privateKeyPem.Length} chars.");
    }
}
