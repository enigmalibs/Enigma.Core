using System;

namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Provides RSA public-key encryption (PKCS#1 v1.5, OAEP) and signing (RSASSA-PKCS1-v1_5).
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete RSA logic arrives with the public-key implementation feature.
/// </remarks>
public sealed class PublicKeyService : IPublicKeyService
{
    /// <inheritdoc />
    public byte[] EncryptPkcs1(byte[] data, string publicKeyPem) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] DecryptPkcs1(byte[] ciphertext, string privateKeyPem, char[]? password = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] EncryptOaep(byte[] data, string publicKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] DecryptOaep(byte[] ciphertext, string privateKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256, char[]? password = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] Sign(byte[] data, string privateKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool Verify(byte[] data, byte[] signature, string publicKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa) => throw new NotImplementedException();
}
