namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// The hash function used to build the OAEP padding when encrypting with RSA (RSAES-OAEP). The same hash
/// must be selected for decryption as was used for encryption. Selecting the hash through this enum keeps
/// the public API free of any underlying provider's naming convention.
/// </summary>
public enum RsaOaepHash
{
    /// <summary>OAEP using SHA-1 as the mask-generation and label hash.</summary>
    Sha1,

    /// <summary>OAEP using SHA-256. The recommended default.</summary>
    Sha256,

    /// <summary>OAEP using SHA-384.</summary>
    Sha384,

    /// <summary>OAEP using SHA-512.</summary>
    Sha512,
}
