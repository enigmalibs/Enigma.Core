namespace Enigma.Core.KeyDerivation;

/// <summary>
/// The Argon2 variant, which determines how the algorithm accesses memory and the trade-off it makes
/// between resistance to side-channel attacks and resistance to GPU/time-memory attacks.
/// </summary>
public enum Argon2Variant
{
    /// <summary>
    /// Argon2d — data-dependent memory access. Maximizes resistance to GPU cracking attacks but is
    /// susceptible to side-channel timing attacks. Suitable where no side-channel risk exists.
    /// </summary>
    Argon2d,

    /// <summary>
    /// Argon2i — data-independent memory access. Resists side-channel timing attacks; intended for
    /// password hashing and key derivation.
    /// </summary>
    Argon2i,

    /// <summary>
    /// Argon2id — a hybrid of Argon2i and Argon2d. The recommended default for most use cases,
    /// combining side-channel resistance with strong resistance to GPU cracking.
    /// </summary>
    Argon2id,
}
