namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Derives cryptographic key material from a password using Argon2, a memory-hard key-derivation
/// function. Its tunable memory, time and parallelism cost parameters make brute-force attacks
/// expensive on both CPUs and GPUs.
/// </summary>
public interface IArgon2Service
{
    /// <summary>
    /// Derives a key of the requested length from a password and salt.
    /// </summary>
    /// <param name="password">The password bytes to derive from.</param>
    /// <param name="salt">The salt. Should be random and unique per password.</param>
    /// <param name="iterations">The number of passes over memory (the time cost).</param>
    /// <param name="memorySizeKb">The amount of memory to use, in kibibytes (the memory cost).</param>
    /// <param name="degreeOfParallelism">The number of parallel lanes (threads) to use.</param>
    /// <param name="keySizeBytes">The desired length of the derived key, in bytes.</param>
    /// <param name="variant">The Argon2 variant. Defaults to <see cref="Argon2Variant.Argon2id"/>.</param>
    /// <param name="version">The Argon2 version. Defaults to <see cref="Argon2Version.Version13"/>.</param>
    /// <returns>The derived key, <paramref name="keySizeBytes"/> bytes long.</returns>
    /// <remarks>
    /// Tune the cost parameters to your hardware. RFC 9106's second recommended option is
    /// <paramref name="iterations"/> = 3, <paramref name="memorySizeKb"/> = 65536 (64 MiB) and
    /// <paramref name="degreeOfParallelism"/> = 4. The <paramref name="password"/> array is used as-is:
    /// it is neither mutated nor cleared, so the caller owns its lifetime.
    /// </remarks>
    /// <exception cref="System.ArgumentNullException">
    /// <paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="System.ArgumentException">
    /// <paramref name="iterations"/>, <paramref name="memorySizeKb"/>,
    /// <paramref name="degreeOfParallelism"/>, or <paramref name="keySizeBytes"/> is not greater than zero.
    /// </exception>
    byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int memorySizeKb,
        int degreeOfParallelism,
        int keySizeBytes,
        Argon2Variant variant = Argon2Variant.Argon2id,
        Argon2Version version = Argon2Version.Version13);
}
