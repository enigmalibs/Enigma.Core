namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Validation for the GCM authentication tag (MAC) size, expressed in bits. A valid size is a
/// multiple of 8 between <see cref="MinBits"/> and <see cref="MaxBits"/> inclusive — the range a
/// standard GCM implementation accepts. Defined once here so all consumers enforce the same rule
/// instead of each hard-coding it.
/// </summary>
public static class GcmMacSize
{
    /// <summary>Smallest valid GCM MAC size, in bits.</summary>
    public const int MinBits = 32;

    /// <summary>Largest valid GCM MAC size, in bits.</summary>
    public const int MaxBits = 128;

    /// <summary>A human-readable description of the valid range, suitable for error messages.</summary>
    public const string RangeDescription = "GCM MAC size must be a multiple of 8 between 32 and 128 bits.";

    /// <summary>Returns whether <paramref name="bits"/> is a valid GCM MAC size.</summary>
    /// <param name="bits">The candidate MAC size, in bits.</param>
    /// <returns>
    /// <c>true</c> when <paramref name="bits"/> is a multiple of 8 within
    /// [<see cref="MinBits"/>, <see cref="MaxBits"/>]; otherwise <c>false</c>.
    /// </returns>
    public static bool IsValid(int bits) => bits is >= MinBits and <= MaxBits && bits % 8 == 0;
}
