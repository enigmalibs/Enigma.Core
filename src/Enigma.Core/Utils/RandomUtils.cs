using System;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Utils;

/// <summary>
/// Utility class for random data generation
/// </summary>
public static class RandomUtils
{
    [ThreadStatic]
    private static SecureRandom? _secureRandom;

    private static SecureRandom GetSecureRandom() => _secureRandom ??= new SecureRandom();

    /// <summary>
    /// Generate random bytes
    /// </summary>
    /// <param name="size">Number of bytes to generate</param>
    /// <returns>Random bytes</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="size"/> is less than or equal to zero</exception>
    public static byte[] GenerateRandomBytes(int size)
    {
        if (size <= 0) throw new ArgumentException("Size must be greater than zero.", nameof(size));

        var sr = GetSecureRandom();
        var bytes = new byte[size];
        sr.NextBytes(bytes);
        return bytes;
    }
}
