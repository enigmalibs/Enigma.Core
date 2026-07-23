using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Enigma.Core.UnitTests.Infrastructure;

/// <summary>
/// Shared loader for the CSV test-vector files that drive the data-driven <c>[Theory]</c> tests.
/// Centralizes the "read file, drop the header row, skip blank lines, split on commas" boilerplate
/// so it is not copy-pasted into every test class. Column mapping and decoding stay with each test,
/// because the column layout differs from one vector file to the next.
/// </summary>
internal static class CsvData
{
    /// <summary>
    /// Reads the CSV vector file at the given path segments (combined relative to the test output
    /// directory), skips the header row and any blank lines, and yields one array of comma-separated
    /// fields per remaining row.
    /// </summary>
    /// <param name="pathSegments">Path segments of the CSV file, e.g. <c>"BlockCiphers", "aes-cbc.csv"</c>.</param>
    /// <returns>One <see cref="string"/>[] of raw fields per data row.</returns>
    public static IEnumerable<string[]> Rows(params string[] pathSegments)
        => File.ReadAllLines(Path.Combine(pathSegments))
            .Skip(1)
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line => line.Split(','));

    /// <summary>Decodes a single hexadecimal CSV field into its raw bytes.</summary>
    /// <param name="value">The hex-encoded field.</param>
    /// <returns>The decoded bytes.</returns>
    // Self-contained: uses System.Convert.FromHexString so the harness takes no dependency on the
    // HexService (which is a stub until the Encoding feature lands).
    public static byte[] Hex(string value) => Convert.FromHexString(value);
}
