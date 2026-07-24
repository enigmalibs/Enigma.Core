namespace Enigma.Core.KeyDerivation;

/// <summary>
/// The Argon2 algorithm version number, which selects the specification revision the derivation
/// conforms to.
/// </summary>
public enum Argon2Version
{
    /// <summary>Version 1.0 (0x10). Provided for compatibility with data produced by older tools.</summary>
    Version10,

    /// <summary>Version 1.3 (0x13). The current specification and the recommended default.</summary>
    Version13,
}
