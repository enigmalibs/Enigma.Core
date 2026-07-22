using System;

namespace Enigma.Core.Certificates;

/// <summary>
/// The purposes a certificate's key may be used for, corresponding to the bits of the X.509 <c>KeyUsage</c>
/// extension. This is a BouncyCastle-free flags enum: combine values with a bitwise OR (for example
/// <c>X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign</c> for a CA). The values are mapped to the underlying
/// <c>KeyUsage</c> extension bits internally, so no provider type is exposed on the public surface.
/// </summary>
[Flags]
public enum X509KeyUsage
{
    /// <summary>No key-usage bits set.</summary>
    None = 0,

    /// <summary>The key may be used to create digital signatures (other than for certificates or CRLs).</summary>
    DigitalSignature = 1 << 0,

    /// <summary>The key may be used to provide non-repudiation (also known as content-commitment).</summary>
    NonRepudiation = 1 << 1,

    /// <summary>The key may be used to encipher other keys (key transport).</summary>
    KeyEncipherment = 1 << 2,

    /// <summary>The key may be used to encipher data directly.</summary>
    DataEncipherment = 1 << 3,

    /// <summary>The key may be used for key agreement.</summary>
    KeyAgreement = 1 << 4,

    /// <summary>The key may be used to verify signatures on certificates (a CA key).</summary>
    KeyCertSign = 1 << 5,

    /// <summary>The key may be used to verify signatures on certificate revocation lists.</summary>
    CrlSign = 1 << 6,

    /// <summary>When combined with <see cref="KeyAgreement"/>, the key may be used only for enciphering.</summary>
    EncipherOnly = 1 << 7,

    /// <summary>When combined with <see cref="KeyAgreement"/>, the key may be used only for deciphering.</summary>
    DecipherOnly = 1 << 8,
}
