namespace Enigma.Core.Padding;

/// <summary>
/// Standard byte-padding schemes used to align data to a block boundary for block cipher operations.
/// Selecting the scheme through this enum keeps the public API free of any underlying provider's
/// padding types.
/// </summary>
public enum PaddingScheme
{
    /// <summary>No padding. The data must already be a whole number of blocks.</summary>
    None,

    /// <summary>
    /// PKCS#7 (a.k.a. PKCS#5 for 8-byte blocks): appends N bytes each of value N, where N is the number
    /// of bytes required to complete the block. The most widely used scheme.
    /// </summary>
    Pkcs7,

    /// <summary>
    /// ISO/IEC 7816-4: appends a single <c>0x80</c> byte followed by zero bytes (<c>0x00</c>) to fill the
    /// block. Also known as scheme 2 of ISO/IEC 9797-1.
    /// </summary>
    Iso7816,

    /// <summary>
    /// ISO 10126-2: fills the padding with random bytes, with the final byte giving the padding length.
    /// </summary>
    Iso10126,

    /// <summary>
    /// ANSI X9.23: fills the padding with zero bytes, with the final byte giving the padding length.
    /// </summary>
    X923,
}
