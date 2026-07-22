using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Enigma.Core.Encoding;
using Enigma.Core.Utils;

namespace Enigma.Core.Otp;

/// <summary>
/// Default <see cref="IOtpProvisioningService"/> implementation: generates shared secrets and
/// builds/parses <c>otpauth://totp/</c> URIs in the Key URI Format used by authenticator apps. The
/// service is stateless and safe to reuse; the Base32 encoder used for the otpauth secret is created once
/// at construction. Instances are created by <see cref="OtpProvisioningServiceFactory"/> only; the secure
/// random source backing <see cref="GenerateSecret"/> is wired internally, so no BouncyCastle type
/// appears on the public surface.
/// </summary>
public sealed class OtpProvisioningService : IOtpProvisioningService
{
    private const int MinSecretSize = 16;
    private const int MinDigits = 4;
    private const int MaxDigits = 9;
    private const string Scheme = "otpauth://";
    private const string TotpType = "totp";

    private readonly IEncodingService _base32;

    // Internal: only the factory constructs the service. The Base32 encoder is [A-Z2-7] canonical output;
    // decoding is tolerant of case, whitespace and missing padding (authenticator-app conventions).
    internal OtpProvisioningService(IEncodingServiceFactory encodingServiceFactory)
    {
        if (encodingServiceFactory is null) throw new ArgumentNullException(nameof(encodingServiceFactory));
        _base32 = encodingServiceFactory.CreateBase32Service();
    }

    /// <inheritdoc />
    public string BuildUri(OtpAuthParameters parameters)
    {
        if (parameters is null) throw new ArgumentNullException(nameof(parameters));
        if (parameters.Secret is null)
            throw new ArgumentNullException(nameof(parameters), "The secret must not be null.");
        if (string.IsNullOrWhiteSpace(parameters.AccountName))
            throw new ArgumentException("Account name must not be null or blank.", nameof(parameters));
        if (parameters.Digits < MinDigits || parameters.Digits > MaxDigits)
            throw new ArgumentOutOfRangeException(nameof(parameters), parameters.Digits,
                $"Digits must be between {MinDigits} and {MaxDigits}.");
        if (parameters.PeriodSeconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(parameters), parameters.PeriodSeconds,
                "Period must be greater than zero.");

        var algorithmName = AlgorithmToString(parameters.Algorithm);
        var hasIssuer = !string.IsNullOrEmpty(parameters.Issuer);
        // Base32 secret is [A-Z2-7] only, so it needs no URI escaping; padding is stripped.
        var encodedSecret = _base32.Encode(parameters.Secret).TrimEnd('=');

        var sb = new StringBuilder(Scheme).Append(TotpType).Append('/');
        if (hasIssuer)
            sb.Append(Uri.EscapeDataString(parameters.Issuer!)).Append(':');
        sb.Append(Uri.EscapeDataString(parameters.AccountName));

        sb.Append("?secret=").Append(encodedSecret);
        if (hasIssuer)
            sb.Append("&issuer=").Append(Uri.EscapeDataString(parameters.Issuer!));
        sb.Append("&algorithm=").Append(algorithmName);
        sb.Append("&digits=").Append(parameters.Digits.ToString(CultureInfo.InvariantCulture));
        sb.Append("&period=").Append(parameters.PeriodSeconds.ToString(CultureInfo.InvariantCulture));

        return sb.ToString();
    }

    /// <inheritdoc />
    public OtpAuthParameters ParseUri(string uri)
    {
        if (uri is null) throw new ArgumentNullException(nameof(uri));
        if (!uri.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"URI must start with '{Scheme}'.");

        var rest = uri.Substring(Scheme.Length);
        var slashIndex = rest.IndexOf('/');
        if (slashIndex < 0)
            throw new FormatException("URI is missing the type/label separator.");

        var type = rest.Substring(0, slashIndex);
        if (!type.Equals(TotpType, StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Unsupported otpauth type '{type}'; only '{TotpType}' is supported.");

        var afterType = rest.Substring(slashIndex + 1);
        var queryIndex = afterType.IndexOf('?');
        var labelPart = queryIndex < 0 ? afterType : afterType.Substring(0, queryIndex);
        var queryPart = queryIndex < 0 ? string.Empty : afterType.Substring(queryIndex + 1);

        var query = ParseQuery(queryPart);

        if (!query.TryGetValue("secret", out var encodedSecret) || string.IsNullOrEmpty(encodedSecret))
            throw new FormatException("URI is missing the required 'secret' parameter.");

        byte[] secret;
        try
        {
            secret = _base32.Decode(encodedSecret);
        }
        catch (FormatException ex)
        {
            throw new FormatException("The 'secret' parameter is not valid Base32.", ex);
        }

        var (labelIssuer, accountName) = SplitLabel(Uri.UnescapeDataString(labelPart));
        var issuer = query.TryGetValue("issuer", out var issuerParam) && !string.IsNullOrEmpty(issuerParam)
            ? issuerParam
            : labelIssuer;

        var algorithm = query.TryGetValue("algorithm", out var algorithmName)
            ? AlgorithmFromString(algorithmName)
            : OtpHashAlgorithm.Sha1;
        var digits = ParseIntParam(query, "digits", 6);
        var period = ParseIntParam(query, "period", 30);

        return new OtpAuthParameters(issuer, accountName, secret, digits, period, algorithm);
    }

    /// <inheritdoc />
    public byte[] GenerateSecret(int sizeBytes = 20)
    {
        if (sizeBytes < MinSecretSize)
            throw new ArgumentOutOfRangeException(nameof(sizeBytes), sizeBytes,
                $"Secret size must be at least {MinSecretSize} bytes.");

        return RandomUtils.GenerateRandomBytes(sizeBytes);
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(pair.Substring(0, eq));
            var value = Uri.UnescapeDataString(pair.Substring(eq + 1));
            result[key] = value;
        }
        return result;
    }

    private static (string? Issuer, string AccountName) SplitLabel(string label)
    {
        var colon = label.IndexOf(':');
        if (colon < 0)
            return (null, label);
        return (label.Substring(0, colon), label.Substring(colon + 1));
    }

    private static int ParseIntParam(IReadOnlyDictionary<string, string> query, string name, int defaultValue)
    {
        if (!query.TryGetValue(name, out var raw))
            return defaultValue;
        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            throw new FormatException($"The '{name}' parameter is not a valid integer: '{raw}'.");
        return value;
    }

    private static string AlgorithmToString(OtpHashAlgorithm algorithm)
        => algorithm switch
        {
            OtpHashAlgorithm.Sha1 => "SHA1",
            OtpHashAlgorithm.Sha256 => "SHA256",
            OtpHashAlgorithm.Sha512 => "SHA512",
            _ => throw new ArgumentException($"Unsupported OTP hash algorithm: {algorithm}.", nameof(algorithm))
        };

    private static OtpHashAlgorithm AlgorithmFromString(string algorithm)
    {
        if (algorithm.Equals("SHA1", StringComparison.OrdinalIgnoreCase)) return OtpHashAlgorithm.Sha1;
        if (algorithm.Equals("SHA256", StringComparison.OrdinalIgnoreCase)) return OtpHashAlgorithm.Sha256;
        if (algorithm.Equals("SHA512", StringComparison.OrdinalIgnoreCase)) return OtpHashAlgorithm.Sha512;
        throw new FormatException($"Unrecognized otpauth algorithm '{algorithm}'.");
    }
}
