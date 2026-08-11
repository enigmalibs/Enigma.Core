using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Two-way mapping between the library's public parameter-set enums and BouncyCastle's parameter objects, for
/// both post-quantum families.
/// </summary>
/// <remarks>
/// <para>
/// The write direction (enum → BouncyCastle) backs the service factories; the read direction
/// (BouncyCastle → enum) backs the PEM services, which recover the parameter set from the algorithm OID.
/// Centralising both here keeps a single place in the assembly that knows which BouncyCastle parameter object
/// corresponds to which enum value — the two cannot drift apart.
/// </para>
/// <para>
/// Note the asymmetry in the exception contract, which mirrors where the value comes from: an undefined enum
/// value is a caller mistake in an argument, so it is an <see cref="ArgumentOutOfRangeException"/>; a
/// BouncyCastle parameter object the library does not expose (a pre-hash set such as <c>ml_dsa_65_with_sha512</c>,
/// which no Enigma.Core enum names) is decoded material the caller supplied, so it is an
/// <see cref="ArgumentException"/> — never a silently wrong enum value.
/// </para>
/// </remarks>
internal static class MLParameterSets
{
    /// <summary>Maps the public ML-DSA parameter set to its BouncyCastle parameter object.</summary>
    internal static MLDsaParameters ToBcParameters(MLDsaParameterSet parameterSet) => parameterSet switch
    {
        MLDsaParameterSet.MLDsa44 => MLDsaParameters.ml_dsa_44,
        MLDsaParameterSet.MLDsa65 => MLDsaParameters.ml_dsa_65,
        MLDsaParameterSet.MLDsa87 => MLDsaParameters.ml_dsa_87,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, "Unsupported ML-DSA parameter set."),
    };

    /// <summary>Recovers the public ML-DSA parameter set from a BouncyCastle parameter object.</summary>
    /// <param name="parameters">The parameter object carried by a decoded ML-DSA key.</param>
    /// <param name="paramName">The name of the public API parameter the key came from, for the exception.</param>
    internal static MLDsaParameterSet FromBcParameters(MLDsaParameters parameters, string paramName)
    {
        // BouncyCastle hands out the same static instance for a given algorithm OID, so reference identity is the
        // exact test: it distinguishes ml_dsa_65 from the pre-hash ml_dsa_65_with_sha512, which shares its level.
        if (ReferenceEquals(parameters, MLDsaParameters.ml_dsa_44)) return MLDsaParameterSet.MLDsa44;
        if (ReferenceEquals(parameters, MLDsaParameters.ml_dsa_65)) return MLDsaParameterSet.MLDsa65;
        if (ReferenceEquals(parameters, MLDsaParameters.ml_dsa_87)) return MLDsaParameterSet.MLDsa87;

        throw new ArgumentException(
            $"The key uses the ML-DSA parameter set '{parameters.Name}', which this library does not support.",
            paramName);
    }

    /// <summary>Maps the public ML-KEM parameter set to its BouncyCastle parameter object.</summary>
    internal static MLKemParameters ToBcParameters(MLKemParameterSet parameterSet) => parameterSet switch
    {
        MLKemParameterSet.MLKem512 => MLKemParameters.ml_kem_512,
        MLKemParameterSet.MLKem768 => MLKemParameters.ml_kem_768,
        MLKemParameterSet.MLKem1024 => MLKemParameters.ml_kem_1024,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, "Unsupported ML-KEM parameter set."),
    };

    /// <summary>Recovers the public ML-KEM parameter set from a BouncyCastle parameter object.</summary>
    /// <param name="parameters">The parameter object carried by a decoded ML-KEM key.</param>
    /// <param name="paramName">The name of the public API parameter the key came from, for the exception.</param>
    internal static MLKemParameterSet FromBcParameters(MLKemParameters parameters, string paramName)
    {
        if (ReferenceEquals(parameters, MLKemParameters.ml_kem_512)) return MLKemParameterSet.MLKem512;
        if (ReferenceEquals(parameters, MLKemParameters.ml_kem_768)) return MLKemParameterSet.MLKem768;
        if (ReferenceEquals(parameters, MLKemParameters.ml_kem_1024)) return MLKemParameterSet.MLKem1024;

        throw new ArgumentException(
            $"The key uses the ML-KEM parameter set '{parameters.Name}', which this library does not support.",
            paramName);
    }
}
