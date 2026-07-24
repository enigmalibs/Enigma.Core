using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLDsaServiceFactory"/> implementation. It maps the public <see cref="MLDsaParameterSet"/>
/// to the internal BouncyCastle parameter set and returns a service bound to that security level.
/// </summary>
/// <remarks>
/// The BouncyCastle parameter mapping is entirely internal; no BouncyCastle type appears on the public surface
/// (principle 1, enforced by the reflection guard test).
/// </remarks>
public sealed class MLDsaServiceFactory : IMLDsaServiceFactory
{
    /// <inheritdoc />
    public IMLDsaService CreateMLDsaService(
        MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65, bool deterministic = false)
        => new MLDsaService(ToBcParameters(parameterSet), deterministic);

    // Maps the public parameter-set enum to the internal BouncyCastle ML-DSA parameter object.
    private static MLDsaParameters ToBcParameters(MLDsaParameterSet parameterSet) => parameterSet switch
    {
        MLDsaParameterSet.MLDsa44 => MLDsaParameters.ml_dsa_44,
        MLDsaParameterSet.MLDsa65 => MLDsaParameters.ml_dsa_65,
        MLDsaParameterSet.MLDsa87 => MLDsaParameters.ml_dsa_87,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, "Unsupported ML-DSA parameter set."),
    };
}
