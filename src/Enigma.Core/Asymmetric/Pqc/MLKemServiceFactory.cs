using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLKemServiceFactory"/> implementation. It maps the public <see cref="MLKemParameterSet"/>
/// to the internal BouncyCastle parameter set and returns a service bound to that security level.
/// </summary>
/// <remarks>
/// The BouncyCastle parameter mapping is entirely internal; no BouncyCastle type appears on the public surface
/// (principle 1, enforced by the reflection guard test).
/// </remarks>
public sealed class MLKemServiceFactory : IMLKemServiceFactory
{
    /// <inheritdoc />
    public IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768)
        => new MLKemService(ToBcParameters(parameterSet));

    // Maps the public parameter-set enum to the internal BouncyCastle ML-KEM parameter object.
    private static MLKemParameters ToBcParameters(MLKemParameterSet parameterSet) => parameterSet switch
    {
        MLKemParameterSet.MLKem512 => MLKemParameters.ml_kem_512,
        MLKemParameterSet.MLKem768 => MLKemParameters.ml_kem_768,
        MLKemParameterSet.MLKem1024 => MLKemParameters.ml_kem_1024,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, "Unsupported ML-KEM parameter set."),
    };
}
