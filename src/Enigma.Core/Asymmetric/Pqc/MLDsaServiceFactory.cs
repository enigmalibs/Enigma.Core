using System;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// A factory for creating ML-DSA signature services.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the post-quantum implementation feature.
/// </remarks>
public sealed class MLDsaServiceFactory : IMLDsaServiceFactory
{
    /// <inheritdoc />
    public IMLDsaService CreateMLDsaService(MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65) => throw new NotImplementedException();
}
