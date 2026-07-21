using System;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// A factory for creating ML-KEM key-encapsulation services.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the post-quantum implementation feature.
/// </remarks>
public sealed class MLKemServiceFactory : IMLKemServiceFactory
{
    /// <inheritdoc />
    public IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768) => throw new NotImplementedException();
}
