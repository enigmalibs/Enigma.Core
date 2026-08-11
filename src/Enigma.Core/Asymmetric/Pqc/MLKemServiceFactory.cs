namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLKemServiceFactory"/> implementation. It maps the public <see cref="MLKemParameterSet"/>
/// to the internal BouncyCastle parameter set and returns a service bound to that security level.
/// </summary>
/// <remarks>
/// The BouncyCastle parameter mapping lives in <see cref="MLParameterSets"/>, shared with the PEM service so the
/// two cannot drift apart; it is entirely internal, so no BouncyCastle type appears on the public surface
/// (principle 1, enforced by the reflection guard test).
/// </remarks>
public sealed class MLKemServiceFactory : IMLKemServiceFactory
{
    /// <inheritdoc />
    public IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768)
        => new MLKemService(MLParameterSets.ToBcParameters(parameterSet));
}
