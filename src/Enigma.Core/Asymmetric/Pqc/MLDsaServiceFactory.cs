namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLDsaServiceFactory"/> implementation. It maps the public <see cref="MLDsaParameterSet"/>
/// to the internal BouncyCastle parameter set and returns a service bound to that security level.
/// </summary>
/// <remarks>
/// The BouncyCastle parameter mapping lives in <see cref="MLParameterSets"/>, shared with the PEM service so the
/// two cannot drift apart; it is entirely internal, so no BouncyCastle type appears on the public surface
/// (principle 1, enforced by the reflection guard test).
/// </remarks>
public sealed class MLDsaServiceFactory : IMLDsaServiceFactory
{
    /// <inheritdoc />
    public IMLDsaService CreateMLDsaService(
        MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65, bool deterministic = false)
        => new MLDsaService(MLParameterSets.ToBcParameters(parameterSet), deterministic);
}
