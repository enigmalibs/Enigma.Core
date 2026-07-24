namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Factory for creating <see cref="IMLDsaService"/> instances. The parameter set fixes the security level
/// for the lifetime of the returned service.
/// </summary>
public interface IMLDsaServiceFactory
{
    /// <summary>Creates an ML-DSA signature service (FIPS 204).</summary>
    /// <param name="parameterSet">The ML-DSA parameter set (security level). Defaults to <see cref="MLDsaParameterSet.MLDsa65"/>.</param>
    /// <param name="deterministic">
    /// When <see langword="true"/>, signing is deterministic: signing the same message with the same key always
    /// yields the identical signature. When <see langword="false"/> (the default), signing is hedged and mixes in
    /// fresh randomness per call, so repeated signatures of the same message differ. Both forms are valid FIPS 204
    /// signatures and verify identically.
    /// </param>
    /// <returns>A configured ML-DSA service.</returns>
    IMLDsaService CreateMLDsaService(MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65, bool deterministic = false);
}
