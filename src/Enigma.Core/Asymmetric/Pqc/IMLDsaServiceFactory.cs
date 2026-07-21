namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Factory for creating <see cref="IMLDsaService"/> instances. The parameter set fixes the security level
/// for the lifetime of the returned service.
/// </summary>
public interface IMLDsaServiceFactory
{
    /// <summary>Creates an ML-DSA signature service (FIPS 204).</summary>
    /// <param name="parameterSet">The ML-DSA parameter set (security level). Defaults to <see cref="MLDsaParameterSet.MLDsa65"/>.</param>
    /// <returns>A configured ML-DSA service.</returns>
    IMLDsaService CreateMLDsaService(MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65);
}
