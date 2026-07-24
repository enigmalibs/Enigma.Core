namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Factory for creating <see cref="IMLKemService"/> instances. The parameter set fixes the security level
/// for the lifetime of the returned service.
/// </summary>
public interface IMLKemServiceFactory
{
    /// <summary>Creates an ML-KEM key-encapsulation service (FIPS 203).</summary>
    /// <param name="parameterSet">The ML-KEM parameter set (security level). Defaults to <see cref="MLKemParameterSet.MLKem768"/>.</param>
    /// <returns>A configured ML-KEM service.</returns>
    IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768);
}
