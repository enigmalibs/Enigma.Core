namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Creates <see cref="IMLDsaPemService"/> instances.
/// </summary>
/// <remarks>
/// Unlike <see cref="IMLDsaServiceFactory"/>, this factory takes no parameter set: PEM serialization is not bound
/// to a security level, so the parameter set is an argument on each service call instead of factory state.
/// </remarks>
public interface IMLDsaPemServiceFactory
{
    /// <summary>Creates an ML-DSA PEM service.</summary>
    /// <returns>A new <see cref="IMLDsaPemService"/> instance.</returns>
    IMLDsaPemService CreateMLDsaPemService();
}
