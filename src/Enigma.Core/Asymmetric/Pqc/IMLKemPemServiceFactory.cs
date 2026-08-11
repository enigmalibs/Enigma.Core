namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Creates <see cref="IMLKemPemService"/> instances.
/// </summary>
/// <remarks>
/// Unlike <see cref="IMLKemServiceFactory"/>, this factory takes no parameter set: PEM serialization is not bound
/// to a security level, so the parameter set is an argument on each service call instead of factory state.
/// </remarks>
public interface IMLKemPemServiceFactory
{
    /// <summary>Creates an ML-KEM PEM service.</summary>
    /// <returns>A new <see cref="IMLKemPemService"/> instance.</returns>
    IMLKemPemService CreateMLKemPemService();
}
