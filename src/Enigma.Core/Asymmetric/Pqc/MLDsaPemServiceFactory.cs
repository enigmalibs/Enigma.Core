namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLDsaPemServiceFactory"/> implementation. Construct it with <c>new</c>, or register it
/// against <see cref="IMLDsaPemServiceFactory"/> in a dependency-injection container.
/// </summary>
public sealed class MLDsaPemServiceFactory : IMLDsaPemServiceFactory
{
    /// <inheritdoc />
    public IMLDsaPemService CreateMLDsaPemService() => new MLDsaPemService();
}
