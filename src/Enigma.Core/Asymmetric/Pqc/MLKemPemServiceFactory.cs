namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLKemPemServiceFactory"/> implementation. Construct it with <c>new</c>, or register it
/// against <see cref="IMLKemPemServiceFactory"/> in a dependency-injection container.
/// </summary>
public sealed class MLKemPemServiceFactory : IMLKemPemServiceFactory
{
    /// <inheritdoc />
    public IMLKemPemService CreateMLKemPemService() => new MLKemPemService();
}
