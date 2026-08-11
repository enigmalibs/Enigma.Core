using System.Linq;
using System.Reflection;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Factory shape for the ML-DSA PEM service: it hands out concrete <see cref="MLDsaPemService"/> instances, a fresh
/// one per call, and — unlike <see cref="MLDsaServiceFactory"/> — takes no parameter set, because PEM serialization
/// is not bound to a security level. Backs the factory half of PHASE01 acceptance criterion 3.
/// </summary>
public class MLDsaPemServiceFactoryTests
{
    private readonly IMLDsaPemServiceFactory _factory = new MLDsaPemServiceFactory();

    [Fact]
    public void CreateMLDsaPemService_ReturnsMLDsaPemService()
        => Assert.IsType<MLDsaPemService>(_factory.CreateMLDsaPemService());

    [Fact]
    public void CreateMLDsaPemService_ReturnsFreshInstancePerCall()
        => Assert.NotSame(_factory.CreateMLDsaPemService(), _factory.CreateMLDsaPemService());

    [Fact]
    public void CreateMLDsaPemService_TakesNoArguments()
    {
        // The parameter set is a per-call argument on the service, never factory state.
        var method = typeof(IMLDsaPemServiceFactory).GetMethod(nameof(IMLDsaPemServiceFactory.CreateMLDsaPemService));

        Assert.NotNull(method);
        Assert.Empty(method!.GetParameters());
    }

    [Fact]
    public void Factory_IsConstructibleWithNew()
    {
        // Every factory in the library is a plain `new`-able class with a parameterless constructor, so it also
        // registers cleanly against its interface in a DI container.
        var constructors = typeof(MLDsaPemServiceFactory).GetConstructors();

        Assert.Single(constructors);
        Assert.Empty(constructors[0].GetParameters());
        Assert.IsType<MLDsaPemServiceFactory>(new MLDsaPemServiceFactory());
    }

    [Fact]
    public void Service_IsConstructibleWithNew()
    {
        // The service adds nothing to construct, so it is usable without going through the factory at all.
        var constructors = typeof(MLDsaPemService).GetConstructors();

        Assert.Single(constructors);
        Assert.Empty(constructors[0].GetParameters());
        Assert.IsAssignableFrom<IMLDsaPemService>(new MLDsaPemService());
    }

    [Fact]
    public void PemTypes_AreExportedFromThePqcNamespace()
    {
        // Criterion 3's surface list: exactly these five types are added, all in the PQC namespace.
        var exported = typeof(IMLDsaService).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == "Enigma.Core.Asymmetric.Pqc")
            .Select(t => t.Name)
            .ToList();

        Assert.Contains(nameof(MLPrivateKeyPemFormat), exported);
        Assert.Contains(nameof(IMLDsaPemService), exported);
        Assert.Contains(nameof(MLDsaPemService), exported);
        Assert.Contains(nameof(IMLDsaPemServiceFactory), exported);
        Assert.Contains(nameof(MLDsaPemServiceFactory), exported);

        // The shared internals stay internal — they must never appear on the exported surface.
        Assert.DoesNotContain("MLParameterSets", exported);
        Assert.DoesNotContain("PemEnvelope",
            typeof(IMLDsaService).Assembly.GetExportedTypes().Select(t => t.Name).ToList());
    }
}
