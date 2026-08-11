using System.Linq;
using System.Reflection;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Factory shape for the ML-KEM PEM service: it hands out concrete <see cref="MLKemPemService"/> instances, a fresh
/// one per call, and — unlike <see cref="MLKemServiceFactory"/> — takes no parameter set, because PEM serialization
/// is not bound to a security level. Backs PHASE02 acceptance criterion 1, including that
/// <see cref="MLPrivateKeyPemFormat"/> is reused rather than duplicated per family.
/// </summary>
public class MLKemPemServiceFactoryTests
{
    private readonly IMLKemPemServiceFactory _factory = new MLKemPemServiceFactory();

    [Fact]
    public void CreateMLKemPemService_ReturnsMLKemPemService()
        => Assert.IsType<MLKemPemService>(_factory.CreateMLKemPemService());

    [Fact]
    public void CreateMLKemPemService_ReturnsFreshInstancePerCall()
        => Assert.NotSame(_factory.CreateMLKemPemService(), _factory.CreateMLKemPemService());

    [Fact]
    public void CreateMLKemPemService_TakesNoArguments()
    {
        // The parameter set is a per-call argument on the service, never factory state.
        var method = typeof(IMLKemPemServiceFactory).GetMethod(nameof(IMLKemPemServiceFactory.CreateMLKemPemService));

        Assert.NotNull(method);
        Assert.Empty(method!.GetParameters());
    }

    [Fact]
    public void Factory_IsConstructibleWithNew()
    {
        // Every factory in the library is a plain `new`-able class with a parameterless constructor, so it also
        // registers cleanly against its interface in a DI container.
        var constructors = typeof(MLKemPemServiceFactory).GetConstructors();

        Assert.Single(constructors);
        Assert.Empty(constructors[0].GetParameters());
        Assert.IsType<MLKemPemServiceFactory>(new MLKemPemServiceFactory());
    }

    [Fact]
    public void Service_IsConstructibleWithNew()
    {
        // The service adds nothing to construct, so it is usable without going through the factory at all.
        var constructors = typeof(MLKemPemService).GetConstructors();

        Assert.Single(constructors);
        Assert.Empty(constructors[0].GetParameters());
        Assert.IsAssignableFrom<IMLKemPemService>(new MLKemPemService());
    }

    [Fact]
    public void PemTypes_AreExportedFromThePqcNamespace()
    {
        // Criterion 1's surface list: exactly these four types are added, all in the PQC namespace.
        var exported = typeof(IMLKemService).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == "Enigma.Core.Asymmetric.Pqc")
            .Select(t => t.Name)
            .ToList();

        Assert.Contains(nameof(IMLKemPemService), exported);
        Assert.Contains(nameof(MLKemPemService), exported);
        Assert.Contains(nameof(IMLKemPemServiceFactory), exported);
        Assert.Contains(nameof(MLKemPemServiceFactory), exported);

        // The shared internals stay internal — they must never appear on the exported surface.
        Assert.DoesNotContain("MLParameterSets", exported);
        Assert.DoesNotContain("PemEnvelope",
            typeof(IMLKemService).Assembly.GetExportedTypes().Select(t => t.Name).ToList());
    }

    [Fact]
    public void PrivateKeyPemFormat_IsSharedBetweenBothFamilies_NotDuplicated()
    {
        // Criterion 1: MLPrivateKeyPemFormat is reused, so exactly one such enum exists and both services take it.
        var formatEnums = typeof(IMLKemService).Assembly
            .GetExportedTypes()
            .Where(t => t.IsEnum && t.Name.Contains("PrivateKeyPemFormat"))
            .ToList();

        Assert.Single(formatEnums);
        Assert.Equal(typeof(MLPrivateKeyPemFormat), formatEnums[0]);

        Assert.Equal(
            typeof(MLPrivateKeyPemFormat),
            ParameterTypeOf<IMLKemPemService>(nameof(IMLKemPemService.GenerateKeyPairPem), "format"));
        Assert.Equal(
            typeof(MLPrivateKeyPemFormat),
            ParameterTypeOf<IMLDsaPemService>(nameof(IMLDsaPemService.GenerateKeyPairPem), "format"));
    }

    private static System.Type ParameterTypeOf<T>(string methodName, string parameterName)
        => typeof(T).GetMethod(methodName)!
            .GetParameters()
            .Single(p => p.Name == parameterName)
            .ParameterType;
}
