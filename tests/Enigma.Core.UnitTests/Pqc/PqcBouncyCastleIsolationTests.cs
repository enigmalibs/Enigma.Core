using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Principle 1, scoped to <c>Enigma.Core.Asymmetric.Pqc</c>: the ML-DSA / ML-KEM services hide BouncyCastle
/// behind raw <see cref="byte"/> arrays, the parameter-set enums and the named value tuples, so this guard walks
/// every exported type in the namespace and fails if any <c>Org.BouncyCastle.*</c> type appears on a base type,
/// implemented interface, exposed method return/parameter, constructor parameter, or exposed field. It is the
/// enforcement behind acceptance criterion 2.
/// </summary>
public class PqcBouncyCastleIsolationTests
{
    private const string ForbiddenNamespaceRoot = "Org.BouncyCastle";
    private const string PqcNamespace = "Enigma.Core.Asymmetric.Pqc";

    [Fact]
    public void NoPqcType_ExposesBouncyCastleType()
    {
        var types = typeof(IMLDsaService).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == PqcNamespace)
            .ToList();

        // Sanity: the concrete services, factories and enums are all in scope.
        Assert.Contains(typeof(MLDsaService), types);
        Assert.Contains(typeof(MLDsaServiceFactory), types);
        Assert.Contains(typeof(MLKemService), types);
        Assert.Contains(typeof(MLKemServiceFactory), types);
        Assert.Contains(typeof(MLDsaParameterSet), types);
        Assert.Contains(typeof(MLKemParameterSet), types);

        var offenders = new List<string>();

        foreach (var type in types)
        {
            foreach (var referenced in ReferencedTypes(type.BaseType)
                         .Concat(type.GetInterfaces().SelectMany(ReferencedTypes)))
                Check(offenders, referenced, $"{type.FullName} (base/interface)");

            const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic |
                                       BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

            foreach (var method in type.GetMethods(flags).Where(IsExposed))
            {
                foreach (var t in ReferencedTypes(method.ReturnType))
                    Check(offenders, t, $"{type.FullName}.{method.Name} (return)");
                foreach (var t in method.GetParameters().SelectMany(p => ReferencedTypes(p.ParameterType)))
                    Check(offenders, t, $"{type.FullName}.{method.Name} (parameter)");
            }

            foreach (var ctor in type.GetConstructors(flags).Where(IsExposed))
                foreach (var t in ctor.GetParameters().SelectMany(p => ReferencedTypes(p.ParameterType)))
                    Check(offenders, t, $"{type.FullName}.ctor (parameter)");

            foreach (var field in type.GetFields(flags).Where(IsExposed))
                foreach (var t in ReferencedTypes(field.FieldType))
                    Check(offenders, t, $"{type.FullName}.{field.Name} (field)");
        }

        Assert.True(offenders.Count == 0,
            "BouncyCastle types leaked onto the PQC public surface:" + Environment.NewLine +
            string.Join(Environment.NewLine, offenders));
    }

    private static bool IsExposed(MethodBase m) => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly;
    private static bool IsExposed(FieldInfo f) => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly;

    private static IEnumerable<Type> ReferencedTypes(Type? type)
    {
        if (type is null) yield break;
        if (type.HasElementType)
        {
            foreach (var t in ReferencedTypes(type.GetElementType()))
                yield return t;
            yield break;
        }
        yield return type;
        if (type.IsGenericType)
            foreach (var arg in type.GetGenericArguments())
                foreach (var t in ReferencedTypes(arg))
                    yield return t;
    }

    private static void Check(List<string> offenders, Type type, string where)
    {
        if (type.Namespace is { } ns &&
            (ns == ForbiddenNamespaceRoot || ns.StartsWith(ForbiddenNamespaceRoot + ".", StringComparison.Ordinal)))
            offenders.Add($"{where}: {type.FullName}");
    }
}
