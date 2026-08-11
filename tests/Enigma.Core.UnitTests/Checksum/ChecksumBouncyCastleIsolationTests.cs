using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Enigma.Core.Checksum;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// Principle 1, scoped to <c>Enigma.Core.Checksum</c>: the CRC engine is hand-written and references
/// BouncyCastle nowhere at all, so this guard is trivially satisfied today. It is here to keep it
/// that way — it walks every exported type in the <c>Enigma.Core.Checksum</c> namespace and fails if
/// any <c>Org.BouncyCastle.*</c> type appears on a base type, implemented interface, exposed method
/// return/parameter, constructor parameter, or exposed field. (The assembly-wide
/// <c>BouncyCastleIsolationTests</c> covers the same property for the whole surface; this one ties
/// the guarantee directly to the Checksum acceptance criterion.)
/// </summary>
public class ChecksumBouncyCastleIsolationTests
{
    private const string ForbiddenNamespaceRoot = "Org.BouncyCastle";
    private const string ChecksumNamespace = "Enigma.Core.Checksum";

    [Fact]
    public void NoChecksumType_ExposesBouncyCastleType()
    {
        var checksumTypes = typeof(IChecksumService).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == ChecksumNamespace)
            .ToList();

        // Sanity: the reflection scope actually found the Checksum surface.
        Assert.Contains(typeof(Crc16Service), checksumTypes);
        Assert.Contains(typeof(Crc32Service), checksumTypes);
        Assert.Contains(typeof(ChecksumServiceFactory), checksumTypes);

        var offenders = new List<string>();

        foreach (var type in checksumTypes)
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
            "BouncyCastle types leaked onto the Checksum public surface:" + Environment.NewLine +
            string.Join(Environment.NewLine, offenders));
    }

    // The engine's parameter sets and lookup tables are implementation detail: a consumer must not be
    // able to construct a checksum service except through the factory.
    [Fact]
    public void ChecksumInternals_AreNotExported()
    {
        var exported = typeof(IChecksumService).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == ChecksumNamespace)
            .Select(t => t.Name)
            .ToList();

        Assert.DoesNotContain("CrcParameters", exported);
        Assert.DoesNotContain("CrcTable", exported);

        Assert.Empty(typeof(Crc16Service).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(Crc32Service).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
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
