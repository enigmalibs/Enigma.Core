using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Enigma.Core;
using Xunit;

namespace Enigma.Core.UnitTests.Api;

/// <summary>
/// Principle 1 — no BouncyCastle type may appear on the public surface of <c>Enigma.Core</c>. Now
/// that the library references <c>BouncyCastle.Cryptography</c>, this reflection guard is the
/// load-bearing guarantee for every downstream restoration: it walks every exported type and its
/// public/protected members and fails if any return type, parameter type, field/property/event type,
/// base type, implemented interface, or generic type argument lives in an <c>Org.BouncyCastle.*</c>
/// namespace. (Property and event types are covered transitively through their accessor methods.)
/// </summary>
public class BouncyCastleIsolationTests
{
    private const string ForbiddenNamespaceRoot = "Org.BouncyCastle";

    [Fact]
    public void NoExportedMember_ExposesBouncyCastleType()
    {
        var assembly = typeof(CryptoDefaults).Assembly;
        var offenders = new List<string>();

        foreach (var type in assembly.GetExportedTypes())
        {
            // Base type, implemented interfaces, and the type's own generic arguments.
            foreach (var referenced in ReferencedTypes(type.BaseType)
                         .Concat(type.GetInterfaces().SelectMany(ReferencedTypes)))
                Check(offenders, referenced, $"{type.FullName} (base/interface)");

            const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic |
                                       BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

            // Methods (includes property/event accessors) — return + parameter types.
            foreach (var method in type.GetMethods(flags).Where(IsExposed))
            {
                foreach (var t in ReferencedTypes(method.ReturnType))
                    Check(offenders, t, $"{type.FullName}.{method.Name} (return)");
                foreach (var t in method.GetParameters().SelectMany(p => ReferencedTypes(p.ParameterType)))
                    Check(offenders, t, $"{type.FullName}.{method.Name} (parameter)");
            }

            // Constructors — parameter types.
            foreach (var ctor in type.GetConstructors(flags).Where(IsExposed))
                foreach (var t in ctor.GetParameters().SelectMany(p => ReferencedTypes(p.ParameterType)))
                    Check(offenders, t, $"{type.FullName}.ctor (parameter)");

            // Fields — field types.
            foreach (var field in type.GetFields(flags).Where(IsExposed))
                foreach (var t in ReferencedTypes(field.FieldType))
                    Check(offenders, t, $"{type.FullName}.{field.Name} (field)");
        }

        Assert.True(offenders.Count == 0,
            "BouncyCastle types leaked onto the public surface:" + Environment.NewLine +
            string.Join(Environment.NewLine, offenders));
    }

    // Public or protected (family / family-or-assembly) — the surface visible to external callers
    // and inheritors. Private and internal-only members are not part of the exported contract.
    private static bool IsExposed(MethodBase m) => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly;
    private static bool IsExposed(FieldInfo f) => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly;

    // Unwrap arrays / by-ref / pointers to their element type, and recurse into generic arguments.
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
