using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Enigma.Core.KeyDerivation;
using Xunit;

namespace Enigma.Core.UnitTests.KeyDerivation;

/// <summary>
/// Principle 1, scoped to the KeyDerivation surface: <see cref="Pbkdf2Service"/> and
/// <see cref="Argon2Service"/> drive BouncyCastle's PBKDF2/Argon2 generators, digests and parameter
/// builders internally, so this guard proves the backend never leaks. It walks every exported type in
/// the <c>Enigma.Core.KeyDerivation</c> namespace and fails if any <c>Org.BouncyCastle.*</c> type
/// appears on a base type, implemented interface, exposed method return/parameter, constructor
/// parameter, or exposed field. (The assembly-wide <c>BouncyCastleIsolationTests</c> covers the same
/// property for the whole surface; this ties the guarantee to the KeyDerivation acceptance criterion.)
/// </summary>
public class KeyDerivationBouncyCastleIsolationTests
{
    private const string ForbiddenNamespaceRoot = "Org.BouncyCastle";

    private const string KeyDerivationNamespace = "Enigma.Core.KeyDerivation";

    [Fact]
    public void NoKeyDerivationType_ExposesBouncyCastleType()
    {
        var keyDerivationTypes = typeof(IPbkdf2Service).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == KeyDerivationNamespace)
            .ToList();

        // Sanity: the reflection scope actually found the KeyDerivation surface.
        Assert.Contains(typeof(Pbkdf2Service), keyDerivationTypes);
        Assert.Contains(typeof(Pbkdf2ServiceFactory), keyDerivationTypes);
        Assert.Contains(typeof(Argon2Service), keyDerivationTypes);
        Assert.Contains(typeof(Argon2ServiceFactory), keyDerivationTypes);

        var offenders = new List<string>();

        foreach (var type in keyDerivationTypes)
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
            "BouncyCastle types leaked onto the KeyDerivation public surface:" + Environment.NewLine +
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
