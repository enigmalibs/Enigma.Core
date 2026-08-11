using System;
using System.Linq;
using System.Reflection;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// Pins the shape of <see cref="IPublicKeyService"/> after the PEM-string surface was cut: exactly seven
/// members, every key crossing as an <see cref="RsaKey"/>, not one passphrase parameter left, and no
/// <see cref="ObsoleteAttribute"/> shim anywhere on the namespace.
/// </summary>
/// <remarks>
/// These are structural guarantees rather than behaviour, so they are asserted by reflection: a well-meant
/// re-addition of a PEM-string or <c>char[]</c> overload — the exact thing this breaking change removed — would
/// otherwise be caught by nothing.
/// </remarks>
public class PublicKeyServiceSurfaceTests
{
    [Fact]
    public void IPublicKeyService_ExposesExactlyTheSevenSpecifiedMembers()
    {
        var members = typeof(IPublicKeyService).GetMembers()
            .Select(m => m.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "DecryptOaep", "DecryptPkcs1", "EncryptOaep", "EncryptPkcs1",
                "GenerateRsaKey", "Sign", "Verify",
            ],
            members);
    }

    [Fact]
    public void IPublicKeyService_TakesKeysOnlyAsRsaKey_AndNoPassphrase()
    {
        foreach (var method in typeof(IPublicKeyService).GetMethods())
        {
            var parameters = method.GetParameters();

            // The passphrase is supplied once, at RsaKey.ImportPrivateKeyPem, and never on the service.
            Assert.DoesNotContain(parameters, p => p.ParameterType == typeof(char[]));

            // No key arrives as PEM text any more: the only string-typed member would be a resurrected overload.
            Assert.DoesNotContain(parameters, p => p.ParameterType == typeof(string));
            Assert.NotEqual(typeof(string), method.ReturnType);
        }

        // GenerateRsaKey hands out the handle rather than a PEM tuple.
        Assert.Equal(typeof(RsaKey), typeof(IPublicKeyService).GetMethod(nameof(IPublicKeyService.GenerateRsaKey))!.ReturnType);
    }

    [Fact]
    public void NoPublicKeyMember_IsMarkedObsolete()
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance |
                                   BindingFlags.Static | BindingFlags.DeclaredOnly;

        // Nothing was deprecated in place: every removed member was deleted outright, with no compatibility shim.
        foreach (var type in typeof(IPublicKeyService).Assembly.GetExportedTypes()
                     .Where(t => t.Namespace == "Enigma.Core.Asymmetric.PublicKey"))
        {
            Assert.Null(type.GetCustomAttribute<ObsoleteAttribute>());
            Assert.DoesNotContain(type.GetMembers(flags), m => m.GetCustomAttribute<ObsoleteAttribute>() is not null);
        }
    }
}
