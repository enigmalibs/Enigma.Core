using System;

namespace Enigma.Core.UnitTests.Infrastructure;

/// <summary>
/// Synchronous <see cref="IProgress{T}"/> implementation that reports values inline on the calling
/// thread, so progress-reporting assertions in tests are deterministic. Reusable scaffolding; the
/// module tests that consume it (Hash, BlockCipher progress/cancellation) arrive with those features.
/// </summary>
internal sealed class SyncProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}
