using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// A pass-through <see cref="Stream"/> that forwards every operation to an inner stream but does
/// <b>not</b> dispose it. BouncyCastle's <c>CipherStream</c> unconditionally disposes the stream it
/// wraps (it has no <c>leaveOpen</c> option), which would close the caller-supplied input/output stream.
/// Wrapping the caller's stream in this adapter keeps the standard .NET convention — the service never
/// takes ownership of a stream it did not create — while still letting <c>CipherStream</c> flush the
/// final block/tag through to the underlying stream on disposal.
/// </summary>
internal sealed class NonDisposingStreamWrapper : Stream
{
    private readonly Stream _inner;

    public NonDisposingStreamWrapper(Stream inner) => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

    public override void SetLength(long value) => _inner.SetLength(value);

    // The whole point: swallow disposal so the inner (caller-owned) stream stays open.
    protected override void Dispose(bool disposing)
    {
        // Intentionally does not dispose _inner.
    }
}
