using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// Differential tests: the shipped table-driven engine against the independent
/// <see cref="BitwiseCrcOracle"/>, over every variant and a spread of input lengths that brackets the
/// default 4096-byte read buffer. Also proves one-shot and streamed results agree, including when the
/// stream hands back short reads.
/// </summary>
public class ChecksumFuzzTests
{
    // 0 and 1 are the degenerate cases; 4095/4096/4097 bracket the default read buffer, where an
    // off-by-one in the chunk fold would show; 12289 forces three buffers plus a remainder.
    private static readonly int[] Lengths = [0, 1, 7, 255, 4095, 4096, 4097, 8192, 12289];

    public static TheoryData<string> Variants()
    {
        var data = new TheoryData<string>();
        foreach (var variant in ChecksumVariants.All)
            data.Add(variant);
        return data;
    }

    // Guards the guard: if the oracle itself were wrong, the parity tests below would happily agree
    // with a broken engine.
    [Theory]
    [MemberData(nameof(Variants))]
    public void Oracle_ReproducesPublishedCheckValue(string variant)
    {
        var expected = ChecksumVariants.CheckValue(variant);

        Assert.Equal(expected, BitwiseCrcOracle.For(variant).Compute(ChecksumVariants.CheckInput()));
    }

    [Theory]
    [MemberData(nameof(Variants))]
    public void TableEngine_MatchesBitwiseOracle_AcrossLengths(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        var oracle = BitwiseCrcOracle.For(variant);

        foreach (var length in Lengths)
        {
            var data = RandomBytes(length);

            Assert.Equal(oracle.Compute(data), service.ComputeChecksumValue(data));
        }
    }

    [Theory]
    [MemberData(nameof(Variants))]
    public async Task Streamed_MatchesOneShot_AcrossLengths(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        foreach (var length in Lengths)
        {
            var data = RandomBytes(length);
            using var input = new MemoryStream(data);

            var streamed = await service.ComputeChecksumValueAsync(
                input, cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(service.ComputeChecksumValue(data), streamed);
        }
    }

    // A stream that never fills the buffer forces the fold across chunk boundaries that no single
    // 4096-byte read would exercise.
    [Theory]
    [MemberData(nameof(Variants))]
    public async Task ShortReadStream_MatchesOneShot_AcrossLengths(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        foreach (var length in Lengths)
        {
            var data = RandomBytes(length);
            using var input = new ShortReadStream(data, maxRead: 3);

            var streamed = await service.ComputeChecksumValueAsync(
                input, cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(service.ComputeChecksumValue(data), streamed);
        }
    }

    // A read buffer far smaller than the input must not change the result — bufferSize is an I/O
    // knob, never a parameter of the checksum.
    [Theory]
    [MemberData(nameof(Variants))]
    public async Task SmallBufferSize_MatchesDefaultBufferSize(string variant)
    {
        var data = RandomBytes(12289);
        var expected = ChecksumVariants.Create(variant).ComputeChecksumValue(data);

        foreach (var bufferSize in new[] { 1, 7, 64 })
        {
            var service = ChecksumVariants.Create(variant, bufferSize);
            using var input = new MemoryStream(data);

            var streamed = await service.ComputeChecksumValueAsync(
                input, cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(expected, streamed);
        }
    }

    // RandomUtils rejects a zero length, and an empty input is one of the cases under test.
    private static byte[] RandomBytes(int length) => length == 0 ? [] : RandomUtils.GenerateRandomBytes(length);

    /// <summary>
    /// A read-only stream that returns at most <c>maxRead</c> bytes per read, however large the
    /// caller's buffer is — the behaviour of a network or compression stream.
    /// </summary>
    private sealed class ShortReadStream(byte[] data, int maxRead) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var toCopy = Math.Min(Math.Min(count, maxRead), data.Length - _position);
            Array.Copy(data, _position, buffer, offset, toCopy);
            _position += toCopy;
            return toCopy;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
