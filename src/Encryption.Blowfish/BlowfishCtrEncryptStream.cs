namespace Encryption.Blowfish;

using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

/// <summary>
///
/// </summary>
public sealed class BlowfishCtrEncryptStream : Stream
{
    private const int BlockSize = 8;
    private const int RemainderSize = BlockSize - 1;
    private readonly Stream input;
    private readonly Codec codec;
    private readonly byte[] iv;
    private readonly byte[] nonce;
    private readonly byte[] work;
    private readonly byte[] remainder;
    private int remainderTail;
    private int written;
    private bool disposed;

    // ReSharper disable once InconsistentNaming
    public ImmutableArray<byte> IV => ImmutableArray.Create(iv);

    public long Counter { get; private set; }

    public BlowfishCtrEncryptStream(Stream input, Codec codec, byte[]? iv = null, long counter = 0)
    {
        this.input = input;
        this.codec = codec;
        this.iv = iv ?? RandomNumberGenerator.GetBytes(BlockSize);
        Counter = counter;
        nonce = new byte[BlockSize];
        work = new byte[BlockSize];
        remainder = new byte[RemainderSize];
    }

    public BlowfishCtrEncryptStream(Stream input, byte[] key, byte[]? iv = null, long counter = 0)
        : this(input, new Codec(key), iv, counter)
    {
    }

    public BlowfishCtrEncryptStream(Stream input, string key, byte[]? iv = null, long counter = 0)
        : this(input, Convert.FromHexString(key), iv, counter)
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposed)
        {
            return;
        }

        if (remainderTail > 0)
        {
            var block = remainder.AsSpan(0, remainderTail);
            Crypt(block);
            input.Write(block);
            remainderTail = 0;
            written += remainderTail;
        }

        disposed = true;
        base.Dispose(disposing);
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (count <= 0 || offset < 0 || buffer.Length == 0)
        {
            return;
        }

        Debug.Assert(buffer.Length - offset >= count);

        var effective = buffer.AsSpan(offset, count);
        while (effective.Length >= BlockSize)
        {
            var n = BlockSize;
            if (remainderTail > 0)
            {
                Buffer.BlockCopy(remainder, 0, work, 0, remainderTail);
                n = BlockSize - remainderTail;
                var workTail = work.AsSpan(remainderTail);
                effective[..n].CopyTo(workTail);
                remainderTail = 0;
            }
            else
            {
                effective[..n].CopyTo(work);
            }

            Crypt(work);
            input.Write(work);
            written += BlockSize;

            effective = effective[n..];
        }

        if (effective.Length > 0)
        {
            effective.CopyTo(remainder);
            remainderTail = effective.Length;
        }
    }

    private void Crypt(Span<byte> block)
    {
        BitConverter.TryWriteBytes(nonce, Counter++);
        Xor8(nonce, iv);
        codec.Encrypt(nonce);
        if (block.Length == BlockSize)
        {
            Xor8(block, nonce);
        }
        else
        {
            Xor(block, nonce);
        }
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => 0;

    public override long Position
    {
        get => written;
        set => throw new NotSupportedException();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Xor8(Span<byte> current, ReadOnlySpan<byte> previous)
    {
        current[0] ^= previous[0];
        current[1] ^= previous[1];
        current[2] ^= previous[2];
        current[3] ^= previous[3];
        current[4] ^= previous[4];
        current[5] ^= previous[5];
        current[6] ^= previous[6];
        current[7] ^= previous[7];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Xor(Span<byte> current, ReadOnlySpan<byte> previous)
    {
        for (var i = 0; i < current.Length; i++)
        {
            current[i] ^= previous[i];
        }
    }
}
