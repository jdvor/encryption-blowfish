namespace Encryption.Blowfish;

using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

/// <summary>
///
/// </summary>
public sealed class BlowfishCtrDecryptStream : Stream
{
    private const int BlockSize = 8;
    private readonly Stream input;
    private readonly Codec codec;
    private readonly byte[] iv;
    private readonly byte[] nonce;
    private readonly byte[] work;
    private int read;

    public long Counter { get; private set; }

    public BlowfishCtrDecryptStream(Stream input, Codec codec, byte[] iv, long counter = 0)
    {
        this.input = input;
        this.codec = codec;
        this.iv = iv;
        Counter = counter;
        nonce = new byte[BlockSize];
        work = new byte[BlockSize];
    }

    public BlowfishCtrDecryptStream(Stream input, byte[] key, byte[] iv, long counter = 0)
        : this(input, new Codec(key), iv, counter)
    {
    }

    public BlowfishCtrDecryptStream(Stream input, string key, byte[] iv, long counter = 0)
        : this(input, Convert.FromHexString(key), iv, counter)
    {
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (offset < 0 || count <= 0 || buffer.Length == 0)
        {
            return 0;
        }

        if (count % BlockSize != 0)
        {
            throw new ArgumentException("requested read must have length in multiples of 8", nameof(count));
        }

        Debug.Assert(buffer.Length - offset >= count);

        var totalBytesRead = 0;
        for (var i = offset; i < offset + count; i += BlockSize)
        {
            Array.Fill(work, (byte)0, 0, work.Length);
            var bytesRead = input.Read(work, 0, work.Length);
            totalBytesRead += bytesRead;
            Crypt(work);
            Buffer.BlockCopy(work, 0, buffer, i, bytesRead);

            if (bytesRead < BlockSize)
            {
                break;
            }
        }

        read += totalBytesRead;
        return totalBytesRead;
    }

    public new void CopyTo(Stream output)
        => CopyTo(output, 4096);

    public new void CopyTo(Stream output, int bufferSize)
    {
        if (bufferSize < 8 || bufferSize % BlockSize != 0)
        {
            throw new ArgumentException("requested read must have length in multiples of 8", nameof(bufferSize));
        }

        var pool = ArrayPool<byte>.Shared;
        var buffer = pool.Rent(bufferSize);
        try
        {
            int bytesRead;
            while ((bytesRead = Read(buffer, 0, bufferSize)) > 0)
            {
                output.Write(buffer, 0, bytesRead);
            }
        }
        finally
        {
            pool.Return(buffer);
        }

    }

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();

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

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => 0;

    public override long Position
    {
        get => read;
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
