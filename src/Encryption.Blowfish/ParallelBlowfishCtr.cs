namespace Encryption.Blowfish;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Blowfish in CTR (counter) block mode with parallelization from certain input size.
/// For smaller sizes it will still compute in serial fashion.
/// </summary>
public sealed class ParallelBlowfishCtr
{
    private readonly Codec codec;

    /// <summary>
    /// Payloads lesser than this number will still be computed in serial fashion.
    /// </summary>
    public int MinDataSizeToParallelize { get; init; } = 4096;

    public ParallelBlowfishCtr(Codec codec)
    {
        this.codec = codec;
    }

    public ParallelBlowfishCtr(byte[] key)
        : this(new Codec(key))
    {
    }

    public ParallelBlowfishCtr(string key)
        : this(Convert.FromHexString(key))
    {
    }

    /// <summary>
    /// Encrypt or decrypt data. In CTR mode encrypt and decrypt are the same operation.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <param name="initVector">IV; the length must be exactly 8</param>
    /// <param name="options">options for tweaking scheduler and degree of parallelism</param>
    /// <returns><code>true</code> if data has been encrypted/decrypted; otherwise <code>false</code>.</returns>
    public bool CryptOrDecrypt(byte[] data, byte[] initVector, ParallelOptions? options = null)
    {
        if (data.Length == 0 || initVector.Length != 8)
        {
            return false;
        }

        if (Parallelize(data.Length))
        {
            var opts = options ?? new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };
            return CryptOrDecryptParallel(data, initVector, opts);
        }

        return CryptOrDecryptSerial(data, initVector);
    }

    private bool CryptOrDecryptParallel(byte[] data, byte[] initVector, ParallelOptions options)
    {
        if (data.Length == 0 || initVector.Length != 8)
        {
            return false;
        }

        var nonceBuffer = new ThreadLocal<byte[]>(() => new byte[8]);

        void Crypt(int i)
        {
            var nonce = nonceBuffer.Value.AsSpan();
            BitConverter.TryWriteBytes(nonce, (long)i);
            Xor8(nonce, initVector);
            codec.Encrypt(nonce);
            var index = i * 8;
            var remaining = data.Length - index;
            if (remaining >= 8)
            {
                var block = data.AsSpan(index, 8);
                Xor8(block, nonce);
            }
            else
            {
                var block = data.AsSpan(index, remaining);
                Xor(block, nonce);
            }
        }

        Parallel.For(0, data.Length / 8, options, Crypt);

        return true;
    }

    private bool CryptOrDecryptSerial(Span<byte> data, ReadOnlySpan<byte> initVector)
    {
        if (data.Length == 0 || initVector.Length != 8)
        {
            return false;
        }

        long counter = 0;
        var nonce = new byte[8].AsSpan();
        for (var i = 0; i < data.Length; i += 8)
        {
            BitConverter.TryWriteBytes(nonce, counter++);
            Xor8(nonce, initVector);
            codec.Encrypt(nonce);
            var remaining = data.Length - i;
            if (remaining >= 8)
            {
                var block = data.Slice(i, 8);
                Xor8(block, nonce);
            }
            else
            {
                var block = data.Slice(i, remaining);
                Xor(block, nonce);
            }
        }

        return true;
    }

    private bool Parallelize(int dataSize)
        => Environment.ProcessorCount > 1 && dataSize >= MinDataSizeToParallelize;

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
