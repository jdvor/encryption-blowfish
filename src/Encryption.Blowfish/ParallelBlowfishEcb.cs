namespace Encryption.Blowfish;

using System;

/// <summary>
/// Blowfish in ECB (electronic codebook) block mode with parallelization from certain input size.
/// For smaller sizes it will still compute in serial fashion.
/// </summary>
public sealed class ParallelBlowfishEcb
{
    private readonly Codec codec;

    /// <summary>
    /// Payloads lesser than this number will still be computed in serial fashion.
    /// </summary>
    public int MinDataSizeToParallelize { get; init; } = 4096;

    public ParallelBlowfishEcb(Codec codec)
    {
        this.codec = codec;
    }

    public ParallelBlowfishEcb(byte[] key)
        : this(new Codec(key))
    {
    }

    public ParallelBlowfishEcb(string key)
        : this(Convert.FromHexString(key))
    {
    }

    private bool Parallelize(int dataSize)
        => Environment.ProcessorCount > 1 && dataSize >= MinDataSizeToParallelize;

    /// <summary>
    /// Encrypt data.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <param name="options">options for tweaking scheduler and degree of parallelism</param>
    /// <returns><code>true</code> if data has been encrypted; otherwise <code>false</code>.</returns>
    public bool Encrypt(byte[] data, ParallelOptions? options = null)
    {
        if (Extensions.IsEmptyOrNotPadded(data))
        {
            return false;
        }

        if (Parallelize(data.Length))
        {
            var opts = options ?? new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };
            Parallel.For(0, data.Length / 8, opts, i => codec.Encrypt(data.AsSpan(i * 8, 8)));
        }
        else
        {
            for (var i = 0; i < data.Length; i += 8)
            {
                var block = data.AsSpan(i, 8);
                codec.Encrypt(block);
            }
        }

        return true;
    }

    /// <summary>
    /// Decrypt data.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <param name="options">options for tweaking scheduler and degree of parallelism</param>
    /// <returns><code>true</code> if data has been decrypted; otherwise <code>false</code>.</returns>
    public bool Decrypt(byte[] data, ParallelOptions? options = null)
    {
        if (Extensions.IsEmptyOrNotPadded(data))
        {
            return false;
        }

        if (Parallelize(data.Length))
        {
            var opts = options ?? new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };
            Parallel.For(0, data.Length / 8, opts, i => codec.Decrypt(data.AsSpan(i * 8, 8)));
        }
        else
        {
            for (var i = 0; i < data.Length; i += 8)
            {
                var block = data.AsSpan(i, 8);
                codec.Decrypt(block);
            }
        }

        return true;
    }
}
