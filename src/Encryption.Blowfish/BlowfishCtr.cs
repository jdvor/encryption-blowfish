namespace Encryption.Blowfish;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Blowfish in CTR (counter) block mode.
/// </summary>
public sealed class BlowfishCtr
{
    private readonly Codec codec;

    public BlowfishCtr(Codec codec)
    {
        this.codec = codec;
    }

    public BlowfishCtr(byte[] key)
        :this(new Codec(key))
    {
    }

    public BlowfishCtr(string key)
        : this(Convert.FromHexString(key))
    {
    }

    /// <summary>
    /// Encrypt or decrypt data. In CTR mode encrypt and decrypt are the same operation.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <param name="initVector">IV; the length must be exactly 8</param>
    /// <param name="counter">initial counter value</param>
    /// <returns><code>true</code> if data has been encrypted/decrypted; otherwise <code>false</code>.</returns>
    public bool CryptOrDecrypt(Span<byte> data, ReadOnlySpan<byte> initVector, long counter = 0)
    {
        if (data.Length == 0 || initVector.Length != 8)
        {
            return false;
        }

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
