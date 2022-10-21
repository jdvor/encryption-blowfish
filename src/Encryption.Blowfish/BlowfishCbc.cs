namespace Encryption.Blowfish;

using System;
using System.Runtime.CompilerServices;

/// <summary>
/// Blowfish in CBC (cipher block chaining) block mode.
/// </summary>
public sealed class BlowfishCbc
{
    private readonly Codec codec;

    public BlowfishCbc(Codec codec)
    {
        this.codec = codec;
    }

    public BlowfishCbc(byte[] key)
     : this(new Codec(key))
    {
    }

    public BlowfishCbc(string key)
        : this(Convert.FromHexString(key))
    {
    }

    /// <summary>
    /// Encrypt data.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <param name="initVector">IV; the length must be exactly 8</param>
    /// <returns><code>true</code> if data has been encrypted; otherwise <code>false</code>.</returns>
    public bool Encrypt(Span<byte> data, ReadOnlySpan<byte> initVector)
    {
        if (Extensions.IsEmptyOrNotPadded(data) || initVector.Length != 8)
        {
            return false;
        }

        var prev = initVector;
        for (var i = 0; i < data.Length; i += 8)
        {
            var block = data.Slice(i, 8);
            Xor(block, prev);
            codec.Encrypt(block);
            prev = block;
        }

        return true;
    }

    /// <summary>
    /// Decrypt data.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <param name="initVector">IV; the length must be exactly 8</param>
    /// <returns><code>true</code> if data has been decrypted; otherwise <code>false</code>.</returns>
    public bool Decrypt(Span<byte> data, ReadOnlySpan<byte> initVector)
    {
        if (Extensions.IsEmptyOrNotPadded(data) || initVector.Length != 8)
        {
            return false;
        }

        var iv = new byte[8].AsSpan();
        initVector.CopyTo(iv);
        var prev = new byte[8].AsSpan();
        for (var i = 0; i < data.Length; i += 8)
        {
            var block = data.Slice(i, 8);
            block.CopyTo(prev);
            codec.Decrypt(block);
            Xor(block, iv);
            prev.CopyTo(iv);
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Xor(Span<byte> current, ReadOnlySpan<byte> previous)
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
}
