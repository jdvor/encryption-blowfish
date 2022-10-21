namespace Encryption.Blowfish;

using System;

/// <summary>
/// Blowfish in ECB (electronic codebook) block mode.
/// </summary>
public sealed class BlowfishEcb
{
    private readonly Codec codec;

    public BlowfishEcb(Codec codec)
    {
        this.codec = codec;
    }

    public BlowfishEcb(byte[] key)
        : this(new Codec(key))
    {
    }

    public BlowfishEcb(string key)
        : this(Convert.FromHexString(key))
    {
    }

    /// <summary>
    /// Encrypt data.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <returns><code>true</code> if data has been encrypted; otherwise <code>false</code>.</returns>
    public bool Encrypt(Span<byte> data)
    {
        if (Extensions.IsEmptyOrNotPadded(data))
        {
            return false;
        }

        for (var i = 0; i < data.Length; i += 8)
        {
            var block = data.Slice(i, 8);
            codec.Encrypt(block);
        }

        return true;
    }

    /// <summary>
    /// Decrypt data.
    /// </summary>
    /// <param name="data">the length must be in multiples of 8</param>
    /// <returns><code>true</code> if data has been decrypted; otherwise <code>false</code>.</returns>
    public bool Decrypt(Span<byte> data)
    {
        if (Extensions.IsEmptyOrNotPadded(data))
        {
            return false;
        }

        for (var i = 0; i < data.Length; i += 8)
        {
            var block = data.Slice(i, 8);
            codec.Decrypt(block);
        }

        return true;
    }
}
