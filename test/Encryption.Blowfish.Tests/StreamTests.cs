namespace Encryption.Blowfish.Tests;

using System.Security.Cryptography;
using Xunit;

public class StreamTests
{
    private const string DefaultKey = "a3bd614b27864e3f854b971f9df1a802";
    private static readonly Codec Codec = new Codec(Convert.FromHexString(DefaultKey));

    [Fact]
    public void SingleUnpaddedWrite()
    {
        const int n = 50;
        var buf = Util.Payload(n, mustBePadded: false);
        using var ms = new MemoryStream();
        using (var bf = new BlowfishCtrEncryptStream(ms, Codec))
        {
            bf.Write(buf);
        }

        Assert.Equal(n, ms.Position);
    }

    [Fact]
    public void SinglePaddedWrite()
    {
        const int n = 128;
        var buf = Util.Payload(n);
        using var ms = new MemoryStream();
        using (var bf = new BlowfishCtrEncryptStream(ms, Codec))
        {
            bf.Write(buf);
        }

        Assert.Equal(n, ms.Position);
    }

    [Fact]
    public void SeveralPaddedAndUnpaddedWrites()
    {
        const int n = 259;
        var writes = new[]
        {
            (0, 17),
            (17, 23),
            (40, 128),
            (128, 1),
            (129, 90),
        };

        var orig = Util.Payload(n, mustBePadded: false);
        using var ms = new MemoryStream();
        using (var bf = new BlowfishCtrEncryptStream(ms, Codec))
        {
            foreach (var (offset, count) in writes)
            {
                bf.Write(orig, offset, count);
            }
        }

        Assert.Equal(n, ms.Position);
    }

    [Fact]
    public void EncryptAndDecrypt()
    {
        const int n = 131;
        var orig = Util.Payload(n, mustBePadded: false);
        var iv = RandomNumberGenerator.GetBytes(8);
        const long counter = 0L;

        using var enc = new MemoryStream();
        using (var bfe = new BlowfishCtrEncryptStream(enc, Codec, iv, counter))
        {
            bfe.Write(orig);
        }

        enc.Position = 0;

        using var dec = new MemoryStream();
        using var bfd = new BlowfishCtrDecryptStream(enc, Codec, iv, counter);
        bfd.CopyTo(dec);

        var decrypted = dec.ToArray();
        Assert.True(Util.IsSame(orig, decrypted));
    }
}
