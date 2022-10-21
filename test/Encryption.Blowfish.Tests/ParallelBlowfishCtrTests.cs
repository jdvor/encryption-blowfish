namespace Encryption.Blowfish.Tests;

using System.Security.Cryptography;
using Xunit;

public class ParallelBlowfishCtrTests
{
    private const string DefaultKey = "a3bd614b27864e3f854b971f9df1a802";

    [Fact]
    public void AcceptsNonPaddedPayload()
    {
        var sut = new ParallelBlowfishCtr(DefaultKey);
        var buf = new byte[17];
        var iv = RandomNumberGenerator.GetBytes(8);
        Assert.True(sut.CryptOrDecrypt(buf, iv));
    }

    [Fact]
    public void EncryptAndDecrypt()
    {
        const int n = 1024;
        var sut = new ParallelBlowfishCtr(DefaultKey) { MinDataSizeToParallelize = n };
        var (orig, buf) = Util.Payloads(n);
        var iv = RandomNumberGenerator.GetBytes(8);

        var ok = sut.CryptOrDecrypt(buf, iv);
        Assert.True(ok);

        ok = sut.CryptOrDecrypt(buf, iv);
        Assert.True(ok);
        Assert.True(Util.IsSame(orig, buf));
    }
}
