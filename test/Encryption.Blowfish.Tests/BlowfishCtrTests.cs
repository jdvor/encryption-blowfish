namespace Encryption.Blowfish.Tests;

using System.Security.Cryptography;
using Xunit;

public class BlowfishCtrTests
{
    private const string DefaultKey = "a3bd614b27864e3f854b971f9df1a802";

    [Fact]
    public void EncryptAndDecrypt()
    {
        var sut = new BlowfishCtr(DefaultKey);
        var (orig, buf) = Util.Payloads(37, mustBePadded: false);
        var iv = RandomNumberGenerator.GetBytes(8);

        var ok = sut.CryptOrDecrypt(buf, iv);
        Assert.True(ok);

        ok = sut.CryptOrDecrypt(buf, iv);
        Assert.True(ok);
        Assert.True(Util.IsSame(orig, buf));
    }
}
