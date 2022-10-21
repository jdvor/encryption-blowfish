namespace Encryption.Blowfish.Tests;

using Xunit;

public class BlowfishEcbTests
{
    private const string DefaultKey = "a3bd614b27864e3f854b971f9df1a802";

    [Fact]
    public void RejectNonPaddedPayload()
    {
        var sut = new BlowfishEcb(DefaultKey);
        var buf = new byte[17];
        Assert.False(sut.Encrypt(buf));
    }

    [Fact]
    public void EncryptAndDecrypt()
    {
        var sut = new BlowfishEcb(DefaultKey);
        var (orig, buf) = Util.Payloads(24);

        var ok = sut.Encrypt(buf);
        Assert.True(ok);

        ok = sut.Decrypt(buf);
        Assert.True(ok);
        Assert.True(Util.IsSame(orig, buf));
    }
}
