namespace Encryption.Blowfish.Tests;

using System.Security.Cryptography;
using Xunit;

public class BlowfishCbcTests
{
    private const string DefaultKey = "a3bd614b27864e3f854b971f9df1a802";

    [Fact]
    public void RejectNonPaddedPayload()
    {
        var sut = new BlowfishCbc(DefaultKey);
        var iv = RandomNumberGenerator.GetBytes(8);
        var buf = new byte[17];
        Assert.False(sut.Encrypt(buf, iv));
    }

    [Fact]
    public void EncryptAndDecrypt()
    {
        var sut = new BlowfishCbc(DefaultKey);
        var (orig, buf) = Util.Payloads(32);
        var iv = RandomNumberGenerator.GetBytes(8);

        var ok = sut.Encrypt(buf, iv);
        Assert.True(ok);

        ok = sut.Decrypt(buf, iv);
        Assert.True(ok);
        Assert.True(Util.IsSame(orig, buf));
    }

    /// <summary>
    /// https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
    /// also Encryption.Blowfish.Tests/test_vectors.txt
    /// </summary>
    [Fact]
    public void SchneierCbcCase()
    {
        // "7654321 Now is the time for " (includes trailing '\0'), length: 29
        var original = Convert.FromHexString("37363534333231204E6F77206973207468652074696D6520666F722000");

        var sut = new BlowfishCbc("0123456789ABCDEFF0E1D2C3B4A59687");
        var iv = Convert.FromHexString("FEDCBA9876543210");
        var data = original.CopyAndPadIfNotAlreadyPadded(); // length: 32

        var ok = sut.Encrypt(data, iv);

        var cipher = Convert.FromHexString("6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC");

        Assert.True(ok);
        Assert.True(Util.IsSame(cipher, data));
    }
}
