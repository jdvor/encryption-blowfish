namespace Encryption.Blowfish.Tests;

using System.Security.Cryptography;
using Xunit;

public class PayloadTests
{
    // [Fact]
    // public void P1()
    // {
    //     var (plain, encrypted) = Util.Payloads(1024 + 7, mustBePadded: false);
    //     var key = Guid.NewGuid().ToByteArray();
    //     var iv = RandomNumberGenerator.GetBytes(8);
    //     var sut = new BlowfishCtr(key);
    //     sut.CryptOrDecrypt(encrypted, iv);
    //     const string path = @"C:\dev\encryption-blowfish\test\Encryption.Blowfish.Tests\payloads\2_ctr.txt";
    //     Util.SavePayload(path, "CTR", key, iv, plain, encrypted, bytesPerLine: 40);
    // }

    [Theory]
    [MemberData(nameof(PayloadPaths))]
    public void ValidatePayload(string path)
    {
        var ok = Util.TryLoadPayload(path, out var mode, out var key, out var iv, out var plain, out var encrypted);
        Assert.True(ok, $"Failed to load payload {path}");

        byte[] encBuf;
        byte[] decBuf;
        switch (mode)
        {
            case "ECB":
                var ecb = new BlowfishEcb(key);

                encBuf = new byte[plain.Length];
                Buffer.BlockCopy(plain, 0, encBuf, 0, plain.Length);
                ok = ecb.Encrypt(encBuf);
                Assert.True(ok);
                Assert.True(Util.IsSame(encrypted, encBuf));

                decBuf = new byte[encrypted.Length];
                Buffer.BlockCopy(encrypted, 0, decBuf, 0, encrypted.Length);
                ok = ecb.Decrypt(decBuf);
                Assert.True(ok);
                Assert.True(Util.IsSame(plain, decBuf));
                break;

            case "CBC":
                var cbc = new BlowfishCbc(key);

                encBuf = new byte[plain.Length];
                Buffer.BlockCopy(plain, 0, encBuf, 0, plain.Length);
                ok = cbc.Encrypt(encBuf, iv);
                Assert.True(ok);
                Assert.True(Util.IsSame(encrypted, encBuf));

                decBuf = new byte[encrypted.Length];
                Buffer.BlockCopy(encrypted, 0, decBuf, 0, encrypted.Length);
                ok = cbc.Decrypt(decBuf, iv);
                Assert.True(ok);
                Assert.True(Util.IsSame(plain, decBuf));
                break;

            case "CTR":
                var ctr = new BlowfishCtr(key);

                encBuf = new byte[plain.Length];
                Buffer.BlockCopy(plain, 0, encBuf, 0, plain.Length);
                ok = ctr.CryptOrDecrypt(encBuf, iv);
                Assert.True(ok);
                Assert.True(Util.IsSame(encrypted, encBuf));

                decBuf = new byte[encrypted.Length];
                Buffer.BlockCopy(encrypted, 0, decBuf, 0, encrypted.Length);
                ok = ctr.CryptOrDecrypt(decBuf, iv);
                Assert.True(ok);
                Assert.True(Util.IsSame(plain, decBuf));
                break;
        }
    }

    public static IEnumerable<object[]> PayloadPaths()
    {
        var files = Directory.EnumerateFiles("payloads", "*.txt", SearchOption.TopDirectoryOnly);
        foreach (var path in files)
        {
            yield return new object[] { path };
        }
    }
}
