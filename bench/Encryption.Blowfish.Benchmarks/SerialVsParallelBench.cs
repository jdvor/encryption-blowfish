#pragma warning disable CA1822

namespace Encryption.Blowfish.Benchmarks;

using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;
using static Encryption.Blowfish.Benchmarks.Size;

[MemoryDiagnoser]
public class SerialVsParallelBench
{
    private static readonly string Key = Util.RndKey();
    private readonly BlowfishEcb serialEcb = new BlowfishEcb(Key);
    private readonly ParallelBlowfishEcb paraEcb = new ParallelBlowfishEcb(Key);
    private readonly BlowfishCtr serialCtr = new BlowfishCtr(Key);
    private readonly ParallelBlowfishCtr paraCtr = new ParallelBlowfishCtr(Key);
    private readonly byte[] iv = RandomNumberGenerator.GetBytes(8);
    private byte[] data = Array.Empty<byte>();

    [Params(24, K2, K4, M1)]
    // ReSharper disable once UnusedAutoPropertyAccessor.Global
    public int N { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        data = Util.Payload(N);
    }

    [Benchmark(Description = "serial ECB encrypt")]
    public void SerialEcbEncrypt()
        => serialEcb.Encrypt(data);

    [Benchmark(Description = "serial ECB decrypt")]
    public void SerialEcbDecrypt()
        => serialEcb.Decrypt(data);

    [Benchmark(Description = "serial CTR")]
    public void SerialCtr()
        => serialCtr.CryptOrDecrypt(data, iv);

    [Benchmark(Description = "parallel ECB encrypt")]
    public void ParallelEcbEncrypt()
        => paraEcb.Encrypt(data);

    [Benchmark(Description = "parallel ECB decrypt")]
    public void ParallelEcbDecrypt()
        => paraEcb.Decrypt(data);

    [Benchmark(Description = "parallel CTR")]
    public void ParallelCtr()
        => paraCtr.CryptOrDecrypt(data, iv);
}
