#pragma warning disable CA1822

namespace Encryption.Blowfish.Benchmarks;

using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;

[MemoryDiagnoser]
public class CodecThroughputBench
{
    private static readonly Codec Codec = new Codec(Convert.FromHexString("a3bd614b27864e3f854b971f9df1a802"));
    private static readonly byte[] Data = RandomNumberGenerator.GetBytes(8);

    [Benchmark]
    public void Encrypt()
    {
        Codec.Encrypt(Data);
    }

    [Benchmark]
    public void Decrypt()
    {
        Codec.Decrypt(Data);
    }
}
