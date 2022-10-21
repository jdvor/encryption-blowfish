namespace Encryption.Blowfish.Benchmarks;

internal static class Size
{
    public const int K1 = 1024;
    public const int K2 = 2 * K1;
    public const int K4 = 4 * K1;
    public const int K16 = 16 * K1;
    public const int K32 = 2 * K16;
    public const int K64 = 2 * K32;
    public const int K256 = 4 * K64;
    public const int M1 = K1 * K1;
    public const int M10 = 10 * M1;
    public const int G1 = K1 * M1;
}
