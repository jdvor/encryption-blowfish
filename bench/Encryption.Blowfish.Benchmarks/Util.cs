namespace Encryption.Blowfish.Benchmarks;

using System;

internal static class Util
{
    internal static string RndKey()
        => Guid.NewGuid().ToString("N");

    internal static byte[] Payload(int n, bool mustBePadded = true)
    {
        if (mustBePadded && n % 8 != 0)
        {
            throw new ArgumentException("n must be multiple of 8", nameof(n));
        }

        var payload = new byte[n];
        for (var i = 0; i < n; i++)
        {
            payload[i] = (byte)(i % 256);
        }

        return payload;
    }
}
