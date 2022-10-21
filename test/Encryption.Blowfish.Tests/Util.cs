namespace Encryption.Blowfish.Tests;

using System;
using System.Text;
using System.Text.RegularExpressions;

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

    internal static (byte[], byte[]) Payloads(int n, bool mustBePadded = true)
    {
        var p1 = Payload(n, mustBePadded);
        var p2 = new byte[n];
        p1.CopyTo(p2.AsSpan());
        return (p1, p2);
    }

    internal static bool IsSame(Span<byte> a, Span<byte> b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    internal static void SavePayload(
        string path, string mode, byte[] key, byte[] iv, Span<byte> plain, Span<byte> encrypted, int bytesPerLine = 8)
    {
        using var w = new StreamWriter(path, false, Encoding.ASCII);
        w.WriteLine($"Mode: {mode}");
        w.WriteLine($"Key: {Convert.ToHexString(key)}");
        var ivStr = iv is not null && iv.Length > 0 ? Convert.ToHexString(iv) : string.Empty;
        w.WriteLine($"IV: {ivStr}");
        w.WriteLine($"--- plain ({plain.Length}) ---");
        w.Write(plain.ToHexString(bytesPerLine: bytesPerLine));
        w.WriteLine($"--- encrypted ({encrypted.Length}) ---");
        w.Write(encrypted.ToHexString(bytesPerLine: bytesPerLine));
        w.Flush();
    }

    private static readonly Regex HeaderRgx
        = new Regex(@"^--- (plain|encrypted) \((?<length>\d+)\) ---$", RegexOptions.Compiled);

    internal static bool TryLoadPayload(
        string path, out string mode, out byte[] key, out byte[] iv, out byte[] plain, out byte[] encrypted)
    {
        static (bool, int) IsHeader(string line)
        {
            if (line is not null && line.StartsWith('-'))
            {
                var m = HeaderRgx.Match(line);
                if (m.Success)
                {
                    var length = int.Parse(m.Groups["length"].Value);
                    return (length > 0, length);
                }

            }

            return (false, 0);
        }

        try
        {
            using var r = new StreamReader(path, Encoding.ASCII, false);

            // mode
            var line = r.ReadLine();
            mode = line![6..].Trim();

            // key
            line = r.ReadLine();
            var keyStr = line![5..].Trim();
            key = Convert.FromHexString(keyStr);

            // IV
            line = r.ReadLine();
            var ivStr = line![4..].Trim();
            iv = string.IsNullOrEmpty(ivStr) ? Array.Empty<byte>() : Convert.FromHexString(ivStr);

            // plain header
            line = r.ReadLine();
            var (ok, length) = IsHeader(line);
            if (!ok)
            {
                throw new Exception();
            }

            plain = Array.Empty<byte>();
            encrypted = Array.Empty<byte>();
            var pos = 0;
            var buffer = new byte[length];

            while ((line = r.ReadLine()) != null)
            {
                (ok, length) = IsHeader(line);
                if (ok)
                {
                    // encrypted header
                    plain = buffer;
                    pos = 0;
                    buffer = new byte[length];
                    continue;
                }

                var lineBytes = Convert.FromHexString(line);
                Buffer.BlockCopy(lineBytes, 0, buffer, pos, lineBytes.Length);
                pos += lineBytes.Length;
            }

            if (plain.Length > 0)
            {
                encrypted = buffer;
            }

            return plain.Length > 0 && encrypted.Length > 0;
        }
        catch
        {
            mode = string.Empty;
            key = Array.Empty<byte>();
            iv = Array.Empty<byte>();
            plain = Array.Empty<byte>();
            encrypted = Array.Empty<byte>();
            return false;
        }
    }
}
