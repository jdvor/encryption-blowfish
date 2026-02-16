using BenchmarkDotNet.Running;
using Encryption.Blowfish.Benchmarks;

if (args.Length > 0)
{
    BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}
else
{
    Console.WriteLine("a) Serial vs. Parallel");
    Console.WriteLine("b) Codec Throughput");
    var key = Console.ReadKey();
    switch (key.Key)
    {
        case ConsoleKey.A:
            BenchmarkRunner.Run<SerialVsParallelBench>();
            break;

        case ConsoleKey.B:
            BenchmarkRunner.Run<CodecThroughputBench>();
            break;
    }
}
