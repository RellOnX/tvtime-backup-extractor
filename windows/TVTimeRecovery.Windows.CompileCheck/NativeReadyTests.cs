using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace TVTimeRecovery.Windows;

// Cloud-only fixtures compiled with this test program. Never invokes the packaged helper.
internal static class NativeReadyTests
{
    private const string Prefix = "SyntheticReady-";
    private const string Ready = "{\"protocolVersion\":3,\"sequence\":1,\"type\":\"ready\",\"payload\":{\"helperVersion\":\"0.3.1a1\",\"minimumProtocolVersion\":3,\"maximumProtocolVersion\":3,\"capabilities\":[\"preflight\",\"recover\",\"cancel\",\"destination-parent-fd\",\"windows-inherited-handles\",\"source-receipt-v1\",\"source-neutral-acquisition-v1\"]}}";

    public static int? TryRunFixture()
    {
        var name = Path.GetFileNameWithoutExtension(Environment.ProcessPath);
        if (name is null || !name.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var mode = name[Prefix.Length..];
        if (mode == "early") return 23;
        if (mode == "partial") { Console.Write("{\"protocolVersion\":3"); Console.Out.Flush(); }
        if (mode is "silent" or "partial" or "late")
        {
            Thread.Sleep(60_000);
            if (mode == "late") Console.WriteLine(Ready);
            return 24;
        }
        if (mode != "valid") return 25;
        Console.WriteLine(Ready);
        Console.Out.Flush();
        using var input = Console.OpenStandardInput();
        var header = new byte[4];
        input.ReadExactly(header);
        var size = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (size != 18) return 26;
        var request = new byte[(int)size];
        input.ReadExactly(request);
        if (Encoding.UTF8.GetString(request) != "{\"synthetic\":true}") return 27;
        Console.WriteLine("{\"protocolVersion\":3,\"sequence\":2,\"type\":\"completed\",\"payload\":{}}");
        return 0;
    }

    public static async Task RunAsync(string temporaryRoot)
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException();
        if (!executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException();
        foreach (var mode in new[] { "early", "silent", "partial", "late", "valid" })
        {
            var alias = Path.Combine(Path.GetDirectoryName(executable)!, Prefix + mode + ".exe");
            File.Copy(executable, alias, overwrite: false);
            try
            {
                await using var helper = NativeHelperProcess.Start(alias, temporaryRoot, TimeSpan.FromSeconds(2));
                if (mode == "valid")
                {
                    await helper.WaitForReadyAsync("preflight", CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
                    // Valid readiness removes the startup timer; real work may be quiet indefinitely.
                    await Task.Delay(2_500);
                    if (helper.HasExited) throw new InvalidOperationException("Quiet ready child was killed.");
                    await helper.SendControlAsync(Encoding.UTF8.GetBytes("{\"synthetic\":true}"), CancellationToken.None);
                    var count = 0;
                    using var eventBudget = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await foreach (var item in helper.EventsAsync(eventBudget.Token))
                    {
                        using (item) { if (item.RootElement.GetProperty("type").GetString() != "completed") throw new InvalidOperationException(); }
                        count++;
                    }
                    if (count != 1) throw new InvalidOperationException();
                    await helper.WaitForSuccessfulExitAsync();
                }
                else
                {
                    try
                    {
                        await helper.WaitForReadyAsync("preflight", CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
                        throw new InvalidOperationException("Invalid fixture became ready.");
                    }
                    catch (RecoveryUserException) { }
                    await RequireExitAsync(helper);
                }
            }
            finally { File.Delete(alias); }
        }
        var cancelAlias = Path.Combine(Path.GetDirectoryName(executable)!, Prefix + "silent.exe");
        File.Copy(executable, cancelAlias, overwrite: false);
        try
        {
            await using var helper = NativeHelperProcess.Start(cancelAlias, temporaryRoot, TimeSpan.FromSeconds(10));
            using var cancel = new CancellationTokenSource(250);
            try { await helper.WaitForReadyAsync("preflight", cancel.Token).WaitAsync(TimeSpan.FromSeconds(10)); throw new InvalidOperationException(); }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
            await RequireExitAsync(helper);
        }
        finally { File.Delete(cancelAlias); }
        Console.WriteLine("Native synthetic child readiness, quiet work, cancellation and Job Object cleanup passed.");
    }

    private static async Task RequireExitAsync(NativeHelperProcess helper)
    {
        var timer = Stopwatch.StartNew();
        while (!helper.HasExited && timer.Elapsed < TimeSpan.FromSeconds(3)) await Task.Delay(25);
        if (!helper.HasExited) throw new InvalidOperationException("Owned synthetic child survived failed startup.");
    }
}
