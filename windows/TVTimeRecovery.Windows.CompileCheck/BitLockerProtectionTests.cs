using System.ComponentModel;
using System.Diagnostics;

namespace TVTimeRecovery.Windows;

internal static class BitLockerProtectionTests
{
    private static void Require(bool value)
    {
        if (!value) throw new InvalidOperationException("Synthetic protection check failed.");
    }

    public static async Task RunAsync()
    {
        foreach (var input in new[] { "Z:", "z:", "Z:\\" })
            Require(BitLockerProtection.NormalizeDrive(input) == "Z:");
        foreach (var input in new string?[] { null, "", "Z", " Z:", "Z:/", "Z:\\folder", "\\\\host\\share", "Z: -off", "1:", "�:", "Z:\\\\" })
            Require(BitLockerProtection.NormalizeDrive(input) is null);
        foreach (var exit in new[] { 0, 1, 5, -2147024891, -2147024809 })
        {
            var platform = new FakePlatform { ExitCode = exit };
            var result = await new BitLockerStatusQuery(platform).QueryAsync("z:\\", CancellationToken.None);
            Require(result == BitLockerProtection.ClassifyExitCode(exit));
            Require(platform.Calls == 1 && platform.ExactCommand);
        }
        var missing = new FakePlatform { Exists = false };
        Require(await new BitLockerStatusQuery(missing).QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Unverified);
        Require(missing.Calls == 0);
        var remote = new FakePlatform { Fixed = false };
        Require(await new BitLockerStatusQuery(remote).QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Unverified);
        Require(remote.Calls == 0);
        var permission = new FakePlatform { Error = new Win32Exception(1223) };
        Require(await new BitLockerStatusQuery(permission).QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.PermissionCancelled);
        Require(permission.Calls == 1); // No implicit retry after cancelling UAC.

        foreach (var platform in new[]
        {
            new FakePlatform { NullHandle = true },
            new FakePlatform { Completed = false },
            new FakePlatform { Error = new Win32Exception(5) },
            new FakePlatform { ExitReadFails = true },
        })
        {
            var query = new BitLockerStatusQuery(platform);
            Require(await query.QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Uncertain);
            Require(await query.QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Uncertain);
            Require(platform.Calls == 1);
        }
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            var platform = new FakePlatform();
            try { await new BitLockerStatusQuery(platform).QueryAsync("Z:", cancelled.Token); Require(false); }
            catch (OperationCanceledException) { Require(platform.Calls == 0); }
        }
        await RequireLateLaunchIsNeverAccepted(cancel: false);
        await RequireLateLaunchIsNeverAccepted(cancel: true);
    }

    private static async Task RequireLateLaunchIsNeverAccepted(bool cancel)
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var disposed = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var platform = new FakePlatform { Entered = entered, Release = release, Disposed = disposed };
        var query = new BitLockerStatusQuery(platform, cancel ? TimeSpan.FromSeconds(30) : TimeSpan.FromSeconds(2));
        var pending = query.QueryAsync("Z:", cancellation.Token);
        try
        {
            Require(entered.Wait(5000));
            Require(await query.QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Uncertain);
            Require(platform.Calls == 1);
            if (cancel) cancellation.Cancel();
            try
            {
                var result = await pending;
                Require(!cancel && result == BitLockerProtectionStatus.Uncertain);
            }
            catch (OperationCanceledException) { Require(cancel); }
            Require(await query.QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Uncertain);
        }
        finally { release.Set(); }
        Require(await Task.Run(() => disposed.Wait(5000)));
        Require(await query.QueryAsync("Z:", CancellationToken.None) == BitLockerProtectionStatus.Uncertain);
        Require(platform.Calls == 1); // A late protected process never clears uncertainty.
    }

    private sealed class FakePlatform : IBitLockerStatusPlatform
    {
        public string SystemDirectory => @"Z:\Windows\System32";
        public bool Fixed { get; init; } = true;
        public bool Exists { get; init; } = true;
        public bool NullHandle { get; init; }
        public bool Completed { get; init; } = true;
        public bool ExitReadFails { get; init; }
        public int ExitCode { get; init; }
        public Exception? Error { get; init; }
        public ManualResetEventSlim? Entered { get; init; }
        public ManualResetEventSlim? Release { get; init; }
        public ManualResetEventSlim? Disposed { get; init; }
        public int Calls;
        public bool ExactCommand;
        public bool IsFixedDrive(string drive) => Fixed && drive == "Z:";
        public bool ExecutableExists(string executable) => Exists && executable == Path.Combine(SystemDirectory, "manage-bde.exe");
        public IBitLockerStatusProcess? StartElevated(ProcessStartInfo info)
        {
            Interlocked.Increment(ref Calls);
            ExactCommand = info.FileName == Path.Combine(SystemDirectory, "manage-bde.exe") &&
                info.WorkingDirectory == SystemDirectory && info.UseShellExecute && info.Verb == "runas" &&
                !info.RedirectStandardOutput && !info.RedirectStandardError && !info.RedirectStandardInput &&
                info.ArgumentList.SequenceEqual(new[] { "-status", "Z:", "-protectionaserrorlevel" });
            Require(ExactCommand);
            Entered?.Set();
            Release?.Wait();
            if (Error is not null) throw Error;
            return NullHandle ? null : new FakeProcess(this);
        }
    }

    private sealed class FakeProcess(FakePlatform platform) : IBitLockerStatusProcess
    {
        public bool WaitForExit(int milliseconds)
        {
            Require(milliseconds == 10_000);
            return platform.Completed;
        }
        public int ExitCode => platform.ExitReadFails ? throw new InvalidOperationException() : platform.ExitCode;
        public void Dispose() => platform.Disposed?.Set();
    }
}
