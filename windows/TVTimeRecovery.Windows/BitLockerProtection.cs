using System.ComponentModel;
using System.Diagnostics;

namespace TVTimeRecovery.Windows;

internal enum BitLockerProtectionStatus
{
    Protected,
    Unprotected,
    Unverified,
    PermissionCancelled,
    Uncertain,
}

// Test seam: synthetic implementations never need to launch a process or request UAC.
internal interface IBitLockerStatusProcess : IDisposable
{
    bool WaitForExit(int milliseconds);
    int ExitCode { get; }
}

internal interface IBitLockerStatusPlatform
{
    string SystemDirectory { get; }
    bool IsFixedDrive(string drive);
    bool ExecutableExists(string executable);
    IBitLockerStatusProcess? StartElevated(ProcessStartInfo startInfo);
}

internal sealed class WindowsBitLockerStatusPlatform : IBitLockerStatusPlatform
{
    public string SystemDirectory => Environment.GetFolderPath(Environment.SpecialFolder.System);
    public bool IsFixedDrive(string drive) => new DriveInfo(drive + "\\").DriveType == DriveType.Fixed;
    public bool ExecutableExists(string executable) => File.Exists(executable);
    public IBitLockerStatusProcess? StartElevated(ProcessStartInfo startInfo)
    {
        var process = Process.Start(startInfo);
        return process is null ? null : new StatusProcess(process);
    }

    private sealed class StatusProcess(Process process) : IBitLockerStatusProcess
    {
        public bool WaitForExit(int milliseconds) => process.WaitForExit(milliseconds);
        public int ExitCode => process.ExitCode;
        public void Dispose() => process.Dispose();
    }
}

internal sealed class BitLockerStatusQuery(
    IBitLockerStatusPlatform platform, TimeSpan? launchAndQueryTimeout = null)
{
    // 0 idle, 1 query outstanding, 2 uncertain: no further launches in this instance.
    // A late shell return may never clear state 2 or authorize recovery.
    private int _state;
    private readonly TimeSpan _timeout = launchAndQueryTimeout ?? TimeSpan.FromSeconds(60);

    public async Task<BitLockerProtectionStatus> QueryAsync(
        string? drive, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedDrive = BitLockerProtection.NormalizeDrive(drive);
        if (normalizedDrive is null) return BitLockerProtectionStatus.Unverified;
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            return BitLockerProtectionStatus.Uncertain;

        // ShellExecuteEx can wait for UAC. Both launch and bounded process wait run off the UI thread.
        // Do not cancel scheduling: the worker must eventually own/dispose a late returned handle.
        var query = Task.Run(() => Run(normalizedDrive, cancellationToken));
        try
        {
            var result = await query.WaitAsync(_timeout, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _state) == 2) return BitLockerProtectionStatus.Uncertain;
            return result;
        }
        catch (OperationCanceledException)
        {
            Interlocked.Exchange(ref _state, 2);
            throw;
        }
        catch (TimeoutException)
        {
            Interlocked.Exchange(ref _state, 2);
            return BitLockerProtectionStatus.Uncertain;
        }
        catch
        {
            Interlocked.Exchange(ref _state, 2);
            return BitLockerProtectionStatus.Unverified;
        }
    }

    private BitLockerProtectionStatus Run(string drive, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var systemDirectory = platform.SystemDirectory;
            if (!Path.IsPathFullyQualified(systemDirectory) || !platform.IsFixedDrive(drive))
                return BitLockerProtectionStatus.Unverified;
            var executable = Path.Combine(systemDirectory, "manage-bde.exe");
            if (!platform.ExecutableExists(executable)) return BitLockerProtectionStatus.Unverified;
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _state) == 2) return Uncertain();
            using var process = platform.StartElevated(new ProcessStartInfo
            {
                FileName = executable,
                WorkingDirectory = systemDirectory,
                ArgumentList = { "-status", drive, "-protectionaserrorlevel" },
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                // Shell execution cannot redirect output. Never add redirection or a shell broker.
            });
            if (process is null) return Uncertain();
            // We cannot safely terminate an elevated process from the ordinary parent.
            // On cancellation/timeout, close its handle, block recovery, and prohibit another launch.
            if (cancellationToken.IsCancellationRequested || Volatile.Read(ref _state) == 2)
                return Uncertain();
            if (!process.WaitForExit(10_000)) return Uncertain();
            if (cancellationToken.IsCancellationRequested || Volatile.Read(ref _state) == 2)
                return Uncertain();
            // Only an actual completed built-in query, with a readable exit status, can succeed.
            return BitLockerProtection.ClassifyExitCode(process.ExitCode);
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            return BitLockerProtectionStatus.PermissionCancelled;
        }
        catch (OperationCanceledException)
        {
            return Uncertain();
        }
        catch
        {
            // A start/wait/exit-code failure may have left an untrackable query running.
            return Uncertain();
        }
        finally
        {
            Interlocked.CompareExchange(ref _state, 0, 1);
        }
    }

    private BitLockerProtectionStatus Uncertain()
    {
        Interlocked.Exchange(ref _state, 2);
        return BitLockerProtectionStatus.Uncertain;
    }
}

internal static class BitLockerProtection
{
    private static readonly BitLockerStatusQuery Query = new(new WindowsBitLockerStatusPlatform());

    internal static string? NormalizeDrive(string? drive)
    {
        if (drive is null || (drive.Length != 2 && drive.Length != 3) || drive[1] != ':' ||
            !((drive[0] >= 'A' && drive[0] <= 'Z') || (drive[0] >= 'a' && drive[0] <= 'z')) ||
            (drive.Length == 3 && drive[2] != '\\')) return null;
        return char.ToUpperInvariant(drive[0]) + ":";
    }

    internal static BitLockerProtectionStatus ClassifyExitCode(int exitCode) => exitCode switch
    {
        0 => BitLockerProtectionStatus.Protected,
        1 => BitLockerProtectionStatus.Unprotected,
        _ => BitLockerProtectionStatus.Unverified,
    };

    public static Task<BitLockerProtectionStatus> QueryAsync(
        string? drive, CancellationToken cancellationToken) => Query.QueryAsync(drive, cancellationToken);
}
