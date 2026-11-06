using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.Json;
using TVTimeRecovery.Windows;

internal static class Program
{
    private static readonly TimeSpan IoBudget = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CleanupBudget = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan TestBudget = TimeSpan.FromSeconds(35);
    private static string _peerPath = "";
    private static string _dataRoot = "";
    private static Version? _peerRuntime;

    private static async Task<int> Main(string[] args)
    {
        try
        {
            Check(OperatingSystem.IsWindows());
            Check(RuntimeInformation.ProcessArchitecture == Architecture.X64);
            Check(Environment.Version.Major == 8 && Environment.Version.Minor == 0);
            Check(args.Length == 1);
            var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../.."));
            var runnerTemp = Environment.GetEnvironmentVariable("RUNNER_TEMP");
            Check(!string.IsNullOrWhiteSpace(runnerTemp));
            var allowedPrefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(runnerTemp!)) + Path.DirectorySeparatorChar;
            Check(root.StartsWith(allowedPrefix, StringComparison.OrdinalIgnoreCase));
            var expectedPeer = Path.Combine(root, "Peer", "bin", "Release", "net8.0", "SyntheticProtocolPeer.exe");
            _peerPath = Path.GetFullPath(args[0]);
            Check(string.Equals(_peerPath, expectedPeer, StringComparison.OrdinalIgnoreCase));
            Check(File.Exists(_peerPath));
            _dataRoot = Path.Combine(root, "RunData");
            Directory.CreateDirectory(_dataRoot);
        }
        catch
        {
            Console.WriteLine("FAIL ISOLATED_RUNNER_CONFIGURATION");
            return 1;
        }

        Console.WriteLine($"PASS HARNESS_RUNTIME_{Environment.Version.ToString().Replace('.', '_')}");
        (string Label, Func<Task> Run)[] tests =
        {
            ("ACTUAL_LAUNCHER_CONTROL_SECRET_IDENTITY_ROUNDTRIP", RoundTripAsync),
            ("EARLY_EOF_AFTER_READY_OBSERVED", EarlyEofAsync),
            ("MALFORMED_JSON_REJECTED", MalformedAsync),
            ("OVERSIZED_CHARACTER_LINE_REJECTED", OversizedAsync),
            ("TRUNCATED_LINE_AT_EOF_REJECTED", TruncatedAsync),
            ("SILENT_AFTER_READY_CALLER_CANCELLATION", () => PendingOutputCancellationAsync("silent")),
            ("PARTIAL_LINE_CALLER_CANCELLATION", () => PendingOutputCancellationAsync("partial")),
            ("ACTUAL_CANCEL_ASYNC_CONTROL_FRAME", CancelControlAsync),
            ("DISPOSE_JOB_TERMINATES_UNRESPONSIVE_PEER", DisposeKillsPeerAsync),
        };

        var failed = false;
        foreach (var (label, run) in tests)
        {
            try
            {
                // Start itself is synchronous. Invoke the whole test on a
                // worker so even a startup hang cannot block this watchdog.
                await Task.Run(run).WaitAsync(TestBudget);
                Console.WriteLine($"PASS {label}");
            }
            catch (TimeoutException)
            {
                AbortRunaway(label);
            }
            catch (PeerStartupException)
            {
                StopSuite(label, "STARTUP_FAILED_NO_RETRY");
            }
            catch
            {
                Console.WriteLine($"FAIL {label}");
                failed = true;
            }
        }
        Console.WriteLine(failed ? "FAIL LAUNCHER_CONTRACT_CHECKS" : "PASS LAUNCHER_CONTRACT_CHECKS");
        return failed ? 1 : 0;
    }

    private static async Task RoundTripAsync()
    {
        await using var session = await Session.OpenAsync();
        await session.SendScenarioAsync("roundtrip");
        await session.Helper.SendSecretAsync("synthetic-secret-only", session.EventToken).WaitAsync(IoBudget);
        using var progress = await session.ReadEventAsync();
        CheckEvent(progress, "progress", 2);
        Check(progress!.RootElement.GetProperty("payload").GetProperty("secretMatches").GetBoolean());
        using var completed = await session.ReadEventAsync();
        CheckEvent(completed, "completed", 3);
        Check(completed!.RootElement.GetProperty("payload").GetProperty("synthetic").GetBoolean());
        await session.Helper.WaitForSuccessfulExitAsync().WaitAsync(TimeSpan.FromSeconds(7));
        using var eof = await session.ReadEventAsync();
        Check(eof is null);
    }

    private static async Task EarlyEofAsync()
    {
        await using var session = await Session.OpenAsync();
        await session.SendScenarioAsync("early-eof");
        using var eof = await session.ReadEventAsync();
        Check(eof is null);
        await session.Helper.WaitForSuccessfulExitAsync().WaitAsync(TimeSpan.FromSeconds(7));
    }

    private static Task MalformedAsync() => ExpectParserFailureAsync<JsonException>("malformed");
    private static Task OversizedAsync() => ExpectParserFailureAsync<InvalidDataException>("oversized");
    private static Task TruncatedAsync() => ExpectParserFailureAsync<InvalidDataException>("truncated");

    private static async Task ExpectParserFailureAsync<T>(string scenario) where T : Exception
    {
        await using var session = await Session.OpenAsync();
        await session.SendScenarioAsync(scenario);
        var rejected = false;
        try
        {
            using var unexpected = await session.ReadEventAsync();
        }
        catch (T)
        {
            rejected = true;
        }
        Check(rejected);
    }

    private static async Task PendingOutputCancellationAsync(string scenario)
    {
        await using var session = await Session.OpenAsync();
        await session.SendScenarioAsync(scenario);
        using var entered = await session.ReadEventAsync();
        CheckEvent(entered, "progress", 2);
        Check(entered!.RootElement.GetProperty("payload").GetProperty("scenario").GetString() == scenario);
        var pending = session.BeginRead();
        await Task.Delay(250);
        Check(!pending.IsCompleted);
        session.CancelEventRead();
        var cancelled = false;
        try
        {
            _ = await pending.WaitAsync(IoBudget);
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        session.ForgetCompletedRead();
        Check(cancelled);
        // This is caller-token cancellation of EventsAsync, not the
        // coordinator's cancellation registration or an automatic watchdog.
    }

    private static async Task CancelControlAsync()
    {
        await using var session = await Session.OpenAsync();
        await session.SendScenarioAsync("cancel-control");
        using var entered = await session.ReadEventAsync();
        CheckEvent(entered, "progress", 2);
        await session.Helper.CancelAsync().WaitAsync(IoBudget);
        using var cancelled = await session.ReadEventAsync();
        CheckEvent(cancelled, "cancelled", 3);
        Check(cancelled!.RootElement.GetProperty("payload").GetProperty("code").GetString() == "cancelled");
        await session.Helper.WaitForSuccessfulExitAsync().WaitAsync(TimeSpan.FromSeconds(7));
    }

    private static async Task DisposeKillsPeerAsync()
    {
        await using var session = await Session.OpenAsync();
        await session.SendScenarioAsync("silent");
        using var entered = await session.ReadEventAsync();
        CheckEvent(entered, "progress", 2);
        Check(!session.PeerHasExited);
        await session.DisposeAsync();
        Check(session.ObservedPeerExit);
        // The peer ignores stdin/EOF in this scenario and its own safety timer
        // is 90 seconds, beyond both this cleanup budget and the test budget.
    }

    private static void CheckEvent(JsonDocument? document, string type, int sequence)
    {
        Check(document is not null);
        var root = document!.RootElement;
        Check(root.GetProperty("protocolVersion").GetInt32() == 3);
        Check(root.GetProperty("sequence").GetInt32() == sequence);
        Check(root.GetProperty("type").GetString() == type);
    }

    private static void Check(bool condition)
    {
        if (!condition) throw new InvalidOperationException();
    }

    [DoesNotReturn]
    private static void AbortRunaway(string label) => StopSuite(label, "RUNAWAY_ABORT_NO_FURTHER_TESTS");

    [DoesNotReturn]
    private static void StopSuite(string label, string reason)
    {
        Console.WriteLine($"FAIL {label}");
        Console.WriteLine($"FAIL {reason}");
        Console.Out.Flush();
        // Immediate process exit closes its job handles. This deliberately
        // avoids FailFast crash dumps and does not run another test.
        Environment.Exit(1);
        throw new InvalidOperationException();
    }

    private sealed class PeerStartupException : Exception { }

    private sealed class Session : IAsyncDisposable
    {
        private readonly CancellationTokenSource _eventsCancellation = new();
        private readonly IAsyncEnumerator<JsonDocument> _events;
        private Task<bool>? _pendingRead;
        private Process? _peer;
        private bool _disposed;
        public NativeHelperProcess Helper { get; }
        public CancellationToken EventToken => _eventsCancellation.Token;
        public bool PeerHasExited => _peer?.HasExited ?? true;
        public bool ObservedPeerExit { get; private set; }

        private Session(NativeHelperProcess helper)
        {
            Helper = helper;
            _events = helper.EventsAsync(_eventsCancellation.Token).GetAsyncEnumerator();
        }

        public static async Task<Session> OpenAsync()
        {
            NativeHelperProcess helper;
            try
            {
                var destination = Path.Combine(_dataRoot, Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(destination);
                helper = NativeHelperProcess.Start(_peerPath, destination);
            }
            catch
            {
                // A denied launch or any other startup failure is never retried
                // by advancing to another scenario in this suite.
                throw new PeerStartupException();
            }
            var session = new Session(helper);
            try
            {
                using var ready = await session.ReadEventAsync();
                CheckEvent(ready, "ready", 1);
                var payload = ready!.RootElement.GetProperty("payload");
                Check(payload.GetProperty("testPeer").GetBoolean());
                Check(payload.GetProperty("device").GetUInt64() == session.Helper.DestinationIdentity.Device);
                Check(payload.GetProperty("inode").GetUInt64() == session.Helper.DestinationIdentity.Inode);
                var version = Version.Parse(payload.GetProperty("runtimeVersion").GetString()!);
                Check(version.Major == 8 && version.Minor == 0);
                if (_peerRuntime is null)
                {
                    _peerRuntime = version;
                    Console.WriteLine($"PASS PEER_RUNTIME_{version.ToString().Replace('.', '_')}");
                }
                else
                {
                    Check(_peerRuntime == version);
                }
                // Observe only the PID returned by this newly built peer.
                // Force the process handle open while it awaits our request.
                session._peer = Process.GetProcessById(payload.GetProperty("processId").GetInt32());
                _ = session._peer.SafeHandle;
                return session;
            }
            catch
            {
                await session.DisposeAsync();
                throw new PeerStartupException();
            }
        }

        public Task SendScenarioAsync(string scenario)
        {
            var request = JsonSerializer.SerializeToUtf8Bytes(new
            {
                protocolVersion = 3,
                type = "scenario",
                payload = new { scenario },
            });
            return Helper.SendControlAsync(request, EventToken).WaitAsync(IoBudget);
        }

        public Task<bool> BeginRead()
        {
            Check(_pendingRead is null);
            _pendingRead = _events.MoveNextAsync().AsTask();
            return _pendingRead;
        }

        public async Task<JsonDocument?> ReadEventAsync()
        {
            var pending = BeginRead();
            try
            {
                return await pending.WaitAsync(IoBudget) ? _events.Current : null;
            }
            finally
            {
                ForgetCompletedRead();
            }
        }

        public void ForgetCompletedRead()
        {
            if (_pendingRead?.IsCompleted == true) _pendingRead = null;
        }

        public void CancelEventRead() => _eventsCancellation.Cancel();

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                _eventsCancellation.Cancel();
                await Helper.DisposeAsync().AsTask().WaitAsync(CleanupBudget);
                if (_pendingRead is not null)
                {
                    try
                    {
                        if (await _pendingRead.WaitAsync(IoBudget)) _events.Current.Dispose();
                    }
                    catch (OperationCanceledException) { }
                    _pendingRead = null;
                }
                await _events.DisposeAsync().AsTask().WaitAsync(IoBudget);
                if (_peer is not null)
                {
                    await _peer.WaitForExitAsync().WaitAsync(IoBudget);
                    ObservedPeerExit = true;
                    _peer.Dispose();
                }
                _eventsCancellation.Dispose();
            }
            catch
            {
                // Failed cleanup leaves process/handle state uncertain. Never
                // continue or claim teardown succeeded. OS job close is the
                // remaining containment action when this test process exits.
                AbortRunaway("CLEANUP_NOT_CONFIRMED");
            }
        }
    }
}
