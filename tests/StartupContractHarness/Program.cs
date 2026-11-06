using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// Independent synthetic reproducer. This does not reference or launch the app
// or its helper. Provenance and integration limitations are in README.md.
internal static class Program
{
    private static readonly TimeSpan IoBudget = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan CleanupBudget = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan TestBudget = TimeSpan.FromSeconds(15);

    private static async Task<int> Main()
    {
        if (!OperatingSystem.IsWindows() ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64 ||
            Environment.Version.Major != 8 ||
            Environment.Version.Minor != 0 ||
            Environment.Version.Build != 29)
        {
            Console.WriteLine("FAIL WINDOWS_X64_DOTNET_8_0_29_REQUIRED");
            return 1;
        }

        Console.WriteLine("PASS WINDOWS_X64_DOTNET_8_0_29_REQUIRED");
        (string Label, Func<Task> Run)[] tests =
        {
            ("PIPE_ASYNC_READ_CONSTRUCTOR_REJECTED", () => RejectAsyncConstructor(readEnd: true)),
            ("PIPE_ASYNC_WRITE_CONSTRUCTOR_REJECTED", () => RejectAsyncConstructor(readEnd: false)),
            ("PIPE_SYNC_HANDLES_ASYNC_FRAME_ROUNDTRIP", FrameRoundTripAsync),
            ("PIPE_EOF_AFTER_WRITER_CLOSE", EofAfterWriterCloseAsync),
            ("PIPE_PENDING_READ_CANCELLATION", PendingReadCancellationAsync),
            ("FIFO_BASELINE_REPRODUCES_STALE_PROGRESS", BaselineProgressOverwrite),
            ("FIFO_GUARD_PRESERVES_TERMINAL_STATES", GuardPreservesTerminalStates),
            ("FIFO_GUARD_REJECTS_PREVIOUS_RUN", GuardRejectsPreviousRun),
        };

        var failed = false;
        foreach (var (label, run) in tests)
        {
            try
            {
                await run().WaitAsync(TestBudget);
                Console.WriteLine($"PASS {label}");
            }
            catch (TimeoutException)
            {
                // Do not proceed with more tests if a timed-out test could
                // still have work pending. Exiting closes this process's handles.
                Console.WriteLine($"FAIL {label}");
                Console.WriteLine("FAIL SYNTHETIC_CHECKS");
                return 1;
            }
            catch
            {
                // Fixed labels only: no exception text, paths, handles or data.
                Console.WriteLine($"FAIL {label}");
                failed = true;
            }
        }

        Console.WriteLine(failed ? "FAIL SYNTHETIC_CHECKS" : "PASS SYNTHETIC_CHECKS");
        return failed ? 1 : 0;
    }

    private static Task RejectAsyncConstructor(bool readEnd)
    {
        using var pipe = NativePipe.Create();
        Check(!pipe.ReadHandle.IsInvalid && !pipe.WriteHandle.IsInvalid);
        Check(!pipe.ReadHandle.IsAsync && !pipe.WriteHandle.IsAsync);

        var suppliedHandle = readEnd ? pipe.ReadHandle : pipe.WriteHandle;
        var rejected = false;
        FileStream? unexpectedStream = null;
        try
        {
            unexpectedStream = readEnd
                ? pipe.OpenRead(isAsync: true)
                : pipe.OpenWrite(isAsync: true);
        }
        catch (ArgumentException error) when (error.ParamName == "handle")
        {
            rejected = true;
        }
        finally
        {
            unexpectedStream?.Dispose();
        }

        Check(rejected);
        // Validation failure does not transfer ownership to a usable stream.
        // NativePipe retains ownership and disposes the handle at scope exit.
        Check(!suppliedHandle.IsClosed && !suppliedHandle.IsInvalid);
        return Task.CompletedTask;
    }

    private static async Task FrameRoundTripAsync()
    {
        using var pipe = NativePipe.Create();
        using var writer = pipe.OpenWrite(isAsync: false);
        using var reader = pipe.OpenRead(isAsync: false);
        Check(!writer.IsAsync && !reader.IsAsync);

        byte[] payload = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)payload.Length);

        // The entire ten-byte frame fits in the otherwise empty 4096-byte
        // pipe. These writes cannot depend on a peer draining a full pipe.
        await writer.WriteAsync(header).AsTask().WaitAsync(IoBudget);
        await writer.WriteAsync(payload).AsTask().WaitAsync(IoBudget);
        await writer.FlushAsync().WaitAsync(IoBudget);

        var readTask = ReadFrameAsync(reader);
        byte[] received;
        try
        {
            received = await readTask.WaitAsync(IoBudget);
        }
        finally
        {
            // WaitAsync limits the wait, not the operation. Closing the only
            // writer releases a pending pipe read if the read timed out.
            writer.Dispose();
            await ObserveReadAfterClosingWriterAsync(readTask);
        }
        Check(payload.AsSpan().SequenceEqual(received));
    }

    private static async Task<byte[]> ReadFrameAsync(FileStream reader)
    {
        var header = new byte[4];
        await ReadExactlyAsync(reader, header);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        Check(length == 6);
        var payload = new byte[checked((int)length)];
        await ReadExactlyAsync(reader, payload);
        return payload;
    }

    private static async Task ReadExactlyAsync(FileStream reader, byte[] bytes)
    {
        var position = 0;
        while (position < bytes.Length)
        {
            var count = await reader.ReadAsync(bytes.AsMemory(position));
            Check(count > 0);
            position += count;
        }
    }

    private static async Task EofAfterWriterCloseAsync()
    {
        using var pipe = NativePipe.Create();
        using var writer = pipe.OpenWrite(isAsync: false, bufferSize: 1);
        using var reader = pipe.OpenRead(isAsync: false, bufferSize: 1);
        writer.Dispose();
        var pendingRead = reader.ReadAsync(new byte[1].AsMemory()).AsTask();
        try
        {
            Check(await pendingRead.WaitAsync(IoBudget) == 0);
        }
        finally
        {
            await ObserveReadAfterClosingWriterAsync(pendingRead);
        }
    }

    private static async Task PendingReadCancellationAsync()
    {
        using var pipe = NativePipe.Create();
        using var writer = pipe.OpenWrite(isAsync: false, bufferSize: 1);
        using var reader = pipe.OpenRead(isAsync: false, bufferSize: 1);
        using var cancellation = new CancellationTokenSource();

        var pendingRead = reader.ReadAsync(new byte[1].AsMemory(), cancellation.Token).AsTask();
        var observedCancellation = false;
        try
        {
            // Verify an externally pending read before cancelling. This does
            // not claim that a kernel read was already issued at this instant.
            await Task.Delay(100);
            Check(!pendingRead.IsCompleted);
            cancellation.Cancel();
            try
            {
                _ = await pendingRead.WaitAsync(IoBudget);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                observedCancellation = true;
            }
        }
        finally
        {
            writer.Dispose();
            await ObserveReadAfterClosingWriterAsync(pendingRead);
        }
        Check(observedCancellation);
    }

    private static async Task ObserveReadAfterClosingWriterAsync(Task readTask)
    {
        try
        {
            await readTask.WaitAsync(CleanupBudget);
        }
        catch (OperationCanceledException)
        {
            // Cancellation is expected in the cancellation test.
        }
        // An unexpected read fault or cleanup timeout remains a failing test.
    }

    private static Task BaselineProgressOverwrite()
    {
        var queue = new FifoQueue();
        var display = "READY";
        try
        {
            queue.Enqueue(() => display = "RUNNING");
            throw new SyntheticStartException();
        }
        catch (SyntheticStartException)
        {
            display = "FAILED";
        }

        Check(display == "FAILED");
        queue.Drain();
        Check(display == "RUNNING");
        return Task.CompletedTask;
    }

    private static Task GuardPreservesTerminalStates()
    {
        foreach (var terminal in new[] { Phase.Failed, Phase.Completed, Phase.Cancelled })
        {
            var queue = new FifoQueue();
            var model = new GuardedStatusModel(queue);
            var run = model.StartRun();
            model.QueueProgress(run, "STALE_PROGRESS");
            model.Finish(run, terminal);
            queue.Drain();
            Check(model.CurrentPhase == terminal);
            Check(model.Display == terminal.ToString());
            Check(model.AppliedProgressCount == 0);

            // A callback received after the terminal transition is also ignored.
            model.QueueProgress(run, "LATE_PROGRESS");
            queue.Drain();
            Check(model.CurrentPhase == terminal);
            Check(model.Display == terminal.ToString());
            Check(model.AppliedProgressCount == 0);
        }
        return Task.CompletedTask;
    }

    private static Task GuardRejectsPreviousRun()
    {
        var queue = new FifoQueue();
        var model = new GuardedStatusModel(queue);
        var oldRun = model.StartRun();
        model.QueueProgress(oldRun, "OLD_PROGRESS");
        model.Finish(oldRun, Phase.Failed);
        var newRun = model.StartRun();
        model.QueueProgress(newRun, "NEW_PROGRESS");

        queue.DrainOne();
        Check(model.CurrentPhase == Phase.Starting);
        Check(model.Display == "STARTING");
        Check(model.AppliedProgressCount == 0);

        queue.DrainOne();
        Check(model.CurrentPhase == Phase.Running);
        Check(model.Display == "NEW_PROGRESS");
        Check(model.AppliedProgressCount == 1);

        model.QueueProgress(oldRun, "OLD_PROGRESS_AFTER_NEW_RUN");
        queue.Drain();
        Check(model.CurrentPhase == Phase.Running);
        Check(model.Display == "NEW_PROGRESS");
        Check(model.AppliedProgressCount == 1);

        model.Finish(newRun, Phase.Completed);
        model.QueueProgress(newRun, "NEW_RUN_LATE_PROGRESS");
        queue.Drain();
        Check(model.CurrentPhase == Phase.Completed);
        Check(model.AppliedProgressCount == 1);
        return Task.CompletedTask;
    }

    private static void Check(bool condition)
    {
        if (!condition) throw new InvalidOperationException();
    }

    private sealed class SyntheticStartException : Exception { }

    private enum Phase { Starting, Running, Failed, Completed, Cancelled }

    private sealed class RunState
    {
        public bool Active { get; set; } = true;
    }

    // A deliberately explicit single-threaded model, not WinUI DispatcherQueue.
    private sealed class FifoQueue
    {
        private readonly Queue<Action> _callbacks = new();
        public void Enqueue(Action callback) => _callbacks.Enqueue(callback);
        public void DrainOne() => _callbacks.Dequeue()();
        public void Drain()
        {
            while (_callbacks.Count > 0) DrainOne();
        }
    }

    private sealed class GuardedStatusModel(FifoQueue queue)
    {
        private RunState? _currentRun;
        public Phase CurrentPhase { get; private set; } = Phase.Starting;
        public string Display { get; private set; } = "STARTING";
        public int AppliedProgressCount { get; private set; }

        public RunState StartRun()
        {
            _currentRun = new RunState();
            CurrentPhase = Phase.Starting;
            Display = "STARTING";
            return _currentRun;
        }

        public void QueueProgress(RunState run, string text)
        {
            queue.Enqueue(() =>
            {
                // Check at execution time, not just when the work is queued.
                if (!ReferenceEquals(run, _currentRun) || !run.Active) return;
                CurrentPhase = Phase.Running;
                Display = text;
                AppliedProgressCount++;
            });
        }

        public void Finish(RunState run, Phase terminal)
        {
            Check(terminal is Phase.Failed or Phase.Completed or Phase.Cancelled);
            Check(ReferenceEquals(run, _currentRun));
            run.Active = false;
            CurrentPhase = terminal;
            Display = terminal.ToString();
        }
    }

    private sealed class NativePipe : IDisposable
    {
        private SafeFileHandle? _read;
        private SafeFileHandle? _write;

        private NativePipe(SafeFileHandle read, SafeFileHandle write)
        {
            _read = read;
            _write = write;
        }

        public SafeFileHandle ReadHandle => _read ?? throw new InvalidOperationException();
        public SafeFileHandle WriteHandle => _write ?? throw new InvalidOperationException();

        public static NativePipe Create()
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = IntPtr.Zero,
                // No child process exists. Keep these test-only handles private.
                InheritHandle = false,
            };
            if (!CreatePipe(out var read, out var write, ref attributes, 4096))
            {
                read?.Dispose();
                write?.Dispose();
                throw new InvalidOperationException();
            }
            return new NativePipe(read, write);
        }

        public FileStream OpenRead(bool isAsync, int bufferSize = 4096)
        {
            var stream = new FileStream(ReadHandle, FileAccess.Read, bufferSize, isAsync);
            // Transfer sole disposal responsibility only after successful creation.
            _read = null;
            return stream;
        }

        public FileStream OpenWrite(bool isAsync, int bufferSize = 4096)
        {
            var stream = new FileStream(WriteHandle, FileAccess.Write, bufferSize, isAsync);
            _write = null;
            return stream;
        }

        public void Dispose()
        {
            _read?.Dispose();
            _read = null;
            _write?.Dispose();
            _write = null;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out SafeFileHandle read,
            out SafeFileHandle write,
            ref SecurityAttributes attributes,
            uint size);
    }
}
