using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TVTimeRecovery.Windows;

// Synthetic only: anonymous OS pipes and queued in-memory callbacks, no helper or backup.
internal static class HelperStartupTests
{
    public static void Run()
    {
        RequirePipeModeContract();
        RequireQueuedProgressCannotRepaintTerminalOrLaterOperations();
    }

    private static void RequirePipeModeContract()
    {
        if (!CreatePipe(out var read, out var write, IntPtr.Zero, 0))
            throw new InvalidOperationException("Synthetic pipe creation failed.");
        using (read)
        using (write)
        {
            var rejected = false;
            try
            {
                using var invalid = new FileStream(read, FileAccess.Read, 4096, isAsync: true);
            }
            catch (ArgumentException) { rejected = true; }
            Require(rejected);
        }
        if (!CreatePipe(out read, out write, IntPtr.Zero, 0))
            throw new InvalidOperationException("Synthetic pipe creation failed.");
        using (read)
        using (write)
        using (var input = new FileStream(read, FileAccess.Read, 4096, isAsync: false))
        using (var output = new FileStream(write, FileAccess.Write, 4096, isAsync: false))
        {
            output.WriteByte(42);
            output.Flush();
            var received = new byte[1];
            Require(input.ReadAsync(received.AsMemory()).AsTask()
                .WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult() == 1);
            Require(received[0] == 42);
        }
    }

    private static void RequireQueuedProgressCannotRepaintTerminalOrLaterOperations()
    {
        var gate = new RecoveryProgressEpoch();
        var queue = new Queue<Action>();
        var painted = 0;
        void Enqueue(long epoch) => queue.Enqueue(() =>
        {
            if (gate.IsCurrent(epoch)) painted++;
        });
        var failed = gate.Begin();
        Enqueue(failed); // Initial progress queued immediately before a synchronous failure.
        gate.End(failed);
        queue.Dequeue()();
        Require(painted == 0);
        var active = gate.Begin();
        Enqueue(failed);
        Enqueue(active);
        gate.End(failed); // Old cleanup must not invalidate a newer operation.
        queue.Dequeue()();
        queue.Dequeue()();
        Require(painted == 1);
        Enqueue(active);
        gate.CancelCurrent(); // Cancel/close must invalidate callbacks before dispatch.
        queue.Dequeue()();
        Require(painted == 1);
        var completed = gate.Begin();
        Enqueue(completed);
        gate.End(completed);
        var later = gate.Begin();
        queue.Dequeue()();
        Require(painted == 1 && gate.IsCurrent(later));
        gate.End(later);
        Require(!gate.IsCurrent(later));
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Synthetic startup contract failed.");
    }

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool CreatePipe(
        out SafeFileHandle read, out SafeFileHandle write, IntPtr attributes, uint size);
}
