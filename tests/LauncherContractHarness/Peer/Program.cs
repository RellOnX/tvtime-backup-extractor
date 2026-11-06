using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 0 || !OperatingSystem.IsWindows()) return 60;
        try
        {
            // Independent last-resort lifetime limit. The job-cleanup tests
            // must terminate this peer much sooner than ninety seconds.
            return await Task.Run(RunAsync).WaitAsync(TimeSpan.FromSeconds(90));
        }
        catch
        {
            // No exception text or local data is written to either stream.
            return 61;
        }
    }

    private static async Task<int> RunAsync()
    {
        using var input = Console.OpenStandardInput();
        using var output = Console.OpenStandardOutput();
        var writer = new EventWriter(output);
        var destination = GetDestinationIdentity();
        await writer.EmitAsync("ready", new
        {
            testPeer = true,
            processId = Environment.ProcessId,
            runtimeVersion = Environment.Version.ToString(),
            device = destination.Device,
            inode = destination.Inode,
            minimumProtocolVersion = 3,
            maximumProtocolVersion = 3,
            capabilities = new[] { "synthetic-protocol-peer" },
        });

        using var request = JsonDocument.Parse(await ReadFrameAsync(input, 4096));
        var root = request.RootElement;
        Require(root.GetProperty("protocolVersion").GetInt32() == 3);
        Require(root.GetProperty("type").GetString() == "scenario");
        var scenario = root.GetProperty("payload").GetProperty("scenario").GetString();
        switch (scenario)
        {
            case "roundtrip":
            {
                var matches = await ReadSyntheticSecretAsync();
                Require(matches);
                await writer.EmitAsync("progress", new { stage = "synthetic", secretMatches = matches });
                await writer.EmitAsync("completed", new { synthetic = true });
                return 0;
            }
            case "early-eof":
                return 0;
            case "malformed":
                await writer.RawAsync("{not-json}\n");
                return 0;
            case "oversized":
                // One character beyond the production reader's actual limit.
                await writer.RawAsync(new string('x', 262_145) + "\n");
                return 0;
            case "truncated":
                await writer.RawAsync("{\"protocolVersion\":3");
                return 0;
            case "silent":
            case "partial":
                await writer.EmitAsync("progress", new { stage = "synthetic", scenario });
                if (scenario == "partial")
                    await writer.RawAsync("{\"protocolVersion\":3,\"sequence\":3,\"type\":\"progress\"");
                // Intentionally ignores stdin, EOF and cancel messages.
                await Task.Delay(Timeout.InfiniteTimeSpan);
                return 62;
            case "cancel-control":
            {
                await writer.EmitAsync("progress", new { stage = "synthetic", scenario });
                using var cancel = JsonDocument.Parse(await ReadFrameAsync(input, 4096));
                Require(cancel.RootElement.GetProperty("protocolVersion").GetInt32() == 3);
                Require(cancel.RootElement.GetProperty("type").GetString() == "cancel");
                Require(cancel.RootElement.EnumerateObject().Count() == 2);
                await writer.EmitAsync("cancelled", new { code = "cancelled", synthetic = true });
                return 0;
            }
            default:
                return 63;
        }
    }

    private static async Task<bool> ReadSyntheticSecretAsync()
    {
        using var handle = new SafeFileHandle(ReadHandleValue("TVTIME_SECRET_HANDLE"), ownsHandle: true);
        using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        var received = await ReadFrameAsync(stream, 64);
        var expected = Encoding.UTF8.GetBytes("synthetic-secret-only");
        try
        {
            return received.AsSpan().SequenceEqual(expected);
        }
        finally
        {
            Array.Clear(received);
            Array.Clear(expected);
        }
    }

    private static async Task<byte[]> ReadFrameAsync(Stream stream, int maximum)
    {
        var header = new byte[4];
        await ReadExactlyAsync(stream, header);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        Require(length > 0 && length <= maximum);
        var payload = new byte[checked((int)length)];
        await ReadExactlyAsync(stream, payload);
        return payload;
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] bytes)
    {
        var offset = 0;
        while (offset < bytes.Length)
        {
            var count = await stream.ReadAsync(bytes.AsMemory(offset));
            Require(count > 0);
            offset += count;
        }
    }

    private static IntPtr ReadHandleValue(string variable)
    {
        var raw = Environment.GetEnvironmentVariable(variable);
        Require(long.TryParse(raw, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var value));
        Require(value > 0);
        return new IntPtr(value);
    }

    private static (ulong Device, ulong Inode) GetDestinationIdentity()
    {
        using var handle = new SafeFileHandle(ReadHandleValue("TVTIME_DESTINATION_HANDLE"), ownsHandle: true);
        Require(GetFileInformationByHandle(handle, out var information));
        Require((information.FileAttributes & 0x10) != 0);
        Require((information.FileAttributes & 0x400) == 0);
        return (information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException();
    }

    private sealed class EventWriter(Stream output)
    {
        private int _sequence;
        public Task EmitAsync(string type, object payload) => RawAsync(JsonSerializer.Serialize(new
        {
            protocolVersion = 3,
            sequence = ++_sequence,
            type,
            payload,
        }) + "\n");

        public async Task RawAsync(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            await output.WriteAsync(bytes.AsMemory());
            await output.FlushAsync();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low, High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint FileAttributes;
        public NativeFileTime CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
}
