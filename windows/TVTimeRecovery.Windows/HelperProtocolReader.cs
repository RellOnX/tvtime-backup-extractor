using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace TVTimeRecovery.Windows;

// One event reader for readiness and all subsequent events. Only readiness has a deadline.
internal sealed class HelperProtocolReader(
    TextReader reader, Action abortStartup, TimeSpan? readyTimeout = null)
{
    private const int ProtocolVersion = 3;
    private const string ExpectedHelperVersion = "0.3.1a1";
    private readonly TimeSpan _readyTimeout = readyTimeout ?? TimeSpan.FromSeconds(15);
    private int _state; // 0 new, 1 awaiting ready, 2 ready, 3 failed
    private int _consumer;
    private int _nextSequence = 1;
    private int _aborted;
    private Task? _pendingReady;

    public bool IsReady => Volatile.Read(ref _state) == 2;
    public void RequireReady()
    {
        if (!IsReady) throw new InvalidOperationException("Helper readiness is required.");
    }

    public async Task WaitForReadyAsync(string lane, CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            throw new InvalidOperationException("Helper readiness cannot be retried.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            deadline.CancelAfter(_readyTimeout);
            _pendingReady = ReadReadyAsync(lane, deadline.Token);
            // Also bound a late/non-cooperative reader. The failed state prevents its late result
            // from authorizing writes; aborting the owned child releases its pipe endpoints.
            await _pendingReady.WaitAsync(deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            if (Interlocked.CompareExchange(ref _state, 2, 1) != 1)
                throw new InvalidDataException();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            FailStartup();
            throw new TimeoutException("The private helper did not become ready in time.");
        }
        catch
        {
            FailStartup();
            throw;
        }
    }

    public async Task ObserveFailedReadyReadAsync()
    {
        if (_pendingReady is null) return;
        try { await _pendingReady.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
        catch { /* Observe only; this can never promote failed readiness to success. */ }
    }

    private void FailStartup()
    {
        Interlocked.Exchange(ref _state, 3);
        if (Interlocked.Exchange(ref _aborted, 1) == 0) abortStartup();
    }

    private void AcquireConsumer()
    {
        if (Interlocked.CompareExchange(ref _consumer, 1, 0) != 0)
            throw new InvalidOperationException("A helper event reader is already active.");
    }

    private async Task ReadReadyAsync(string lane, CancellationToken cancellationToken)
    {
        AcquireConsumer();
        try
        {
            using var document = await ReadEventAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("The private helper exited before readiness.");
            var root = document.RootElement;
            if (root.GetProperty("type").GetString() != "ready") throw new InvalidDataException();
            var payload = root.GetProperty("payload");
            if (payload.GetProperty("helperVersion").GetString() != ExpectedHelperVersion ||
                !payload.GetProperty("minimumProtocolVersion").TryGetInt32(out var minimum) ||
                !payload.GetProperty("maximumProtocolVersion").TryGetInt32(out var maximum) ||
                minimum <= 0 || maximum < minimum || minimum > ProtocolVersion || maximum < ProtocolVersion)
                throw new InvalidDataException();
            var capabilities = payload.GetProperty("capabilities");
            if (capabilities.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            var available = new HashSet<string>(StringComparer.Ordinal);
            foreach (var capability in capabilities.EnumerateArray())
            {
                if (capability.ValueKind != JsonValueKind.String || !available.Add(capability.GetString()!))
                    throw new InvalidDataException();
            }
            string[] required = lane switch
            {
                "preflight" => ["preflight", "source-receipt-v1"],
                "recover" => ["recover", "source-receipt-v1"],
                "acquire" => ["source-neutral-acquisition-v1"],
                _ => throw new InvalidDataException(),
            };
            foreach (var capability in required.Concat(new[]
                { "cancel", "destination-parent-fd", "windows-inherited-handles" }))
                if (!available.Contains(capability)) throw new InvalidDataException();
        }
        finally { Interlocked.Exchange(ref _consumer, 0); }
    }

    public async IAsyncEnumerable<JsonDocument> EventsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!IsReady) throw new InvalidOperationException("Helper readiness is required.");
        AcquireConsumer();
        try
        {
            while (true)
            {
                // No global post-ready inactivity timer: legitimate work may be quiet.
                var document = await ReadEventAsync(cancellationToken).ConfigureAwait(false);
                if (document is null) yield break;
                if (document.RootElement.GetProperty("type").GetString() == "ready")
                {
                    document.Dispose();
                    throw new InvalidDataException();
                }
                yield return document;
            }
        }
        finally { Interlocked.Exchange(ref _consumer, 0); }
    }

    private async Task<JsonDocument?> ReadEventAsync(CancellationToken cancellationToken)
    {
        var line = await ReadBoundedLineAsync(cancellationToken).ConfigureAwait(false);
        if (line is null) return null;
        var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 32 });
        try
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.GetProperty("protocolVersion").GetInt32() != ProtocolVersion ||
                root.GetProperty("sequence").GetInt32() != _nextSequence ||
                root.GetProperty("type").ValueKind != JsonValueKind.String ||
                root.GetProperty("type").GetString() is not ("ready" or "progress" or "completed" or "failed" or "cancelled") ||
                root.GetProperty("payload").ValueKind != JsonValueKind.Object)
                throw new InvalidDataException();
            _nextSequence = checked(_nextSequence + 1);
            return document;
        }
        catch { document.Dispose(); throw; }
    }

    private async Task<string?> ReadBoundedLineAsync(CancellationToken cancellationToken)
    {
        const int maximumCharacters = 1_048_576 / 4;
        var line = new StringBuilder();
        var one = new char[1];
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = await reader.ReadAsync(one.AsMemory(), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (count == 0) return line.Length == 0 ? null : throw new InvalidDataException();
            if (one[0] == '\n') return line.ToString();
            if (one[0] == '\r') continue;
            line.Append(one[0]);
            if (line.Length > maximumCharacters) throw new InvalidDataException();
        }
    }
}
