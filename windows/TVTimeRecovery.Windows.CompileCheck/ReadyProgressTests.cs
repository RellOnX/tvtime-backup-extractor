using System.Text.Json;

namespace TVTimeRecovery.Windows;

internal static class ReadyProgressTests
{
    private const string Ready = "{\"protocolVersion\":3,\"sequence\":1,\"type\":\"ready\",\"payload\":{\"helperVersion\":\"0.3.1a1\",\"minimumProtocolVersion\":3,\"maximumProtocolVersion\":3,\"capabilities\":[\"preflight\",\"recover\",\"cancel\",\"destination-parent-fd\",\"windows-inherited-handles\",\"source-receipt-v1\",\"source-neutral-acquisition-v1\"]}}\n";
    private const string Progress = "{\"protocolVersion\":3,\"sequence\":2,\"type\":\"progress\",\"payload\":{\"stage\":\"extraction\",\"current\":2,\"total\":5}}\n";

    public static async Task RunAsync()
    {
        foreach (var lane in new[] { "preflight", "recover", "acquire" })
        {
            var aborts = 0;
            var protocol = new HelperProtocolReader(new StringReader(Ready), () => aborts++);
            Require(!protocol.IsReady);
            await RejectAsync(() => { protocol.RequireReady(); return Task.CompletedTask; });
            await protocol.WaitForReadyAsync(lane, CancellationToken.None);
            Require(protocol.IsReady && aborts == 0);
            protocol.RequireReady();
        }
        foreach (var input in new[]
        {
            "", "{\n", Ready.TrimEnd('\n'),
            Ready.Replace("\"protocolVersion\":3", "\"protocolVersion\":4"),
            Ready.Replace("\"sequence\":1", "\"sequence\":2"),
            Ready.Replace("0.3.1a1", "synthetic-wrong-version"),
            Ready.Replace("\"minimumProtocolVersion\":3", "\"minimumProtocolVersion\":4"),
            Ready.Replace("\"recover\",", ""),
            Ready.Replace("\"windows-inherited-handles\",", ""),
        })
        {
            var aborts = 0;
            var protocol = new HelperProtocolReader(new StringReader(input), () => aborts++);
            await RejectAsync(() => protocol.WaitForReadyAsync("recover", CancellationToken.None));
            Require(!protocol.IsReady && aborts == 1);
            await RejectAsync(() => protocol.WaitForReadyAsync("recover", CancellationToken.None));
            Require(aborts == 1);
        }
        await RequireFirstReadyTimeoutAsync(partial: false, late: false);
        await RequireFirstReadyTimeoutAsync(partial: true, late: false);
        await RequireFirstReadyTimeoutAsync(partial: true, late: true);
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            var aborts = 0;
            var protocol = new HelperProtocolReader(new StringReader(Ready), () => aborts++);
            await RejectAsync(() => protocol.WaitForReadyAsync("preflight", cancelled.Token));
            Require(!protocol.IsReady && aborts == 1);
        }
        await RequireCancellationBeforeReadyAsync();
        await RequireLongQuietWorkAfterReadyAsync();
        await RequireQuietPostReadyCancellationAsync();
        await RequireMalformedPostReadyAsync();
        RequirePhaseCountsOnly();
    }

    private static async Task RequireFirstReadyTimeoutAsync(bool partial, bool late)
    {
        using var reader = new PausedReader(Ready, partial ? 12 : 0, ignoreCancellation: late);
        var aborts = 0;
        var protocol = new HelperProtocolReader(reader, () =>
        {
            aborts++;
            if (!late) reader.Abort();
        }, TimeSpan.FromMilliseconds(40));
        await RejectAsync(() => protocol.WaitForReadyAsync("preflight", CancellationToken.None));
        Require(!protocol.IsReady && aborts == 1);
        reader.Release(); // A ready frame completed after the deadline must never enable writes.
        await protocol.ObserveFailedReadyReadAsync();
        Require(!protocol.IsReady && aborts == 1);
    }

    private static async Task RequireCancellationBeforeReadyAsync()
    {
        using var cancellation = new CancellationTokenSource();
        using var reader = new PausedReader(Ready, 8);
        var aborts = 0;
        var protocol = new HelperProtocolReader(reader, () => { aborts++; reader.Abort(); });
        var pending = protocol.WaitForReadyAsync("preflight", cancellation.Token);
        cancellation.Cancel();
        try { await pending; Require(false); }
        catch (OperationCanceledException) { Require(!protocol.IsReady && aborts == 1); }
        await protocol.ObserveFailedReadyReadAsync();
    }

    private static async Task RequireLongQuietWorkAfterReadyAsync()
    {
        using var reader = new PausedReader(Ready + Progress, Ready.Length);
        var aborts = 0;
        var protocol = new HelperProtocolReader(reader, () => { aborts++; reader.Abort(); }, TimeSpan.FromMilliseconds(40));
        await protocol.WaitForReadyAsync("preflight", CancellationToken.None);
        await using var events = protocol.EventsAsync(CancellationToken.None).GetAsyncEnumerator();
        var next = events.MoveNextAsync().AsTask();
        await Task.Delay(120); // Deliberately exceeds the first-ready budget.
        Require(!next.IsCompleted && protocol.IsReady && aborts == 0);
        // A second consumer cannot steal bytes or reset sequence state.
        await using (var duplicate = protocol.EventsAsync(CancellationToken.None).GetAsyncEnumerator())
            await RejectAsync(async () => { _ = await duplicate.MoveNextAsync(); });
        reader.Release();
        Require(await next.WaitAsync(TimeSpan.FromSeconds(2)));
        using var document = events.Current;
        Require(document.RootElement.GetProperty("sequence").GetInt32() == 2 && aborts == 0);
    }

    private static async Task RequireQuietPostReadyCancellationAsync()
    {
        using var cancellation = new CancellationTokenSource();
        using var reader = new PausedReader(Ready + Progress, Ready.Length);
        var aborts = 0;
        var protocol = new HelperProtocolReader(reader, () => aborts++, TimeSpan.FromMilliseconds(40));
        await protocol.WaitForReadyAsync("recover", CancellationToken.None);
        await using var events = protocol.EventsAsync(cancellation.Token).GetAsyncEnumerator();
        var pending = events.MoveNextAsync().AsTask();
        await Task.Delay(120);
        Require(!pending.IsCompleted && aborts == 0);
        cancellation.Cancel();
        try { _ = await pending.WaitAsync(TimeSpan.FromSeconds(2)); Require(false); }
        catch (OperationCanceledException) { Require(aborts == 0); }
    }
    private static async Task RequireMalformedPostReadyAsync()
    {
        foreach (var tail in new[] { "{\n", "{\"partial\":", Ready.Replace("\"sequence\":1", "\"sequence\":2") })
        {
            var protocol = new HelperProtocolReader(new StringReader(Ready + tail), () => { });
            await protocol.WaitForReadyAsync("recover", CancellationToken.None);
            await using var events = protocol.EventsAsync(CancellationToken.None).GetAsyncEnumerator();
            await RejectAsync(async () => { _ = await events.MoveNextAsync(); });
        }
    }

    private static void RequirePhaseCountsOnly()
    {
        RecoveryProgress Parse(string value)
        {
            using var document = JsonDocument.Parse(value);
            return RecoveryProgress.FromPayload(document.RootElement);
        }
        var extraction = Parse("{\"stage\":\"extraction\",\"current\":2,\"total\":5}");
        Require(extraction.IsDeterminate && extraction.PhasePercent == 40 && extraction.DisplayText.Contains("Extraction phase"));
        foreach (var value in new[]
        {
            "{\"stage\":\"preflight\",\"current\":2,\"total\":5}",
            "{\"stage\":\"analysis\",\"current\":2,\"total\":5}",
            "{\"stage\":\"report\"}",
            "{\"stage\":\"extraction\"}",
            "{\"stage\":\"extraction\",\"current\":6,\"total\":5}",
            "{\"stage\":\"extraction\",\"current\":-1,\"total\":5}",
            "{\"stage\":\"extraction\",\"current\":\"2\",\"total\":5}",
        }) Require(!Parse(value).IsDeterminate);
        var empty = Parse("{\"stage\":\"extraction\",\"current\":0,\"total\":0}");
        Require(empty.HasExtractionCounts && !empty.IsDeterminate);
    }

    private static async Task RejectAsync(Func<Task> action)
    {
        var failed = false;
        Task task;
        try { task = action(); }
        catch { return; }
        try { await task.WaitAsync(TimeSpan.FromSeconds(3)); }
        catch (TimeoutException) when (!task.IsCompleted)
        {
            throw new InvalidOperationException("Synthetic failure did not settle within its budget.");
        }
        catch { failed = true; }
        Require(failed);
    }
    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Synthetic ready/progress contract failed.");
    }

    private sealed class PausedReader(string text, int pauseAt, bool ignoreCancellation = false) : TextReader
    {
        private readonly TaskCompletionSource<bool> _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _position;
        private bool _aborted;
        public void Release() => _released.TrySetResult(true);
        public void Abort() { _aborted = true; Release(); }
        public override async ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
        {
            if (_position >= pauseAt)
            {
                if (ignoreCancellation) await _released.Task;
                else await _released.Task.WaitAsync(cancellationToken);
            }
            if (_aborted || _position == text.Length) return 0;
            buffer.Span[0] = text[_position++];
            return 1;
        }
    }
}
