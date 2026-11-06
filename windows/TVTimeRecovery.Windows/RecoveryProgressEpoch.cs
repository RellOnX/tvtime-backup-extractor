namespace TVTimeRecovery.Windows;

// Callers apply progress and terminal UI state on the UI thread. A queued callback must
// check its captured epoch when it executes, not merely when it is enqueued.
internal sealed class RecoveryProgressEpoch
{
    private long _next;
    private long _active;

    public long Begin()
    {
        var epoch = Interlocked.Increment(ref _next);
        Interlocked.Exchange(ref _active, epoch);
        return epoch;
    }

    public bool IsCurrent(long epoch) => epoch != 0 && Volatile.Read(ref _active) == epoch;
    public void End(long epoch) => Interlocked.CompareExchange(ref _active, 0, epoch);
    public void CancelCurrent() => Interlocked.Exchange(ref _active, 0);
}
