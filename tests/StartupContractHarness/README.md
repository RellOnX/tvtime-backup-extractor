# Independent Windows startup contract checks

This dependency-free console harness tests two narrowly defined contracts. It is
not the recovery application, does not reference its binaries or source project,
and never starts its helper or another process. It uses no backup, credentials,
Python, MSIX, certificates, registry access, or security-setting changes.

## Provenance

The reproducer was designed from source review of
`RellOnX/tvtime-backup-extractor` at commit
`410f88964df6d5ce1fc7d56f899fafc47c84325c`:

- `windows/TVTimeRecovery.Windows/NativeHelperProcess.cs`, lines 173–177 and
  310–321: synchronous `CreatePipe` handles were wrapped with `isAsync: true`.
- `windows/TVTimeRecovery.Windows/RecoveryCoordinator.cs`, lines 185–195:
  progress is reported immediately before synchronous helper startup.
- `windows/TVTimeRecovery.Windows/MainWindow.xaml.cs`, lines 174–219:
  progress is deferred but terminal status is assigned immediately.

Official references:

- [Windows anonymous-pipe operations](https://learn.microsoft.com/en-us/windows/win32/ipc/anonymous-pipe-operations)
- [.NET 8.0.29 FileStream handle validation](https://github.com/dotnet/runtime/blob/v8.0.29/src/libraries/System.Private.CoreLib/src/System/IO/FileStream.cs#L87-L117)
- [.NET 8.0.29 async-over-sync read implementation](https://github.com/dotnet/runtime/blob/v8.0.29/src/libraries/System.Private.CoreLib/src/System/IO/RandomAccess.Windows.cs#L233-L269)
- [DispatcherQueue.TryEnqueue contract](https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.dispatching.dispatcherqueue.tryenqueue)

## What is checked

The pipe tests call real Win32 `CreatePipe` in this single process. They verify
that both ends are synchronous, that `FileStream(isAsync: true)` rejects a valid
synchronous handle, and that `isAsync: false` supports async API calls for a tiny
framed round trip, EOF and pending-read cancellation. The pipe handles are
noninheritable because these tests have no child process. This deliberately does
not reproduce or test the production inheritance configuration.

The FIFO tests are explicit single-threaded models. The baseline must reproduce
stale progress overwriting an immediate failure. The corrected model must reject
queued progress after failure, completion or cancellation, and must reject a
previous run's callback while still allowing current-run progress.

The model uses a captured operation identity and active flag. It is not compiled
production UI code and does not instantiate WinUI or a real DispatcherQueue.
Passing is not proof that production changes implement the same guard correctly.

## Running in the isolated Windows CI job

Use `windows-2022`, provision SDK **8.0.423** through the approved CI SDK setup,
and select a five-minute job timeout. Do not install tools on the user's PC.
Run the following PowerShell from this directory so `global.json` is honored:

```powershell
$ErrorActionPreference = "Stop"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_NOLOGO = "1"

if ((dotnet --version).Trim() -ne "8.0.423") {
    Write-Output "FAIL SDK_8_0_423_REQUIRED"
    exit 1
}
if (-not (dotnet --list-runtimes |
    Select-String '^Microsoft\.NETCore\.App 8\.0\.29 \[')) {
    Write-Output "FAIL RUNTIME_8_0_29_REQUIRED"
    exit 1
}

dotnet restore ./StartupContractHarness.csproj --configfile ./NuGet.Config
if ($LASTEXITCODE -ne 0) { exit 1 }
dotnet build ./StartupContractHarness.csproj --configuration Release --no-restore
if ($LASTEXITCODE -ne 0) { exit 1 }
dotnet --fx-version 8.0.29 ./bin/Release/net8.0/StartupContractHarness.dll
exit $LASTEXITCODE
```

The project has no package references, no apphost and no self-contained runtime
pack. `NuGet.Config` clears package sources. Missing SDK components should fail
the job rather than prompt a fallback download or a broader build.

The harness emits fixed `PASS`/`FAIL` labels only, with exit code zero only when
all checks pass. It does not print exception details, handle values, paths or
payloads. SDK restore/build output is separate from harness output; the workflow
owns whether that output is shown. No production application build, package,
signing, installation or helper smoke test belongs in this job.

## Timeout and cleanup boundaries

Each I/O wait is bounded at three seconds, read cleanup at three seconds, and an
individual test at fifteen seconds. `Task.WaitAsync` only bounds waiting. For a
pending read, cleanup closes the sole writer to release the read, then observes
the read task. A cleanup timeout fails the suite and stops further tests. The CI
job timeout is a final boundary, not a claim of graceful cleanup on every fault.

The round-trip frame is only ten bytes in an empty 4096-byte pipe. This does not
test a full pipe or blocked-write cancellation. The cancellation test confirms
that a read task is externally pending before cancelling; it does not prove
exactly when the operating system began its underlying read.

## What passing does not establish

Passing does not establish that the installed helper may execute, that its
package or permissions are correct, that inherited handles reach a child, that
the production cancellation/disposal path is bounded, or that recovery works.
It does not exercise real WinUI scheduling, cross-thread races, process exit,
the production startup watchdog, or the user's original incident. The installed
helper's denied launch is not retried or bypassed by this harness.

This source was authored for review without local execution. Results must be
reported only after the separately authorized isolated CI run completes.
