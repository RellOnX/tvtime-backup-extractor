# Isolated launcher contract checks

This test builds one new harmless .NET peer and launches it through the exact
production `NativeHelperProcess` source. It never launches, copies or retries the
installed or packaged recovery helper. It uses no Python, WinUI, real backup,
credentials, network, certificate installation, trust changes or registry edits.
The invented secret payload is the fixed string `synthetic-secret-only`.

## Source-bound staging contract

Publish these files under `tests/LauncherContractHarness`. The dedicated workflow
must stage them in a fresh child directory of `RUNNER_TEMP`. It must copy the
unchanged `windows/TVTimeRecovery.Windows/NativeHelperProcess.cs` from commit
`4689593beec8e7d9b80aacf5e95bf6117c9fb0e1` to
`Source/NativeHelperProcess.cs` in that staged directory and verify its expected
Git blob ID `d64ace7e0c2e7b454a36206297e4ca959feaeba7` before building.
`Harness/Harness.csproj` compiles that file directly.
The test files do not contain a replacement implementation of the launcher.

Select an already installed .NET 8 SDK using a generated `global.json` in the
staged root. Do not install an SDK, runtime, packages, certificates or the app.
Both projects use `net8.0`, no PackageReferences and cleared NuGet sources. The
peer's framework-dependent apphost must be available from the preinstalled SDK;
if restore cannot find required SDK packs, fail instead of enabling downloads.
Record the actual selected SDK version. The harness records its own runtime and
the peer runtime. No exact 8.0.29 runtime result is assumed.

The staged tree is:

```text
stage/
  global.json                 # Generated from a preinstalled SDK selection
  NuGet.Config
  Source/NativeHelperProcess.cs
  Harness/Harness.csproj
  Harness/Program.cs
  Peer/SyntheticProtocolPeer.csproj
  Peer/Program.cs
```

Build from the staged root with PowerShell, checking every exit code:

```powershell
dotnet restore ./Peer/SyntheticProtocolPeer.csproj --configfile ./NuGet.Config
if ($LASTEXITCODE -ne 0) { exit 1 }
dotnet build ./Peer/SyntheticProtocolPeer.csproj -c Release --no-restore
if ($LASTEXITCODE -ne 0) { exit 1 }
dotnet restore ./Harness/Harness.csproj --configfile ./NuGet.Config
if ($LASTEXITCODE -ne 0) { exit 1 }
dotnet build ./Harness/Harness.csproj -c Release --no-restore
if ($LASTEXITCODE -ne 0) { exit 1 }
$peer = (Resolve-Path ./Peer/bin/Release/net8.0/SyntheticProtocolPeer.exe).Path
dotnet ./Harness/bin/Release/net8.0/Harness.dll $peer
exit $LASTEXITCODE
```

The harness accepts only this exact peer output path relative to its own output
directory, and requires its staged root to be inside `RUNNER_TEMP`. The peer
accepts no command-line arguments, external paths or commands. Scenarios are a
small fixed set selected by the first synthetic control frame. Fresh empty
destination directories live under staged `RunData`; no recovered files are
created. Ephemeral runner teardown can discard them.

## Test matrix

| Check | Actual boundary exercised | Expected observation |
| --- | --- | --- |
| Round trip | Start, inherited control/stdout/secret/destination handles, framing, EventsAsync, successful exit | Ready identity matches, invented secret accepted, progress/completed/EOF |
| Early EOF | EventsAsync after ready | Clean EOF is observed; coordinator policy is not invoked |
| Malformed JSON | Production event parser | JsonException |
| Oversized line | Production bounded-line reader | InvalidDataException at 262,145 ASCII characters |
| Truncated EOF | Production bounded-line reader | InvalidDataException for a nonempty unterminated line |
| Silence after ready | Production EventsAsync with caller cancellation | Pending observation, then OperationCanceledException |
| Partial line | Production EventsAsync with caller cancellation | Pending observation, then OperationCanceledException |
| Cancel control | Actual CancelAsync and synthetic peer | Peer receives the cancel frame and emits cancelled |
| Unresponsive cleanup | Actual DisposeAsync and job containment | Peer ignores stdin/EOF, then process exit is independently observed |

Each peer normally emits ready before receiving its scenario. Silence therefore
means **after ready and a scenario acknowledgement**, not a silent startup.
The partial-line acknowledgement is sent just before the partial bytes; the
test does not instrument the exact point those bytes reach the reader.

The harness validates ready for its own setup. Production EventsAsync only parses
events; this test does not change or validate RecoveryCoordinator's handshake
policy. Coordinator source is not compiled here. Passing does not mean the
missing production ready validation or watchdog was fixed.

## Bounds and cleanup

I/O waits have five-second limits, production DisposeAsync has an external
fifteen-second limit, and each entire test has a thirty-five-second limit.
The entire test, including synchronous Start, runs behind that test watchdog.
Use an eight-minute maximum workflow/job ceiling as the final boundary.

On ordinary exit, a session cancels its event read, awaits actual production
disposal, settles an outstanding event read, disposes the enumerator and
independently waits for its known peer PID to exit. Any cleanup failure or test
timeout immediately exits the harness with failure and stops subsequent tests.
Any launch or initial-ready failure also stops the entire suite without retry,
including access-denied or other security restrictions. Later scenarios run only
after earlier startup checks succeeded.
Process exit closes its job handles, enabling the production kill-on-close job
policy. This is fail-fast containment, not a claim that WaitAsync itself cancels
underlying I/O. No crash dump is deliberately generated.

The peer also exits after a ninety-second lifetime limit. That is longer than
both the test and cleanup budgets, so it cannot make a normal cleanup test pass
by timing out first. Silent/partial scenarios intentionally ignore stdin and
EOF; the cleanup test monitors the peer before and after disposal.

Harness output is fixed PASS/FAIL labels plus runtime-version labels. It prints
no exception text, local paths, handle values or payload contents. SDK build
output is separate and controlled by the workflow.

## Limits

This does not exercise the blocked recovery executable, MSIX execution context,
Python packaging, real backup processing, WinUI, coordinator cancellation
registration, blocked large control writes, grandchildren, security policies or
all cleanup error paths. A 250 ms pending observation is not proof of an
infinite wait; the absence of a production watchdog is a separate source-review
finding. No short global idle timeout is recommended for legitimate long work.

Compilation and runtime results must be reported from the separately authorized
isolated CI run, not inferred from source review.
