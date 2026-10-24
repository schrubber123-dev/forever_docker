# Windows launch investigation (1.60.1.70450)

The launcher starts `WowB.exe -launcherlogin -config ForeverLauncher.wtf` in the
configured game directory. It writes these values under the current Windows user:

`HKCU\Software\Blizzard Entertainment\Battle.net\Launch Options\WoW`

| Value | Type | Encoding |
|---|---|---|
| `CONNECTION_STRING` | `REG_SZ` | NUL-terminated UTF-16, portal hostname and port |
| `GAME_ACCOUNT` | `REG_SZ` | NUL-terminated UTF-16, account name returned by REST (e.g. `WoW1`) |
| `WEB_TOKEN` | `REG_BINARY` | Current-user DPAPI, UTF-8 ticket bytes without a trailing NUL, Battle.net entropy |

## Diagnostic build and log

The diagnostic workflow runs on launcher changes pushed to `main`, or manually
through Actions > Launcher > Run workflow with **version left empty**. It builds
Windows only, runs native library tests, and uploads the `Forever-Launcher-Windows`
artifact without publishing a release. The artifact contains the portable
`forever-launcher.exe`, installer and `diagnostic-build.txt` identifying the exact
commit. The same revision appears in each diagnostic log session header.

On Windows, pressing **Play** opens/appends to:

```text
%APPDATA%\forever-launcher-app\windows-launch-diagnostics.log
```

Paste that path into Explorer or open it with:

```powershell
notepad "$env:APPDATA\forever-launcher-app\windows-launch-diagnostics.log"
```

The launcher's existing log panel also shows the resolved absolute log path.
No console, developer tools or debug build is needed. Login alone does not write
registry diagnostics: they are recorded on Play, after REST ticket retrieval.
A failure to open the file is shown as a launch error. Session sections append,
so copy the latest section starting at `=== Play session; revision=... ===`.

For each registry value the file records the `RegQueryValueExW` status (0 means
success), actual registry type (name and number), and byte length. REG_SZ lengths
include the UTF-16 NUL terminator. It compares read-back bytes, checks DPAPI
plaintext against the ticket, and records SUCCESS/FAILED/NOT RUN. If opening or
writing the key fails, the file instead records that prerequisite failure; values
not reached are not claimed as verified. It never records either form of the
ticket, account values, password, REST responses or environment variable values.
Inherited `BNET_*` **names only** are recorded even if REST preparation fails.
This proves the launcher's user-context check, not the game's acceptance.

Immediately before spawning WowB, a process snapshot reports already running
`Agent.exe` and `WowB.exe` instances (PID and parent PID). After spawn it logs the
new WowB PID, then observes appearances/disappearances for 60 seconds at 250ms
intervals. An empty list means none observed; errors are explicit. This does not
start/stop Agent or change its environment. A new Agent PID is an observation,
not proof it was caused by WowB or a relaunch. Brief processes may be missed;
Procmon supplies exact process-start evidence.

## Short Windows test

1. In Actions, open the Launcher run for the new diagnostic commit. Wait for
   **build** to pass; **release** should be skipped. Download and extract its
   `Forever-Launcher-Windows` artifact. Check `diagnostic-build.txt`, then run the
   extracted `forever-launcher.exe` as your normal Windows user. Avoid an older
   installed shortcut. Leave existing Agent state unchanged for the first test.
2. Start the Procmon capture below before Login. Login, press Play once, wait at
   least 65 seconds, then stop capture. Record the game's visible outcome.
3. Copy the latest complete session from the diagnostic log. Confirm its revision
   matches `diagnostic-build.txt`. Send that section and the selected Procmon rows
   described below. Do not send registry exports, raw PML files, full Process
   Start details/environment, or any token bytes.

The known starting point remains: WowB successfully reads WEB_TOKEN and
CONNECTION_STRING (`trinity.actual.battle.net:1119`, 62 UTF-16 bytes including NUL),
but previously made no connection to the private server on TCP/1119. GAME_ACCOUNT
consumption and game-context ticket acceptance remain unconfirmed.

## Exact Procmon capture and display filters

Run Procmon elevated if needed; keep the launcher/game non-elevated. Stop capture
(Ctrl+E), reset filters (Ctrl+L > Reset), clear events (Ctrl+X). Enable Registry,
Network and Process/Thread activity. Disable **Filter > Drop Filtered Events**
so switching views later does not discard needed events. Disable **Options >
Resolve Network Addresses** to keep port numbers numeric. Start capture (Ctrl+E)
before Login/Play and stop after the wait. Keep the raw capture local: registry
and process details may contain credentials.

Apply these as **three separate views**, resetting filters between them. Each
listed row is an Include filter. Procmon ORs Include rows on the same column and
ANDs different columns; do not combine all three views in one filter set.

**A. WowB registry reads**

| Column | Relation | Value |
|---|---|---|
| Process Name | is | `WowB.exe` |
| Operation | is | `RegOpenKey` |
| Operation | is | `RegQueryValue` |
| Path | begins with | `HKCU\Software\Blizzard Entertainment\Battle.net\Launch Options\WoW` |

If your Procmon renders the observed key as `HKU\S-1-...` rather than `HKCU`,
use that exact user SID prefix in the Path row. Record results for WEB_TOKEN,
CONNECTION_STRING and GAME_ACCOUNT, including NAME NOT FOUND if observed.
Copy Time of Day, Process Name, PID, Operation, Path, Result; manually add type
and length only from Detail. Never copy WEB_TOKEN Data.

**B. WowB/Agent process starts and exits**

| Column | Relation | Value |
|---|---|---|
| Process Name | is | `WowB.exe` |
| Process Name | is | `Agent.exe` |
| Operation | is | `Process Start` |
| Operation | is | `Process Exit` |

Copy time, process name, PID, operation and parent PID. Copy only the WowB
command line if it contains no credentials. Do not copy the full Detail field
or environment. To inspect parent-side Process Create events too, use a separate
view with **only** `Operation is Process Create Include`, then Find `WowB.exe`
and `Agent.exe` in the child paths; a process-name filter would hide events whose
parent has a different name (including the launcher).

**C. TCP/1119 connections**

| Column | Relation | Value |
|---|---|---|
| Process Name | is | `WowB.exe` |
| Process Name | is | `Agent.exe` |
| Operation | is | `TCP Connect` |
| Operation | is | `TCP Reconnect` |
| Path | ends with | `:1119` |

Copy time, process name, PID, operation, path and result, or explicitly report
**zero matching rows**. For an HTTPS comparison, replace the Path filter with
`ends with :443` and send only connection metadata. Report whether TCP/1119
reached `192.168.188.106`; do not equate unrelated Agent HTTPS activity with a
proven cause of missing Battle.net traffic.

## Upstream comparison

[Shauren/tc-client-launcher, revision 9c3e911](https://github.com/Shauren/tc-client-launcher/blob/9c3e9112823f216d1f7ef51782c91ce850a31957/src/native/Win32Launcher.cpp)
writes only these three values with the same types and DPAPI entropy. Its
DPAPI input is `strlen(ticket)` bytes, consistent with this launcher. The DPAPI
description differs; descriptions are metadata, not decryption entropy.
It passes the game account string through without adding a region suffix.
There is no evidence there for additional region/product launch-option values.

However, Shauren launches **Arctium**, and uses a different registry vendor path.
[Arctium/Burralis, revision ed59218](https://github.com/Arctium/WoW-Launcher/blob/ed59218c3a5847510fde05fc2b3c5a874abd9d39/src/Launcher.cs)
starts suspended and patches the portal suffix, registry path and crypto keys
before resuming. This repository starts the client directly and patches only the
realm encryption key after startup. Consequently, upstream success is not proof
that an unmodified direct launch has equivalent endpoint selection. Its patches
must not be copied blindly: the reported client already reads our registry path,
and the target build must first be inspected for the relevant startup behavior.

No Agent bypass, extra region/product registry values, protocol changes, build
changes or launch-argument changes are implemented. Await the runtime results
before choosing a behavioral fix.

## Native client log finding and socket diagnostics

The supplied client logs from 2026-10-24 11:33-11:34 select the private endpoint:

```text
Glue login started ... launcherPortal="trinity.actual.battle.net:1119" loginPortal="trinity.actual.battle.net:1119"
Battle.net logon requested host="trinity.actual.battle.net" port="1119"
Battle.net front disconnected ... reason="ERROR_NETWORK_MODULE_SOCKET_CLOSED (1016)"
```

The request and error share the same logged millisecond. This proves endpoint
selection and a native socket-closed result, not its underlying cause or whether
the peer was contacted. The two uploads of these connection logs are identical,
not two independent reproductions. The earlier Procmon excerpt is from 11:05;
do not combine them as a synchronized network capture.

This evidence weakens the hypothesis that Agent prevents reaching the login path.
Agent's `playable:false` is still a reported product state, not a proven blocking
branch. No Agent bypass, build change, guessed signature or transport override is
justified. Likewise, the QUIC message concerns enabling logging, not a proven
transport failure.

Absence of a Procmon TCP Connect event must not be treated as proof that no
native connect operation was attempted. To obtain the actual connect result,
use the standalone helper in `scripts/windows-network-diagnostics/`:

1. Download the `Forever-Network-Diagnostics` artifact from the **Windows network
   diagnostics** workflow and extract it. Close WoW normally first, keeping the
   normal launcher open. Double-click `Start-Network-Diagnostics.cmd`.
2. Accept elevation for the tracing helper only. Press Play in the existing
   **normal, non-elevated launcher** when the helper says the trace is running.
3. Let the capture finish. Send the ZIP it creates on the Desktop. Keep the raw
   ETL files locally. The helper does not launch, patch or stop the game or Agent.

The helper records machine-wide socket metadata and DNS names, so close unrelated
applications first. It explicitly enables only Winsock-AFD and DNS-Client at
information level 4, with bounded circular ETL files. It does not enable packet,
HTTP-body, registry or process-environment capture. Provider availability and ETW
decoding must succeed; failures must not be interpreted as absence of traffic.

Microsoft documents AFD socket-create events with `UserModePid`, connect requests
(IDs 4/5), connect completion/error (ID 6), bind failures, resets and closes at
this level. Correlate later events by their kernel Process/Endpoint fields back
to socket creation; asynchronous events can have a System header PID. Inspect
the loss summary before making any claim about missing events.

The helper's Windows CI self-test exercises successful and refused loopback
connections, verifies that socket creation/connect/completion events were
actually decoded, and exercises XML/ZIP export. That validates collection on the
runner, not the game or the user's computer.

Sources: [Winsock tracing control](https://learn.microsoft.com/en-us/windows/win32/winsock/control-of-winsock-tracing),
[information-level events](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-levels),
[event fields](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-event-details).

## Earlier compilation checks

Run `cargo test --locked --lib` in `app/src-tauri` with `FOREVER_CA_CERT` set to a
public PEM CA certificate. Windows additionally runs a native DPAPI test covering
round-trip success, a different expected ticket and an invalid blob. The existing
Windows launcher workflow runs this suite before building. A Linux cross-check
cannot execute Windows DPAPI or reproduce the game's endpoint selection.

Investigation validation on the Linux cloud machine:

- `FOREVER_CHECK_ONLY=1 cargo check --locked --tests --target x86_64-pc-windows-gnu`
  passed with a temporary test CA supplied through `FOREVER_CA_CERT` (not a
  production server certificate).
- The full `cargo test --locked --lib` command stopped before test execution
  because GLib development libraries are missing. Package installation was
  unavailable to this machine's non-root user.
- The four existing translation and Wine-DPAPI tests passed in a temporary
  standalone Cargo harness importing the original source modules. This is a
  subset check, not a successful Tauri library test run.
- The new native Windows DPAPI test was compiled by the cross-check, but cannot
  be executed here. Actual game/Agent behavior still needs Windows validation.
