# Windows launch investigation (1.60.1.70450)

The launcher starts `WowB.exe -launcherlogin -config ForeverLauncher.wtf` in the
configured game directory. It writes these values under the current Windows user:

`HKCU\Software\Blizzard Entertainment\Battle.net\Launch Options\WoW`

| Value | Type | Encoding |
|---|---|---|
| `CONNECTION_STRING` | `REG_SZ` | NUL-terminated UTF-16, portal hostname and port |
| `GAME_ACCOUNT` | `REG_SZ` | NUL-terminated UTF-16, account name returned by REST (e.g. `WoW1`) |
| `WEB_TOKEN` | `REG_BINARY` | Current-user DPAPI, UTF-8 ticket bytes without a trailing NUL, Battle.net entropy |

Before starting the game, Windows now reads back all three values, verifies their
types and exact bytes, and decrypts the stored ticket with the expected entropy.
A failure stops launch with the affected value's name or DPAPI error. Success
appears in the launcher's log, followed by inherited `BNET_*` variable names (an
empty list means none were present). Values are never logged or changed.
Neither encrypted nor plaintext tickets are logged.
This verifies the launcher's user context; it does not prove that the game runs
as that same user, consumes the ticket, or connects to the server.

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

## Next Windows capture

The reported successful REST login, trusted certificate, hosts resolution and
reachable port 1119 do not explain a client that never attempts that connection.
External HTTPS activity alone also does not identify the endpoint-selection branch
(Agent may independently access content/version services).

1. Run the diagnostic launcher as the same non-elevated user as the game. Record
   whether the launch-options verification succeeds. Do not share ticket contents.
2. In Procmon, capture `WowB.exe` and `Agent.exe` process creation (including parent,
   command line and user), registry reads and TCP connections from before Play.
   Record `RegQueryValue` results and value types/lengths for the three values.
   Redact all `WEB_TOKEN` data before sharing a trace or screenshot.
3. Record the actual child's command line, whether it restarts through Agent, and
   any `BNET_*` variable **names only** inherited from the launcher's parent.
4. Correlate the game's startup/connection logs with that capture, redacting
   credentials and tickets. A successful read alone does not prove successful
   DPAPI decryption in the game's context or acceptance of the endpoint.

The cause of the missing 1119 connection is still unconfirmed. No Agent bypass,
extra registry values, protocol changes, build changes or argument changes are
implemented on the basis of this comparison.

## Tests

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
