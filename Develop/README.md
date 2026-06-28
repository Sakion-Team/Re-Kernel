# librekernel

The official Android library for connecting your tombstone (or any app) to the
[Re:Kernel](https://github.com/Sakion-Team/Re-Kernel) Netlink server.

Re:Kernel opens a kernel-side Netlink server that broadcasts Binder, Signal and
Network events. `librekernel` handles the socket, the Generic Netlink family
resolution and the message parsing for you, and delivers decoded events through
a single `Callback`.

It transparently supports both the current **Generic Netlink** protocol and the
**legacy** unit-based protocol (older Re:Kernel modules) — you write the same
code for both.

## Requirements

- `minSdk` 29

## Quick start

```java
int result = ReKernel.registerListener(new ReKernel.Callback() {
    @Override
    public void binder(int binderType, boolean oneway, int fromUid, int fromPid,
                       int targetUid, int targetPid, String rpcName, int code) {
        // A Binder event. binderType is one of:
        //   Callback.BINDER_TRANSACTION
        //   Callback.BINDER_REPLY
        //   Callback.BINDER_FREE_BUFFER_FULL
    }

    @Override
    public void signal(int signal, int killerUid, int killerPid,
                       int targetUid, int targetPid) {
        // A process is about to be signalled (e.g. killed).
    }

    @Override
    public void network(int proto, int targetUid, int dataLen) {
        // A monitored uid received a packet.
        // proto is Callback.PROTO_IPV4 or Callback.PROTO_IPV6.
    }

    @Override
    public void disconnected() {
        // The connection dropped unexpectedly (not on a clean unregister).
    }

    @Override
    public void exception(Exception exception) {
        // A non-fatal error occurred while receiving.
    }
}, /* searchNetlinkUnit = */ true, /* chooseNetlinkUnit = */ -1);

if (result == -1) {
    // Failed to connect — Re:Kernel not present, or not running as root.
}
```

Callbacks are dispatched on a dedicated `Re-Kernel` handler thread, not the main
thread.

When you're done:

```java
ReKernel.unregisterListener();
```

## API

### `registerListener(Callback callback, boolean searchNetlinkUnit, int chooseNetlinkUnit)`

Connects and starts receiving. Returns:

- `0` — connected via the modern Generic Netlink protocol
- `> 0` — connected via the legacy protocol; the value is the netlink unit used
- `-1` — failed (already running, null callback, or no server)

The library first tries the Generic Netlink family `rekernel`. If that family
can't be resolved it falls back to the legacy protocol automatically. The two
legacy parameters only matter on that fallback path:

| Parameter | Meaning |
|---|---|
| `searchNetlinkUnit` | Auto-detect the unit from `/proc/rekernel`. Pass `true` if you don't know it. |
| `chooseNetlinkUnit` | Pin a specific unit (valid range `22`–`26`). Used only when `searchNetlinkUnit` is `false`. Pass `-1` to ignore. |

If neither yields a unit, the legacy path falls back to the default unit (22).

### `unregisterListener()`

Closes the socket and invokes `Callback.disconnected()` once.

### `addMonitorNet(int uid)` / `delMonitorNet(int uid)`

Start / stop receiving `network()` events for a given uid. Returns `true` on
success. Network monitoring is opt-in per uid and is unavailable when running on
the legacy default unit (`isDefaultUnit()` returns `true`).

### State helpers

| Method | Returns |
|---|---|
| `isRunning()` | Whether a listener is currently connected |
| `isLegacy()` | Whether the legacy protocol is in use |
| `isDefaultUnit()` | Whether the legacy default unit (no network monitoring) is in use |

## Event reference

### Binder — `binder(binderType, oneway, fromUid, fromPid, targetUid, targetPid, rpcName, code)`

| `binderType` | Constant |
|---|---|
| transaction | `BINDER_TRANSACTION` (0) |
| reply | `BINDER_REPLY` (1) |
| free-buffer exhaustion | `BINDER_FREE_BUFFER_FULL` (2) |

### Signal — `signal(signal, killerUid, killerPid, targetUid, targetPid)`

The standard signal number, the sender (`killer*`) and the target process.

### Network — `network(proto, targetUid, dataLen)`

`proto` is `PROTO_IPV4` (4) or `PROTO_IPV6` (6). `dataLen` is the observed
payload length, or `DATA_LEN_UNKNOWN` (-1). Only fires for uids registered via
`addMonitorNet`.
