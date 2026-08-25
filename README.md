# gil-sec

A Node.js security monitor that patches `child_process`, `fs`, and `net` in
the process that loads it, so dangerous commands, filesystem operations, and
outgoing network requests can be detected and blocked before they run.

## Quick start

```bash
pnpm install
pnpm start        # run the monitor standalone
pnpm run monitor  # run the monitor + web dashboard together
pnpm run simulate # exercise it against a set of safe/malicious scenarios
pnpm test         # run the test suite
```

Both ports are configured via `.env`:

| Variable | Purpose | Default | This repo's `.env` |
|---|---|---|---|
| `DASHBOARD_PORT` | Dashboard HTTP server | `8080` | `5005` |
| `WS_PORT` | WebSocket live-update feed | `8081` | `8081` |

Open `http://localhost:<DASHBOARD_PORT>` while `pnpm run monitor` is
running — the page fetches `WS_PORT` from the server itself
(`GET /api/config`) rather than hardcoding it.

### Docker

```bash
docker compose up --build
```

Runs the monitor + dashboard together in one container, publishing
`5005` (dashboard) and `8081` (WebSocket feed), and bind-mounts
`security.log` to the host so it survives container restarts and stays
inspectable outside Docker. Override the port with
`DASHBOARD_PORT=9000 docker compose up --build` (update the `ports:` mapping
in `docker-compose.yml` to match if you do).

Without Compose:

```bash
docker build -t gil-sec .
docker run -p 5005:5005 -p 8081:8081 -v $(pwd)/security.log:/app/security.log gil-sec
```

## What it protects against

### Commands (`monitor/command-monitor.js`, `monitor/rules-engine.js`)

Hooks `child_process.exec` / `spawn` / `execFile` and checks every command
against the rules in `config/rules.json`:

| Rule | Blocks |
|---|---|
| R001 File Deletion | `rm -rf`, `rmdir /s`, `del /f` |
| R002 System Modification | `chmod 777`, `chown -R`, `mount`, `fdisk`, `mkfs` |
| R003 Network Attacks | `curl \| sh`, `wget \| sh`, `nc -e`, `telnet`, `ssh -R` |
| R004 Process Manipulation | `kill -9`, `pkill`, `killall`, `systemctl stop/disable` (warns, doesn't block) |
| R005 Data Exfiltration | reading `/etc/passwd`, `/etc/shadow`, `.env`/`.pem`/`.key` files |
| R006 Command Injection | `; rm`, `&& rm`, `` `rm` ``, `$(rm)`, chained `wget`/`curl` |
| R007 Blockchain RPC Access | known Ethereum RPC hosts (publicnode, Infura, Cloudflare) — commonly abused for wallet-draining exfiltration |

A short whitelist (`echo`, `ls`, `pwd`, `whoami`, `date`) always passes.
Add new rules at runtime with `monitor.addRule({...})` — it's persisted back
to `config/rules.json`.

### Filesystem (`monitor/fs-monitor.js`)

Hooks `fs.unlink`, `fs.rmdir`, and `fs.writeFile`. Blocks writes/deletes
under a configured list of protected paths (`/etc`, `/bin`, your home
directory, etc.) unless the file extension is explicitly allowlisted
(`.txt`, `.log`, `.tmp`, `.cache`).

### Network (`monitor/network-monitor.js`)

Two layers:

- **Connection blocking** — hooks `net.Socket.prototype.connect`. Blocks
  loopback addresses, a configured host blocklist (includes known Ethereum
  RPC endpoints by default), and a set of suspicious ports (22, 3389, 5432,
  3306, 27017, ...).
- **Credential exfiltration scanning** — hooks `net.Socket.prototype.write`
  and scans every outgoing payload for GitHub tokens, GitHub fine-grained
  PATs, AWS access keys, and `Authorization: Bearer` headers. A match blocks
  the write before anything leaves the machine — *unless* the destination is
  a trusted host for that credential (e.g. a GitHub token going to
  `github.com` is normal auth, not exfiltration).

DNS lookups (`dns.resolve`) are also flagged for suspicious TLDs
(`.onion`, `.tor`, `.top`, `.ru`, `.cn`, ...).

## Dashboard

`dashboard/server.js` serves `public/` and exposes:

- `GET /api/stats` — aggregate counts computed from `security.log`
- `GET /api/logs?query=&limit=` — search recent log entries
- WebSocket (`:8081`) — pushes live `log` events as they're written, plus an
  initial `stats` snapshot on connect (auto-reconnects if the server
  restarts)

The monitor and dashboard normally run as **separate processes**
(`pnpm run monitor` uses `concurrently`), so they only share state through
`security.log` on disk — there's no shared in-memory instance between them.

## Logging

Every intercepted operation is appended as JSON to `security.log`
(`monitor/logger.js`), buffered and flushed roughly once a second or every
100 entries. `SecurityMonitor.shutdown()` flushes all buffers before
stopping.

## Project layout

```
index.js              # SecurityMonitor — wires up all monitors + periodic stats
monitor/
  command-monitor.js   # child_process hooks
  fs-monitor.js         # fs hooks
  network-monitor.js    # net/dns hooks + credential scanning
  rules-engine.js        # loads/matches config/rules.json
  logger.js              # buffered JSON log writer
config/rules.json      # command rules (see table above)
dashboard/server.js    # Express + WebSocket dashboard backend
public/                # dashboard frontend
scripts/simulate.js    # runs realistic scenarios through the real monitor
tests/                 # Jest unit + integration tests
```

## Run automatically on startup (Windows / macOS / Linux)

```bash
pnpm run startup:install    # set it up
pnpm run startup:uninstall  # remove it
```

Detects the OS and installs the right thing, all running `pnpm run monitor`
under your own user account — no admin/root rights needed:

| OS | Mechanism | Trigger |
|---|---|---|
| Windows | Scheduled Task (`gil-sec-security-monitor`) via `scripts/register-startup-task.ps1` | user logon |
| macOS | launchd agent (`~/Library/LaunchAgents/com.gilsec.monitor.plist`) | user login, `KeepAlive` restarts it if it dies |
| Linux | systemd user service (`~/.config/systemd/user/gil-sec.service`) | user login, `Restart=on-failure` |

On Linux, add `loginctl enable-linger $USER` if you want it to keep running
after you log out. None of these start it before any user logs in — for
that you'd need a true system service (Windows Service via NSSM, a root
systemd unit, or a `launchd` daemon in `/Library/LaunchDaemons`) instead.

## Notes / limitations

- Monitoring is per-process: it only sees `child_process`/`fs`/`net` calls
  made by whatever Node process actually `require()`s this module — it does
  not intercept commands run in other terminals or other processes.
- `FSMonitor` and `NetworkMonitor` don't currently expose a `restore()` (only
  `CommandMonitor` does), so their hooks stay installed for the life of the
  process.
