const fs = require('fs');
const path = require('path');
const net = require('net');
const { execSync } = require('child_process');

const PID_DIR = path.join(__dirname, '..', '..', '.pids');

function pidFilePath(name) {
  return path.join(PID_DIR, `${name}.pid`);
}

function isRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// A pidfile written by an older version of this module may just be a bare
// number — fall back to that shape instead of failing to parse it.
function readPidRecord(file) {
  const raw = fs.readFileSync(file, 'utf8').trim();
  try {
    const parsed = JSON.parse(raw);
    // A bare-number pidfile (old format) parses fine as JSON too, just not
    // into an object — treat that case as the legacy format as well.
    if (parsed && typeof parsed === 'object') return parsed;
    return { pid: Number(parsed) };
  } catch {
    return { pid: parseInt(raw, 10) };
  }
}

// Before killing a recorded ancestor PID, confirm it still looks like our
// own launcher (pnpm/concurrently) and not some unrelated process that
// happens to have reused that PID since we last recorded it.
function looksLikeOurWrapper(pid) {
  if (process.platform !== 'win32') return true;
  try {
    const out = execSync(
      `powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \\"ProcessId=${pid}\\" -ErrorAction SilentlyContinue).CommandLine"`,
      { encoding: 'utf8' }
    );
    return /concurrently|pnpm/i.test(out);
  } catch {
    return false;
  }
}

// Kills `pid` and, where the platform supports it, anything still running
// underneath it — a lone SIGKILL only ever removes that one process, leaving
// its parent (pnpm/concurrently) as an orphan once its last child is gone.
function killTree(pid) {
  if (process.platform === 'win32') {
    try {
      execSync(`taskkill /PID ${pid} /T /F`, { stdio: 'ignore' });
    } catch {
      // already gone
    }
    return;
  }

  try {
    // Negative pid targets the whole process group, covering a shell-spawned
    // wrapper and its children in one shot when they share a group.
    process.kill(-pid, 'SIGKILL');
  } catch {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      // already gone
    }
  }
}

function waitForPortFree(port, timeoutMs = 3000) {
  return new Promise(resolve => {
    const deadline = Date.now() + timeoutMs;

    const tryBind = () => {
      const tester = net.createServer();
      tester.once('error', () => {
        if (Date.now() > deadline) {
          resolve(false);
          return;
        }
        setTimeout(tryBind, 100);
      });
      tester.once('listening', () => tester.close(() => resolve(true)));
      tester.listen(port, '0.0.0.0');
    };

    tryBind();
  });
}

// Kills whatever previous instance of `name` is still running (tracked via a
// pidfile under .pids/), then claims the lock for this process. If `ports`
// are given, waits for each to actually become free before returning, since
// killing a process doesn't release its listening sockets synchronously.
async function ensureSingleInstance(name, ports = []) {
  fs.mkdirSync(PID_DIR, { recursive: true });
  const file = pidFilePath(name);

  if (fs.existsSync(file)) {
    const record = readPidRecord(file);
    const oldPid = record.pid;

    if (oldPid && oldPid !== process.pid && isRunning(oldPid)) {
      console.log(`[single-instance] Stopping previous '${name}' instance (pid ${oldPid})...`);

      // Take out the launcher (pnpm/concurrently) first, verified so we
      // never kill an unrelated process that has since reused that PID —
      // otherwise it's left behind as an orphan once its last child dies.
      if (record.ppid && record.ppid !== oldPid && isRunning(record.ppid) && looksLikeOurWrapper(record.ppid)) {
        console.log(`[single-instance] Also stopping its launcher (pid ${record.ppid})...`);
        killTree(record.ppid);
      }

      killTree(oldPid);

      for (const port of ports) {
        await waitForPortFree(port);
      }
    }
  }

  fs.writeFileSync(file, JSON.stringify({ pid: process.pid, ppid: process.ppid }));

  const cleanup = () => {
    try {
      const record = readPidRecord(file);
      if (record.pid === process.pid) {
        fs.unlinkSync(file);
      }
    } catch {
      // ignore — file may already be gone, or claimed by a newer instance
    }
  };

  process.on('exit', cleanup);
  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

module.exports = { ensureSingleInstance };
