require('dotenv').config();

const express = require('express');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const { ensureSingleInstance } = require('../scripts/lib/single-instance');

const app = express();
const PORT = process.env.DASHBOARD_PORT || 8080;
const WS_PORT = process.env.WS_PORT || 8081;

// Serve static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// Stats are derived from security.log rather than a live SecurityMonitor
// instance: the dashboard runs in its own process, separate from the one
// actually doing the monitoring (see `pnpm run monitor`), so an in-memory
// singleton here would only ever reflect this idle process, not real activity.
function computeStats() {
  const { Logger } = require('../monitor/logger');
  const logger = new Logger('./security.log');
  const entries = logger.search(null, { limit: Number.MAX_SAFE_INTEGER });

  const stats = {
    uptime: 0,
    commands: { blocked: 0, allowed: 0 },
    filesystem: { blocked: 0, allowed: 0 },
    network: { blocked: 0, allowed: 0 },
    logs: logger.getStats()
  };

  for (const entry of entries) {
    const blocked = entry.result?.blocked === true;
    if (['exec', 'spawn', 'execFile'].includes(entry.type)) {
      blocked ? stats.commands.blocked++ : stats.commands.allowed++;
    } else if (entry.type === 'fs') {
      blocked ? stats.filesystem.blocked++ : stats.filesystem.allowed++;
    } else if (entry.type === 'network' || entry.type === 'network-payload') {
      blocked ? stats.network.blocked++ : stats.network.allowed++;
    }
  }

  if (entries.length > 0) {
    stats.uptime = Math.floor((Date.now() - new Date(entries[0].timestamp)) / 1000);
  }

  return stats;
}

app.get('/api/config', (req, res) => {
  res.json({ wsPort: Number(WS_PORT) });
});

// API endpoints
app.get('/api/stats', (req, res) => {
  res.json(computeStats());
});

app.get('/api/rules', (req, res) => {
  try {
    const rulesPath = path.join(__dirname, '..', 'config', 'rules.json');
    const data = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load rules', message: err.message });
  }
});

app.get('/api/logs', (req, res) => {
  const { Logger } = require('../monitor/logger');
  const logger = new Logger('./security.log');
  const logs = logger.search(req.query.query, {
    limit: parseInt(req.query.limit) || 100
  });
  res.json(logs);
});

async function start() {
  // Stop any previous dashboard instance still holding these ports before
  // binding, so re-launching doesn't just crash with EADDRINUSE.
  await ensureSingleInstance('dashboard', [PORT, WS_PORT]);

  // Create WebSocket server
  const wss = new WebSocket.Server({ port: WS_PORT });

  wss.on('connection', (ws) => {
    console.log('Client connected to WebSocket');

    // Watch log file changes
    const logPath = path.join(__dirname, '../security.log');
    let watcher = null;

    try {
      watcher = fs.watch(logPath, (event) => {
        if (event === 'change') {
          const content = fs.readFileSync(logPath, 'utf8');
          const lines = content.split('\n').filter(line => line.trim());
          const lastLine = lines[lines.length - 1];

          if (lastLine) {
            try {
              const data = JSON.parse(lastLine);
              ws.send(JSON.stringify({
                type: 'log',
                data: data
              }));
            } catch (e) {
              // Ignore parsing errors
            }
          }
        }
      });
    } catch (err) {
      console.error('Failed to watch log file:', err.message);
    }

    ws.on('close', () => {
      if (watcher) {
        watcher.close();
      }
      console.log('Client disconnected');
    });

    // Send initial stats
    ws.send(JSON.stringify({
      type: 'stats',
      data: computeStats()
    }));
  });

  app.listen(PORT, () => {
    console.log(`📊 Dashboard running on http://localhost:${PORT}`);
  });
}

start();