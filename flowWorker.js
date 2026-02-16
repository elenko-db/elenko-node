const { parentPort } = require("worker_threads");
const fs = require("fs");
const path = require("path");

// Simple worker that receives messages from the main thread,
// queues them, and writes them to a log file in JSON lines format.

// Default to a logs/ subdirectory next to this file so that
// Docker bind mounts like ./logs:/app/logs pick it up even if
// FLOW_LOG_FILE is not set.
const logFile = process.env.FLOW_LOG_FILE || path.join(__dirname, "logs", "flow.log");
const logDir = path.dirname(logFile);

// Ensure the log directory exists so that appendFile succeeds even
// when the directory is missing (e.g. fresh container, new bind mount).
try {
  fs.mkdirSync(logDir, { recursive: true });
} catch (err) {
  console.error("Flow worker: failed to create log directory:", err);
}

console.log("Flow worker: logging to", logFile);

const queue = [];
let writing = false;

function writeNext() {
  if (writing || queue.length === 0) return;
  writing = true;
  const msg = queue.shift();

  const line = JSON.stringify({
    ...msg,
    ts: msg.ts || new Date().toISOString(),
  }) + "\n";

  fs.appendFile(logFile, line, (err) => {
    if (err) {
      // Logging errors should not crash the worker; report to stderr instead.
      console.error("Flow worker: log write error:", err);
    }
    writing = false;
    writeNext();
  });
}

if (!parentPort) {
  throw new Error("Flow worker must be started as a worker thread.");
}

parentPort.on("message", (msg) => {
  queue.push(msg);
  writeNext();
});

