const { parentPort, workerData } = require("worker_threads");
const fs = require("fs");
const path = require("path");

// Simple worker that receives messages from the main thread,
// queues them, and writes them to a log file in JSON lines format.

// Default to a logs/ subdirectory next to this file so that
// Docker bind mounts like ./logs:/app/logs pick it up even if
// FLOW_LOG_FILE is not set.
const logFile = process.env.FLOW_LOG_FILE || path.join(__dirname, "logs", "flow.log");
const logDir = path.dirname(logFile);

// When FLOW_DEBUG is set (e.g. 1, true, yes), log every message that passes through,
// including those that are routed to localDb or api (which are otherwise not written).
const debug = /^(1|true|yes)$/i.test(String(process.env.FLOW_DEBUG || "").trim());

// Check if .env is present and readable; use path from main thread (workerData.envPath) if provided
const envPath = (workerData && workerData.envPath) ? workerData.envPath : path.resolve(__dirname, ".env");
let envStatus = "ok";
try {
  fs.accessSync(envPath, fs.constants.R_OK);
} catch (_) {
  envStatus = ".env not found";
}

// Ensure the log directory exists so that appendFile succeeds even
// when the directory is missing (e.g. fresh container, new bind mount).
try {
  fs.mkdirSync(logDir, { recursive: true });
} catch (err) {
  console.error("Flow worker: failed to create log directory:", err);
}

console.log("Flow worker: logging to", logFile, debug ? "(debug: log all messages)" : "");

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

// Log startup and current debug level to the flow log
queue.push({
  kind: "flowWorker.start",
  payload: envStatus === ".env not found" ? { debug, env: envStatus, envPath } : { debug, env: envStatus },
  ts: new Date().toISOString(),
});
writeNext();

if (!parentPort) {
  throw new Error("Flow worker must be started as a worker thread.");
}

parentPort.on("message", (msg) => {
  if (debug) {
    queue.push(msg);
    writeNext();
  }
  const target = msg.payload && msg.payload.target;
  if (msg.kind === "entry.sendToFlow" && target === "localDb") {
    parentPort.postMessage({
      kind: "createEntryInProfile",
      targetProfileId: (msg.payload.param != null ? String(msg.payload.param) : "").trim(),
      sourceDocId: msg.payload.entryId,
      dataset: msg.payload.dataset,
    });
    return;
  }
  if (msg.kind === "entry.sendToFlow" && target === "api") {
    parentPort.postMessage({
      kind: "callApi",
      apiDocId: (msg.payload.param != null ? String(msg.payload.param) : "").trim(),
      entryId: msg.payload.entryId,
      profileId: msg.payload.profileId,
      dataset: msg.payload.dataset,
    });
    return;
  }
  if (!debug) {
    queue.push(msg);
    writeNext();
  }
});

