const { parentPort, workerData, Worker } = require("worker_threads");
const fs = require("fs");
const path = require("path");

// Simple worker that receives messages from the main thread,
// queues them, and writes them to a log file in JSON lines format.

// Default to a logs/ subdirectory next to this file so that
// Docker bind mounts like ./logs:/app/logs pick it up even if
// FLOW_LOG_FILE is not set.
const logFile = process.env.FLOW_LOG_FILE || path.join(__dirname, "logs", "elenko.log");
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

let scriptWorker = null;
try {
  const scriptWorkerPath = path.join(__dirname, "scriptWorker.js");
  scriptWorker = new Worker(scriptWorkerPath, {
    workerData: {},
  });
  scriptWorker.on("error", (err) => {
    // Forward to main via a flow log message; also surface errors to stderr.
    parentPort.postMessage({
      type: "scriptWorker.error",
      error: err && err.message ? err.message : String(err),
    });
    console.error("Flow worker: scriptWorker error:", err);
  });
} catch (err) {
  console.error("Flow worker: failed to start scriptWorker:", err);
}

const queue = [];
let writing = false;

function writeNext() {
  if (writing || queue.length === 0) return;
  writing = true;
  const msg = queue.shift();
  const line = JSON.stringify({
    ...msg,
    ts: (msg && msg.ts) || new Date().toISOString(),
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
  type: "flowWorker.start",
  payload: envStatus === ".env not found" ? { debug, env: envStatus, envPath } : { debug, env: envStatus },
  ts: new Date().toISOString(),
});
writeNext();

if (!parentPort) {
  throw new Error("Flow worker must be started as a worker thread.");
}

parentPort.on("message", (msg) => {
  const eventType = msg && msg.type ? msg.type : "";
  const skipLogging = eventType === "flow.scriptRequest" || eventType === "flow.scriptResponse";
  if (debug && !skipLogging) {
    queue.push(msg);
    writeNext();
  }

  if (eventType === "flow.scriptRequest") {
    if (!scriptWorker) {
      parentPort.postMessage({
        type: "flow.scriptResponse",
        requestId: msg.payload && msg.payload.requestId,
        returnValue: undefined,
        output: {},
        scriptLogs: [],
        error: "scriptWorker not available",
      });
      return;
    }
    try {
      scriptWorker.postMessage({
        type: "scriptRequest",
        requestId: msg.payload && msg.payload.requestId,
        script: msg.payload && msg.payload.script,
        input: msg.payload && msg.payload.input,
        timeoutMs: msg.payload && msg.payload.timeoutMs,
      });
    } catch (err) {
      parentPort.postMessage({
        type: "flow.scriptResponse",
        requestId: msg.payload && msg.payload.requestId,
        returnValue: undefined,
        output: {},
        scriptLogs: [],
        error: "Failed to post scriptRequest: " + (err && err.message ? err.message : String(err)),
      });
    }
    return;
  }

  // Response messages produced by scriptWorker are forwarded to main as flow.scriptResponse.
  if (eventType === "scriptResponse") return;

  const target = msg.payload && msg.payload.target;
  if (msg.type === "entry.sendToFlow" && target === "localDb") {
    parentPort.postMessage({
      type: "createEntryInProfile",
      targetProfileId: (msg.payload.param != null ? String(msg.payload.param) : "").trim(),
      sourceDocId: msg.payload.entryId,
      dataset: msg.payload.dataset,
    });
    return;
  }
  if (msg.type === "entry.sendToFlow" && target === "response") {
    parentPort.postMessage({
      type: "createResponseInProfile",
      sourceDocId: msg.payload.entryId,
      profileId: msg.payload.profileId,
      dataset: msg.payload.dataset,
    });
    return;
  }
  if (msg.type === "entry.sendToFlow" && target === "api") {
    parentPort.postMessage({
      type: "callApi",
      apiDocId: (msg.payload.param != null ? String(msg.payload.param) : "").trim(),
      entryId: msg.payload.entryId,
      profileId: msg.payload.profileId,
      dataset: msg.payload.dataset,
    });
    return;
  }
  if (!debug && !skipLogging) {
    queue.push(msg);
    writeNext();
  }
});

if (scriptWorker) {
  scriptWorker.on("message", (msg) => {
    if (!msg || msg.type !== "scriptResponse") return;
    parentPort.postMessage({
      type: "flow.scriptResponse",
      requestId: msg.requestId,
      returnValue: msg.returnValue,
      output: msg.output && typeof msg.output === "object" ? msg.output : {},
      scriptLogs: Array.isArray(msg.scriptLogs) ? msg.scriptLogs : [],
      error: msg.error,
    });
  });
}
