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

const FLOW_LOG_LEVELS = new Set(["minimal", "normal", "verbose"]);

function normalizeFlowLogLevel(raw) {
  const s = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (FLOW_LOG_LEVELS.has(s)) return s;
  if (/^(1|true|yes)$/i.test(String(process.env.FLOW_DEBUG || "").trim())) return "verbose";
  const envLevel = typeof process.env.FLOW_LOG_LEVEL === "string" ? process.env.FLOW_LOG_LEVEL.trim().toLowerCase() : "";
  if (FLOW_LOG_LEVELS.has(envLevel)) return envLevel;
  return "normal";
}

let logLevel = normalizeFlowLogLevel("");

function shouldLogMessage(msg) {
  if (!msg || typeof msg !== "object") return false;
  const type = typeof msg.type === "string" ? msg.type : "";
  if (type === "flow.logConfig") return false;
  if (type === "flow.scriptRequest" || type === "flow.scriptResponse") {
    return logLevel === "verbose";
  }
  if (logLevel === "minimal") {
    if (
      /Error|error|callRejected|keyLookupError|pipelineError|scriptError|purgeOldError|refreshError|appendRepeatError|console\.error/i.test(
        type
      )
    ) {
      return true;
    }
    if (type === "flow.scriptLog" || type === "flow.importStats") return true;
    return false;
  }
  return true;
}

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

console.log("Flow worker: logging to", logFile, "(level:", logLevel + ")");

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

// Log startup and current level to the flow log
queue.push({
  type: "flowWorker.start",
  payload:
    envStatus === ".env not found"
      ? { logLevel, env: envStatus, envPath, logFile }
      : { logLevel, env: envStatus, logFile },
  ts: new Date().toISOString(),
});
writeNext();

if (!parentPort) {
  throw new Error("Flow worker must be started as a worker thread.");
}

parentPort.on("message", (msg) => {
  const eventType = msg && msg.type ? msg.type : "";

  if (eventType === "flow.logConfig") {
    logLevel = normalizeFlowLogLevel(msg.payload && msg.payload.level);
    queue.push({
      type: "flowWorker.logConfig",
      payload: { logLevel },
      ts: new Date().toISOString(),
    });
    writeNext();
    return;
  }

  if (shouldLogMessage(msg)) {
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
