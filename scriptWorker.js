const { parentPort } = require("worker_threads");
const vm = require("vm");

if (!parentPort) {
  throw new Error("scriptWorker must be started as a worker thread.");
}

function runScriptInSandbox(script, input, timeoutMs) {
  const timeout = Math.min(Math.max(Number(timeoutMs) || 5000, 100), 60000);
  const scriptLogs = [];
  const output = {};

  Object.defineProperty(output, "_writeLog", {
    enumerable: false,
    configurable: false,
    writable: false,
    value: function writeScriptLog(obj) {
      try {
        const raw = obj == null ? null : obj;
        const safe = JSON.parse(JSON.stringify(raw));
        scriptLogs.push(safe);
      } catch (_) {
        scriptLogs.push({ value: String(obj) });
      }
      return null;
    },
  });

  const sandbox = {
    input: input && typeof input === "object" ? input : {},
    output,
    __returnValue: undefined,
  };

  const wrapped =
    "__returnValue = (function() {\n" + (typeof script === "string" ? script : "") + "\n})();";

  try {
    const context = vm.createContext(sandbox);
    vm.runInContext(wrapped, context, { timeout });

    const safeOutput = sandbox.output && typeof sandbox.output === "object" ? sandbox.output : {};
    return { returnValue: sandbox.__returnValue, output: safeOutput, scriptLogs, error: null };
  } catch (err) {
    return {
      returnValue: undefined,
      output: {},
      scriptLogs,
      error: err && err.message ? err.message : String(err),
    };
  }
}

parentPort.on("message", (msg) => {
  if (!msg || msg.kind !== "scriptRequest") return;
  const { requestId, script, input, timeoutMs } = msg;

  const result = runScriptInSandbox(script, input, timeoutMs);

  // `_writeLog` is a function defined as non-enumerable. Don't send the function across
  // workers; only send enumerable output properties (matching main-thread `{...output}` behavior).
  const outputEnum = (() => {
    if (!result.output || typeof result.output !== "object") return {};
    const out = {};
    for (const k of Object.keys(result.output)) out[k] = result.output[k];
    return out;
  })();

  const safeReturnValue = (() => {
    const v = result.returnValue;
    if (typeof v === "function") return "[Function returned by script]";
    if (typeof v === "symbol") return v.toString();
    if (typeof v === "bigint") return v.toString();
    return v;
  })();

  // Note: if the remaining output/returnValue contains non-structured-clone values,
  // Node will throw on postMessage. We catch and fall back to a JSON-safe representation.
  try {
    parentPort.postMessage({
      kind: "scriptResponse",
      requestId,
      returnValue: safeReturnValue,
      output: outputEnum,
      scriptLogs: Array.isArray(result.scriptLogs) ? result.scriptLogs : [],
      error: result.error,
    });
  } catch (postErr) {
    let jsonSafeOutput = {};
    let jsonSafeReturn = undefined;
    try {
      jsonSafeOutput = JSON.parse(JSON.stringify(outputEnum));
    } catch (_) {
      jsonSafeOutput = {};
    }
    try {
      jsonSafeReturn = JSON.parse(JSON.stringify(safeReturnValue));
    } catch (_) {
      jsonSafeReturn = String(safeReturnValue);
    }
    parentPort.postMessage({
      kind: "scriptResponse",
      requestId,
      returnValue: jsonSafeReturn,
      output: jsonSafeOutput,
      scriptLogs: [],
      error:
        "Failed to serialize script output: " + (postErr && postErr.message ? postErr.message : String(postErr)),
    });
  }
});

