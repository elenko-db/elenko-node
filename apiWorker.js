const { parentPort } = require("worker_threads");

if (!parentPort) {
  throw new Error("API worker must be started as a worker thread.");
}

function buildUrlWithQuery(baseUrl, dataset) {
  if (!dataset || typeof dataset !== "object") return baseUrl;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(dataset)) {
    if (k === "_id" || k === "_rev" || k === "type" || k === "profileId" || k === "sortKey" || k === "createdAt" || k === "updatedAt" || k === "entryFormId" || k === "sourceDocId") continue;
    if (v != null && String(v).trim() !== "") params.set(k, String(v).trim());
  }
  const qs = params.toString();
  if (!qs) return baseUrl;
  const sep = baseUrl.indexOf("?") !== -1 ? "&" : "?";
  return baseUrl + sep + qs;
}

parentPort.on("message", (msg) => {
  if (msg.kind !== "apiRequest") return;
  const { apiDoc, apiKey, dataset, entryId, profileId } = msg;
  const responseTarget = (apiDoc && (apiDoc.responseTarget === "create" ? "create" : "update")) || "update";
  const url = apiDoc && apiDoc.url ? String(apiDoc.url).trim() : "";
  const method = (apiDoc && apiDoc.method) ? String(apiDoc.method).toUpperCase() : "GET";
  if (!url) {
    parentPort.postMessage({
      kind: "apiResponse",
      entryId,
      profileId,
      success: false,
      statusCode: null,
      body: null,
      error: "Missing URL in API doc",
      responseTarget,
    });
    return;
  }
  const finalUrl = method === "GET" ? buildUrlWithQuery(url, dataset) : url;
  const headers = { "Content-Type": "application/json" };
  if (apiKey && String(apiKey).trim()) {
    headers["Authorization"] = "Bearer " + String(apiKey).trim();
  }
  const options = {
    method,
    headers,
  };
  if ((method === "POST" || method === "PUT" || method === "PATCH") && dataset && typeof dataset === "object") {
    options.body = JSON.stringify(dataset);
  }
  (async () => {
    try {
      const res = await fetch(finalUrl, options);
      const text = await res.text();
      let body = text;
      try {
        body = JSON.parse(text);
      } catch (_) {}
      parentPort.postMessage({
        kind: "apiResponse",
        entryId,
        profileId,
        success: res.ok,
        statusCode: res.status,
        body,
        error: res.ok ? null : (text || res.statusText),
        responseTarget,
      });
    } catch (err) {
      parentPort.postMessage({
        kind: "apiResponse",
        entryId,
        profileId,
        success: false,
        statusCode: null,
        body: null,
        error: err && err.message ? err.message : String(err),
        responseTarget,
      });
    }
  })();
});
