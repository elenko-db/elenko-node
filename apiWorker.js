const { parentPort } = require("worker_threads");

if (!parentPort) {
  throw new Error("API worker must be started as a worker thread.");
}

/** Replace #fieldName# in template with dataset[fieldName]; unknown fields become empty string. Double quotes in values are replaced with single quotes to avoid breaking JSON/query strings. */
function applyTemplate(template, dataset) {
  if (typeof template !== "string" || !template) return "";
  if (!dataset || typeof dataset !== "object") return template;
  return template.replace(/#([^#]+)#/g, (_, fieldName) => {
    const key = String(fieldName).trim();
    if (key === "") return "";
    const v = dataset[key];
    const raw = v != null ? String(v) : "";
    return raw.replace(/"/g, "'");
  });
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
  const { apiDoc, apiKey, dataset, entryId, profileId, requestId } = msg;
  const responseTarget = (apiDoc && (apiDoc.responseTarget === "create" ? "create" : apiDoc.responseTarget === "forward" ? "forward" : "update")) || "update";
  const url = apiDoc && apiDoc.url ? String(apiDoc.url).trim() : "";
  const method = (apiDoc && apiDoc.method) ? String(apiDoc.method).toUpperCase() : "GET";
  const template = apiDoc && typeof apiDoc.template === "string" ? apiDoc.template.trim() : "";
  const responseField = (apiDoc && typeof apiDoc.responseField === "string") ? apiDoc.responseField.trim() : "";
  const responseStart = (apiDoc && typeof apiDoc.responseStart === "string") ? apiDoc.responseStart : "";
  const responseEnd = (apiDoc && typeof apiDoc.responseEnd === "string") ? apiDoc.responseEnd : "";
  if (!url && !template) {
    parentPort.postMessage({
      kind: "apiResponse",
      entryId,
      profileId,
      requestId,
      success: false,
      statusCode: null,
      body: null,
      error: "Missing URL and Template in API doc",
      responseTarget,
      responseField,
      responseStart,
      responseEnd,
    });
    return;
  }
  let finalUrl;
  let bodyPayload = undefined;
  if (template) {
    const substituted = applyTemplate(template, dataset);
    if (method === "GET") {
      finalUrl = substituted || url;
    } else {
      finalUrl = url;
      bodyPayload = substituted;
    }
  } else {
    finalUrl = method === "GET" ? buildUrlWithQuery(url, dataset) : url;
    if ((method === "POST" || method === "PUT" || method === "PATCH") && dataset && typeof dataset === "object") {
      bodyPayload = JSON.stringify(dataset);
    }
  }
  if (!finalUrl) {
    parentPort.postMessage({
      kind: "apiResponse",
      entryId,
      profileId,
      requestId,
      success: false,
      statusCode: null,
      body: null,
      error: "Missing URL in API doc",
      responseTarget,
      responseField,
      responseStart,
      responseEnd,
    });
    return;
  }
  const headers = { "Content-Type": "application/json" };
  if (apiKey && String(apiKey).trim()) {
    headers["Authorization"] = "Bearer " + String(apiKey).trim();
  }
  const options = {
    method,
    headers,
  };
  if (bodyPayload !== undefined) options.body = bodyPayload;
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
        requestId,
        success: res.ok,
        statusCode: res.status,
        body,
        error: res.ok ? null : (text || res.statusText),
        responseTarget,
        responseField,
        responseStart,
        responseEnd,
      });
    } catch (err) {
      const code = err && err.code ? String(err.code) : "";
      const cause = err && err.cause && err.cause.message ? String(err.cause.message) : "";
      const msg = err && err.message ? String(err.message) : String(err);
      const errorDetail = [msg, code, cause].filter(Boolean).join(" ");
      parentPort.postMessage({
        kind: "apiResponse",
        entryId,
        profileId,
        requestId,
        success: false,
        statusCode: null,
        body: null,
        error: errorDetail || "Unknown error",
        responseTarget,
        responseField,
        responseStart,
        responseEnd,
      });
    }
  })();
});
