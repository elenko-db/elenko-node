const { parentPort } = require("worker_threads");

const FEDERATION_SCHEMA_VERSION = 1;

function validateInboxEnvelope(body) {
  const b = body && typeof body === "object" ? body : {};
  const schemaVersion =
    typeof b.schemaVersion === "number" ? b.schemaVersion : FEDERATION_SCHEMA_VERSION;
  if (schemaVersion !== FEDERATION_SCHEMA_VERSION) {
    return { ok: false, error: `Unsupported schemaVersion (expected ${FEDERATION_SCHEMA_VERSION})` };
  }
  const messageId = typeof b.messageId === "string" ? b.messageId.trim() : "";
  const exchangeId = typeof b.exchangeId === "string" ? b.exchangeId.trim() : "";
  const msgType = typeof b.type === "string" ? b.type.trim().toLowerCase() : "";
  const fromPeerId = typeof b.fromPeerId === "string" ? b.fromPeerId.trim() : "";
  const toPeerId = typeof b.toPeerId === "string" ? b.toPeerId.trim() : "";
  const sentAt = typeof b.sentAt === "string" ? b.sentAt.trim() : "";
  const payload = b.payload && typeof b.payload === "object" && !Array.isArray(b.payload) ? b.payload : null;
  if (!messageId) return { ok: false, error: "messageId is required" };
  if (!exchangeId) return { ok: false, error: "exchangeId is required" };
  if (msgType !== "entry" && msgType !== "response") return { ok: false, error: "type must be entry or response" };
  if (!fromPeerId || !toPeerId) return { ok: false, error: "fromPeerId and toPeerId are required" };
  if (!sentAt) return { ok: false, error: "sentAt is required" };
  if (!payload) return { ok: false, error: "payload object is required" };
  let inReplyTo = null;
  if (msgType === "response") {
    const ir = b.inReplyTo && typeof b.inReplyTo === "object" ? b.inReplyTo : null;
    const originPeerId =
      ir && typeof ir.originPeerId === "string" ? ir.originPeerId.trim() : "";
    const remoteEntryId =
      ir && typeof ir.remoteEntryId === "string" ? ir.remoteEntryId.trim() : "";
    if (!originPeerId || !remoteEntryId) {
      return { ok: false, error: "inReplyTo.originPeerId and inReplyTo.remoteEntryId are required for response" };
    }
    inReplyTo = { originPeerId, remoteEntryId };
  }
  return {
    ok: true,
    envelope: {
      schemaVersion,
      messageId,
      exchangeId,
      type: msgType,
      fromPeerId,
      toPeerId,
      sentAt,
      inReplyTo,
      payload,
    },
  };
}

async function postEnvelopeToHub(remoteBaseUrl, apiKey, envelope) {
  const base = String(remoteBaseUrl || "")
    .trim()
    .replace(/\/+$/, "");
  if (!base) throw new Error("remoteBaseUrl is required");
  const url = `${base}/api/federation/inbox`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(envelope),
  });
  const text = await resp.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    throw new Error(`Hub inbox returned non-JSON (${resp.status})`);
  }
  if (!resp.ok) {
    throw new Error(data.error || data.message || `Hub inbox HTTP ${resp.status}`);
  }
  return data;
}

if (!parentPort) {
  throw new Error("Federation worker must be started as a worker thread.");
}

parentPort.on("message", async (msg) => {
  if (!msg || msg.type !== "federation.hubPublish") return;
  const requestId = msg.requestId;
  const payload = msg.payload && typeof msg.payload === "object" ? msg.payload : {};
  try {
    const remoteBaseUrl = payload.remoteBaseUrl != null ? String(payload.remoteBaseUrl).trim() : "";
    const apiKey = payload.apiKey != null ? String(payload.apiKey) : "";
    const validated = validateInboxEnvelope(payload.envelope);
    if (!validated.ok) {
      parentPort.postMessage({
        type: "federation.hubPublish.result",
        requestId,
        ok: false,
        error: validated.error,
      });
      return;
    }
    if (!apiKey) {
      parentPort.postMessage({
        type: "federation.hubPublish.result",
        requestId,
        ok: false,
        error: "API key missing for hub publish",
      });
      return;
    }
    const hub = await postEnvelopeToHub(remoteBaseUrl, apiKey, validated.envelope);
    parentPort.postMessage({
      type: "federation.hubPublish.result",
      requestId,
      ok: true,
      result: { hub, messageId: validated.envelope.messageId },
    });
  } catch (err) {
    parentPort.postMessage({
      type: "federation.hubPublish.result",
      requestId,
      ok: false,
      error: err && err.message ? err.message : String(err),
    });
  }
});
