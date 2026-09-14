const { parentPort } = require("worker_threads");
const crypto = require("crypto");

/** Profile repeat scalar storage: plain text or { version: 1, rows: ["...", ...] }. */
function parseRepeatScalarRows(stored) {
  const storedStr = stored == null ? "" : String(stored);
  if (storedStr.trim() === "") return [];
  let parsed;
  try {
    parsed = JSON.parse(storedStr);
  } catch (_) {
    return [storedStr];
  }
  if (typeof parsed === "string") return [parsed];
  if (Array.isArray(parsed)) {
    return parsed.map((r) => (r != null ? String(r) : ""));
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.rows)) {
    return parsed.rows.map((r) => {
      if (r != null && typeof r === "object") {
        const vals = Object.values(r).filter((v) => v != null && String(v).trim() !== "");
        return vals.length > 0 ? String(vals[0]) : "";
      }
      return r != null ? String(r) : "";
    });
  }
  return [storedStr];
}

function resolveRepeatScalarModifier(rows, modifier) {
  const list = Array.isArray(rows) ? rows : [];
  const modRaw = String(modifier || "").trim();
  const mod = modRaw.toUpperCase();
  if (mod === "FIRST") return list.length > 0 ? String(list[0]) : "";
  if (mod === "LAST") return list.length > 0 ? String(list[list.length - 1]) : "";
  if (mod === "ALL") {
    return list
      .map((r) => (r != null ? String(r) : ""))
      .filter((s) => s.trim() !== "")
      .join("\n\n");
  }
  if (/^\d+$/.test(modRaw)) {
    const idx = parseInt(modRaw, 10) - 1;
    if (idx >= 0 && idx < list.length) return list[idx] != null ? String(list[idx]) : "";
    return "";
  }
  return "";
}

/** Parse #PROMPT# or #PROMPT(LAST)# / #PROMPT(2)# token (without surrounding #). */
function parseFieldTemplateToken(token) {
  const raw = String(token || "").trim();
  if (!raw) return { fieldName: "", modifier: null };
  const m = raw.match(/^([^(]+)\((FIRST|LAST|ALL|\d+)\)$/i);
  if (m) {
    const modPart = m[2];
    const modifier = /^\d+$/.test(modPart) ? modPart : modPart.toUpperCase();
    return { fieldName: m[1].trim(), modifier };
  }
  return { fieldName: raw, modifier: null };
}

const DATASET_SKIP_KEYS = new Set([
  "_id",
  "_rev",
  "type",
  "profileId",
  "sortKey",
  "createdAt",
  "updatedAt",
  "entryFormId",
  "sourceDocId",
  "lastApiResponse",
  "createdBy",
  "updatedBy",
]);

function isRepeatScalarFieldValue(v) {
  if (v == null) return false;
  if (typeof v !== "string") return false;
  const s = v.trim();
  if (!s.startsWith("{")) return false;
  try {
    const p = JSON.parse(s);
    return !!(p && typeof p === "object" && Array.isArray(p.rows));
  } catch (_) {
    return false;
  }
}

/** Row count from profile repeat JSON fields only (PROMPT / RESPONSE), not plain text columns. */
function dialogRowCount(dataset) {
  if (!dataset || typeof dataset !== "object") return 0;
  let max = 0;
  for (const [k, v] of Object.entries(dataset)) {
    if (!k || k.startsWith("_") || DATASET_SKIP_KEYS.has(k)) continue;
    if (!isRepeatScalarFieldValue(v)) continue;
    max = Math.max(max, parseRepeatScalarRows(v).length);
  }
  return max;
}

function getRepeatScalarRowAt(dataset, fieldName, oneBasedIndex) {
  if (!dataset || typeof dataset !== "object") return "";
  const rows = parseRepeatScalarRows(dataset[fieldName]);
  const idx = oneBasedIndex - 1;
  if (idx < 0 || idx >= rows.length) return "";
  return rows[idx] != null ? String(rows[idx]) : "";
}

/** Field placeholder on the assistant line in a REPEAT block (e.g. #RESPONSE(N)#). */
function assistantReplyFieldInRepeatInner(inner, varName) {
  const re = new RegExp(
    '"role"\\s*:\\s*"assistant"[\\s\\S]*?#\\s*([A-Za-z_][A-Za-z0-9_]*)\\(\\s*' +
      varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
      "\\s*\\)\\s*#",
    "i"
  );
  const m = inner.match(re);
  return m ? m[1] : "RESPONSE";
}

function shouldSkipHistoryIteration(inner, varName, dataset, oneBasedIndex) {
  const replyField = assistantReplyFieldInRepeatInner(inner, varName);
  const reply = getRepeatScalarRowAt(dataset, replyField, oneBasedIndex);
  return !String(reply || "").trim();
}

/** Expand #REPEAT(N)# ... #END REPEAT(N)# (iterates 1 .. rowCount-1; N is loop variable for #FIELD(N)#). */
function expandRepeatBlocks(template, dataset) {
  if (typeof template !== "string" || !template) return "";
  if (!dataset || typeof dataset !== "object") return template;
  const blockRe = /#REPEAT\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*#([\s\S]*?)#\s*END\s+REPEAT\s*\(\s*\1\s*\)\s*#/gi;
  return template.replace(blockRe, (match, varName, inner) => {
    void match;
    const total = dialogRowCount(dataset);
    if (total <= 1) return "";
    const varRe = new RegExp(
      "#\\s*([^#\\(][^(#]*?)\\(\\s*" + varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*\\)\\s*#",
      "gi"
    );
    let out = "";
    for (let i = 1; i < total; i++) {
      if (shouldSkipHistoryIteration(inner, varName, dataset, i)) continue;
      let chunk = inner;
      chunk = chunk.replace(varRe, (_, fieldPart) => {
        const fieldName = String(fieldPart).trim();
        return escapeTemplateValue(getRepeatScalarRowAt(dataset, fieldName, i));
      });
      out += chunk;
    }
    return out;
  });
}

/** Escape for embedding inside a JSON double-quoted string in the request template. */
function escapeTemplateValue(raw) {
  const s = String(raw != null ? raw : "");
  return s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
}

function resolveTemplateFieldValue(fieldName, modifier, dataset) {
  const key = String(fieldName || "").trim();
  if (!key || !dataset || typeof dataset !== "object") return "";
  const v = dataset[key];
  if (modifier) return resolveRepeatScalarModifier(parseRepeatScalarRows(v), modifier);
  return v != null ? String(v) : "";
}

const FIELD_PLACEHOLDER_RE = /#([A-Za-z_][A-Za-z0-9_]*(?:\((?:FIRST|LAST|ALL|\d+)\))?)\#/g;

/** Replace #REPEAT(N)# blocks, then #fieldName# / #fieldName(FIRST|LAST|ALL|n)# placeholders. */
function applyTemplate(template, dataset, options) {
  if (typeof template !== "string" || !template) return "";
  if (!dataset || typeof dataset !== "object") return template;
  const forUrl = options && options.forUrl === true;
  const expanded = expandRepeatBlocks(template, dataset);
  return expanded.replace(FIELD_PLACEHOLDER_RE, (_, token) => {
    const { fieldName, modifier } = parseFieldTemplateToken(token);
    if (!fieldName) return "";
    const raw = resolveTemplateFieldValue(fieldName, modifier, dataset);
    return forUrl ? raw : escapeTemplateValue(raw);
  });
}

function urlHasFieldPlaceholders(url) {
  return typeof url === "string" && /#[A-Za-z_][A-Za-z0-9_]*(?:\((?:FIRST|LAST|ALL|\d+)\))?\#/.test(url);
}

function buildUrlWithQuery(baseUrl, dataset) {
  if (!dataset || typeof dataset !== "object") return baseUrl;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(dataset)) {
    if (DATASET_SKIP_KEYS.has(k) || k.startsWith("_")) continue;
    if (k === "lastApiResponse" || k === "rssXml" || k === "importCount" || k === "lastRun" || k === "lastImported") continue;
    if (v != null && String(v).trim() !== "") params.set(k, String(v).trim());
  }
  const qs = params.toString();
  if (!qs) return baseUrl;
  const sep = baseUrl.indexOf("?") !== -1 ? "&" : "?";
  return baseUrl + sep + qs;
}

function md5Hex(s) {
  return crypto.createHash("md5").update(s, "utf8").digest("hex");
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function parseDigestParams(str) {
  const out = {};
  let i = 0;
  const d = String(str);
  while (i < d.length) {
    while (i < d.length && (d[i] === " " || d[i] === ",")) i++;
    if (i >= d.length) break;
    const eq = d.indexOf("=", i);
    if (eq === -1) break;
    const name = d.slice(i, eq).trim().toLowerCase();
    i = eq + 1;
    if (d[i] === '"') {
      i++;
      let sb = "";
      while (i < d.length) {
        if (d[i] === "\\" && i + 1 < d.length) {
          sb += d[i + 1];
          i += 2;
          continue;
        }
        if (d[i] === '"') {
          i++;
          break;
        }
        sb += d[i];
        i++;
      }
      out[name] = sb;
    } else {
      let j = i;
      while (j < d.length && d[j] !== "," && d[j] !== " ") j++;
      out[name] = d.slice(i, j).trim();
      i = j;
    }
  }
  return out;
}

/** Pick first Digest challenge from WWW-Authenticate (Node fetch may join multiple headers). */
function extractDigestChallenge(wwwAuthenticate) {
  if (!wwwAuthenticate || typeof wwwAuthenticate !== "string") return null;
  const s = wwwAuthenticate;
  const re = /\bDigest\s+/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    const rest = s.slice(m.index + m[0].length).trim();
    const parsed = parseDigestParams(rest);
    if (parsed && parsed.realm != null && parsed.nonce != null) return parsed;
  }
  return null;
}

function escapeDigestQuotedString(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function pickQop(qopRaw) {
  if (!qopRaw || typeof qopRaw !== "string") return "";
  const parts = qopRaw.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  if (parts.includes("auth")) return "auth";
  if (parts.includes("auth-int")) return "auth-int";
  return "";
}

/**
 * HTTP Digest Authorization header (RFC 2617 / RFC 7616).
 * Hash and HA1/HA2 rules follow the challenged algorithm (MD5 vs SHA-256, with optional -sess).
 */
function buildDigestAuthHeader(method, urlObj, username, password, ch, ncHex, cnonce, entityBody) {
  const realm = String(ch.realm || "");
  const nonce = String(ch.nonce || "");
  const opaque = ch.opaque != null ? String(ch.opaque) : "";
  const algorithmRaw = (ch.algorithm || "").trim();
  const algorithmNorm = algorithmRaw ? algorithmRaw.toUpperCase().replace(/\s+/g, "") : "MD5";
  const useSha = algorithmNorm.includes("SHA-256");
  const isSess = algorithmNorm.includes("-SESS");
  const h = (s) => (useSha ? sha256Hex(s) : md5Hex(s));

  const uri = urlObj.pathname + urlObj.search;
  const qop = pickQop(ch.qop);

  let ha1 = h(`${username}:${realm}:${password}`);
  if (isSess) {
    ha1 = h(`${ha1}:${nonce}:${cnonce}`);
  }

  const ent = entityBody != null ? String(entityBody) : "";
  let ha2;
  if (qop === "auth-int") {
    ha2 = h(`${method.toUpperCase()}:${uri}:${h(ent)}`);
  } else {
    ha2 = h(`${method.toUpperCase()}:${uri}`);
  }

  let response;
  if (qop) {
    response = h(`${ha1}:${nonce}:${ncHex}:${cnonce}:${qop}:${ha2}`);
  } else {
    response = h(`${ha1}:${nonce}:${ha2}`);
  }

  const parts = [
    `username="${escapeDigestQuotedString(username)}"`,
    `realm="${escapeDigestQuotedString(realm)}"`,
    `nonce="${escapeDigestQuotedString(nonce)}"`,
    `uri="${escapeDigestQuotedString(uri)}"`,
    `response="${response}"`,
  ];
  if (algorithmRaw) parts.push(`algorithm=${algorithmRaw}`);
  if (opaque) parts.push(`opaque="${escapeDigestQuotedString(opaque)}"`);
  if (qop) {
    parts.push(`qop=${qop}`, `nc=${ncHex}`, `cnonce="${escapeDigestQuotedString(cnonce)}"`);
  }
  return "Digest " + parts.join(", ");
}

/** FRITZ!Box /api/v0/... often returns HTTP 200 + JSON error (e.g. 3001) when no Digest was sent, so clients must not treat that as success. */
function fritzJsonSuggestsUnauthenticatedDenied(bodyText) {
  if (!bodyText || typeof bodyText !== "string" || !/"errors"\s*:\s*\[/.test(bodyText)) return false;
  try {
    const j = JSON.parse(bodyText);
    const errors = j && j.errors;
    if (!Array.isArray(errors)) return false;
    return errors.some(
      (e) =>
        e &&
        (e.code === 3001 ||
          (typeof e.message === "string" && /permission denied|not authorized|unauthorized/i.test(e.message)))
    );
  } catch {
    return /"code"\s*:\s*3001\b/.test(bodyText);
  }
}

function sameUrlIgnoringTrailingSlash(a, b) {
  const x = (a || "").split("#")[0].replace(/\/+$/, "");
  const y = (b || "").split("#")[0].replace(/\/+$/, "");
  return x === y;
}

/** When the real URL returns 200 without a Digest challenge, ask paths that typically return 401 + WWW-Authenticate on FRITZ!Box. */
async function probeFritzDigestChallenge(urlObj, plainHeaders, finalUrlNorm) {
  const origin = urlObj.origin;
  const candidates = [];
  candidates.push(`${origin}/`);
  candidates.push(`${origin}/net/`);
  let pathOnly = urlObj.pathname;
  if (pathOnly.endsWith("/")) pathOnly = pathOnly.slice(0, -1);
  const lastSlash = pathOnly.lastIndexOf("/");
  if (lastSlash > 0) candidates.push(`${origin}${pathOnly.slice(0, lastSlash)}`);
  candidates.push(`${origin}/api/v0`);
  candidates.push(`${origin}/api/v0/`);

  for (const tryUrl of candidates) {
    if (sameUrlIgnoringTrailingSlash(tryUrl, finalUrlNorm)) continue;
    try {
      const pr = await fetch(tryUrl, { method: "GET", headers: plainHeaders });
      const www = pr.headers.get("www-authenticate") || pr.headers.get("WWW-Authenticate") || "";
      const ch = extractDigestChallenge(www);
      await pr.text();
      if ((pr.status === 401 || pr.status === 403) && ch) return ch;
    } catch {
      // ignore probe failure
    }
  }
  return null;
}

async function fetchWithDigestAuth(finalUrl, method, bodyPayload, apiUsername, apiPassword, baseHeaders) {
  let urlObj;
  try {
    urlObj = new URL(finalUrl);
  } catch {
    return fetch(finalUrl, { method, headers: Object.assign({}, baseHeaders), body: bodyPayload });
  }

  const finalUrlNorm = urlObj.href.split("#")[0];
  const useSlimGet = method === "GET" && (bodyPayload == null || bodyPayload === "");
  const plainHeaders = useSlimGet ? { Accept: "application/json, */*" } : Object.assign({}, baseHeaders);
  const mergeDigest = (extra) => Object.assign({}, plainHeaders, extra);
  let res = await fetch(finalUrl, { method, headers: plainHeaders, body: bodyPayload });

  let ch = null;
  if (res.status === 401 || res.status === 403) {
    const www = res.headers.get("www-authenticate") || res.headers.get("WWW-Authenticate") || "";
    ch = extractDigestChallenge(www);
  }

  if (!ch && res.ok) {
    const text = await res.text();
    if (!fritzJsonSuggestsUnauthenticatedDenied(text)) {
      return new Response(text, { status: res.status, statusText: res.statusText, headers: res.headers });
    }
    ch = await probeFritzDigestChallenge(urlObj, plainHeaders, finalUrlNorm);
    if (!ch) {
      return new Response(text, { status: res.status, statusText: res.statusText, headers: res.headers });
    }
  } else if (!ch) {
    return res;
  } else {
    await res.text();
  }

  const runWithChallenge = async (challenge) => {
    const cnonce = crypto.randomBytes(16).toString("hex");
    const authHdr = buildDigestAuthHeader(
      method,
      urlObj,
      String(apiUsername),
      String(apiPassword),
      challenge,
      "00000001",
      cnonce,
      bodyPayload
    );
    return fetch(finalUrl, { method, headers: mergeDigest({ Authorization: authHdr }), body: bodyPayload });
  };

  let res2 = await runWithChallenge(ch);
  if (res2.status !== 401 && res2.status !== 403) return res2;

  const www2 = res2.headers.get("www-authenticate") || res2.headers.get("WWW-Authenticate") || "";
  const ch2 = extractDigestChallenge(www2);
  const stale = ch2 && String(ch2.stale || "").toLowerCase() === "true";
  await res2.text();
  if (stale && ch2) return runWithChallenge(ch2);
  return res2;
}

function fritzReadXmlTag(xml, name) {
  const re = new RegExp(`<${name}>([^<]*)</${name}>`, "i");
  const m = re.exec(xml || "");
  return m ? m[1].trim() : "";
}

function fritzMd5LoginResponse(challengeCode, password) {
  const hash = crypto.createHash("md5");
  const buf = Buffer.from(challengeCode + "-" + password, "utf16le");
  return challengeCode + "-" + hash.update(buf).digest("hex");
}

function fritzPbkdf2LoginResponse(challengeCode, password) {
  const parts = challengeCode.split("$");
  if (parts.length < 5) throw new Error("fritzSession: invalid PBKDF2 challenge");
  const iter1 = Number(parts[1]);
  const salt1Hex = parts[2];
  const iter2 = Number(parts[3]);
  const salt2Hex = parts[4];
  const pass = Buffer.from(password, "utf8");
  const salt1 = Buffer.from(salt1Hex, "hex");
  const salt2 = Buffer.from(salt2Hex, "hex");
  const salt2Norm = salt2Hex;
  const keyLen = 32;
  const hash1 = crypto.pbkdf2Sync(pass, salt1, iter1, keyLen, "sha256").toString("hex");
  const hash2 = crypto.pbkdf2Sync(Buffer.from(hash1, "hex"), salt2, iter2, keyLen, "sha256").toString("hex");
  return salt2Norm + "$" + hash2;
}

/** FRITZ!OS login_sid.lua challenge/response (PBKDF2 for 7.24+, else legacy MD5). */
async function fritzObtainSid(origin, username, password) {
  const loginBase = `${origin.replace(/\/+$/, "")}/login_sid.lua`;
  const r1 = await fetch(`${loginBase}?version=2`, { method: "GET" });
  const xml1 = await r1.text();
  const challenge = fritzReadXmlTag(xml1, "Challenge");
  if (!challenge) throw new Error("fritzSession: no Challenge in login_sid.lua response");

  let responseVal;
  if (challenge.startsWith("2$")) {
    responseVal = fritzPbkdf2LoginResponse(challenge, password);
  } else {
    responseVal = fritzMd5LoginResponse(challenge, password);
  }

  const params = new URLSearchParams({
    version: "2",
    username: username != null ? String(username) : "",
    response: responseVal,
  });
  const r2 = await fetch(`${loginBase}?${params.toString()}`, { method: "GET" });
  const xml2 = await r2.text();
  const sid = fritzReadXmlTag(xml2, "SID");
  if (!sid || /^0+$/.test(sid)) {
    const blockTime = fritzReadXmlTag(xml2, "BlockTime");
    throw new Error(`fritzSession: login failed (wrong user/password or blocked). BlockTime=${blockTime || "0"}`);
  }
  return sid;
}

/**
 * Smart Home REST (/api/v0/smarthome/...) expects the session id in the Authorization
 * header (OpenAPI scheme AVM-SID: apiKey in header "Authorization"), not as ?sid= on the URL.
 * @see https://github.com/ByteSizedMarius/go-fritzbox-api/blob/main/client.go RestRequest
 */
async function fetchWithFritzSessionAuth(finalUrl, method, bodyPayload, apiUsername, apiPassword, baseHeaders) {
  let urlObj;
  try {
    urlObj = new URL(finalUrl);
  } catch {
    throw new Error("fritzSession: invalid request URL");
  }
  const sid = await fritzObtainSid(urlObj.origin, apiUsername, apiPassword);
  const authHdr = "AVM-SID " + sid;
  const useSlimGet = method === "GET" && (bodyPayload == null || bodyPayload === "");
  const headers = useSlimGet
    ? { Accept: "application/json, */*", Authorization: authHdr }
    : Object.assign({}, baseHeaders, { Authorization: authHdr });
  return fetch(finalUrl, { method, headers, body: bodyPayload });
}

async function fetchWithElenkoAuth(finalUrl, method, bodyPayload, authType, apiKey, apiUsername, apiPassword) {
  const baseHeaders = { "Content-Type": "application/json" };
  const merge = (extra) => Object.assign({}, baseHeaders, extra);

  if (authType === "bearer" && apiKey && String(apiKey).trim()) {
    const key = String(apiKey).trim();
    return fetch(finalUrl, {
      method,
      headers: merge({ "api-key": key, Authorization: "Bearer " + key }),
      body: bodyPayload,
    });
  }

  if (authType === "x-api-key" && apiKey && String(apiKey).trim()) {
    const key = String(apiKey).trim();
    return fetch(finalUrl, {
      method,
      headers: merge({ "X-API-Key": key }),
      body: bodyPayload,
    });
  }

  if (authType === "basic" && apiUsername != null && apiPassword != null) {
    const auth = Buffer.from(String(apiUsername) + ":" + String(apiPassword), "utf8").toString("base64");
    return fetch(finalUrl, {
      method,
      headers: merge({ Authorization: "Basic " + auth }),
      body: bodyPayload,
    });
  }

  if (authType === "digest" && apiUsername != null && apiPassword != null) {
    return fetchWithDigestAuth(finalUrl, method, bodyPayload, apiUsername, apiPassword, baseHeaders);
  }

  if (authType === "fritz" && apiUsername != null && apiPassword != null) {
    return fetchWithFritzSessionAuth(finalUrl, method, bodyPayload, apiUsername, apiPassword, baseHeaders);
  }

  return fetch(finalUrl, { method, headers: Object.assign({}, baseHeaders), body: bodyPayload });
}

if (parentPort) parentPort.on("message", (msg) => {
  if (msg.type !== "apiRequest") return;
  const { apiDoc, dataset, entryId, profileId, requestId } = msg;
  const authTypeRaw = msg.authType != null ? String(msg.authType).trim().toLowerCase() : "";
  const authType =
    authTypeRaw === "none" ||
    authTypeRaw === "bearer" ||
    authTypeRaw === "x-api-key" ||
    authTypeRaw === "basic" ||
    authTypeRaw === "digest" ||
    authTypeRaw === "fritz"
      ? authTypeRaw
      : msg.apiKey
        ? "bearer"
        : "none";
  const apiKey = msg.apiKey != null ? msg.apiKey : null;
  const apiUsername = msg.apiUsername != null ? msg.apiUsername : null;
  const apiPassword = msg.apiPassword != null ? msg.apiPassword : null;

  const responseTarget = (apiDoc && (apiDoc.responseTarget === "create" ? "create" : apiDoc.responseTarget === "forward" ? "forward" : "update")) || "update";
  const url = apiDoc && apiDoc.url ? String(apiDoc.url).trim() : "";
  const method = (apiDoc && apiDoc.method) ? String(apiDoc.method).toUpperCase() : "GET";
  const template = apiDoc && typeof apiDoc.template === "string" ? apiDoc.template.trim() : "";
  const appendEntryFieldsToGet =
    typeof apiDoc.getQueryFromEntry === "boolean" ? apiDoc.getQueryFromEntry : true;
  const responseField = (apiDoc && typeof apiDoc.responseField === "string") ? apiDoc.responseField.trim() : "";
  const responseStart = (apiDoc && typeof apiDoc.responseStart === "string") ? apiDoc.responseStart : "";
  const responseEnd = (apiDoc && typeof apiDoc.responseEnd === "string") ? apiDoc.responseEnd : "";
  if (!url && !template) {
    parentPort.postMessage({
      type: "apiResponse",
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
    const substituted = applyTemplate(template, dataset, { forUrl: method === "GET" });
    if (method === "GET") {
      finalUrl = substituted || url;
    } else {
      finalUrl = url;
      bodyPayload = substituted;
    }
  } else {
    let baseUrl = url;
    const hadPlaceholders = urlHasFieldPlaceholders(baseUrl);
    if (hadPlaceholders) {
      baseUrl = applyTemplate(baseUrl, dataset, { forUrl: true });
    }
    finalUrl =
      method === "GET"
        ? (appendEntryFieldsToGet && !hadPlaceholders ? buildUrlWithQuery(baseUrl, dataset) : baseUrl)
        : baseUrl;
    if ((method === "POST" || method === "PUT" || method === "PATCH") && dataset && typeof dataset === "object") {
      bodyPayload = JSON.stringify(dataset);
    }
  }
  if (!finalUrl) {
    parentPort.postMessage({
      type: "apiResponse",
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
  (async () => {
    try {
      const res = await fetchWithElenkoAuth(finalUrl, method, bodyPayload, authType, apiKey, apiUsername, apiPassword);
      const text = await res.text();
      let body = text;
      try {
        body = JSON.parse(text);
      } catch (_) {}
      parentPort.postMessage({
        type: "apiResponse",
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
      const msgErr = err && err.message ? String(err.message) : String(err);
      const errorDetail = [msgErr, code, cause].filter(Boolean).join(" ");
      parentPort.postMessage({
        type: "apiResponse",
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

module.exports = {
  applyTemplate,
  expandRepeatBlocks,
  parseFieldTemplateToken,
  resolveTemplateFieldValue,
  parseRepeatScalarRows,
  dialogRowCount,
  escapeTemplateValue,
};
