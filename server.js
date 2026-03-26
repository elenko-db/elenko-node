const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env"), override: true });
const crypto = require("crypto");
const { Worker } = require("worker_threads");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const iconv = require("iconv-lite");
const marked = require("marked");
const nano = require("nano");

const originalConsoleError = console.error.bind(console);

function truncateString(s, maxLen) {
  const str = String(s);
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + "…[truncated]";
}

function serializeConsoleArgForFlow(arg) {
  if (arg instanceof Error) {
    return {
      name: arg.name,
      message: arg.message,
      stack: arg.stack,
    };
  }
  if (typeof arg === "string") return truncateString(arg, 4000);
  if (typeof arg === "number" || typeof arg === "boolean" || arg == null) return arg;
  try {
    const json = JSON.stringify(arg);
    return typeof json === "string" ? truncateString(json, 4000) : json;
  } catch (_) {
    try {
      return truncateString(String(arg), 4000);
    } catch {
      return "[unserializable]";
    }
  }
}

function serializeConsoleArgsForFlow(args) {
  try {
    return Array.isArray(args) ? args.map(serializeConsoleArgForFlow) : [];
  } catch (_) {
    return [];
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const COUCHDB_URL = process.env.COUCHDB_URL || "http://admin:admin@localhost:5984";
const COUCHDB_DB = process.env.COUCHDB_DB || "elenko";
const ELENKO_CONFIG_DB = process.env.ELENKO_CONFIG_DB || "elenko_config";
const COUCHDB_USER = "admin";
const COUCHDB_BOOTSTRAP_FILE = process.env.COUCHDB_BOOTSTRAP_FILE || path.join(__dirname, "couchdb.bootstrap.json");
const COUCHDB_ENC_KEY = Buffer.from("ElenkoCouchBootstrapKey32Bytes!!", "utf8").slice(0, 32);
const COUCHDB_ENC_IV = Buffer.from("ElenkoCouchBootstrapIV16", "utf8").slice(0, 16);
const IO_DIR = process.env.IO_DIR || path.join(__dirname, "io");
const PUBLIC_DIR = path.join(__dirname, "public");
const CONFIG_BACKUPS_DIR = path.join(PUBLIC_DIR, "backups");
const MAX_ENTRIES_PER_PROFILE = 500000;
const ENTRIES_PAGE_SIZE = 25;
const SORT_KEY_SPECIAL = ["createdAt", "updatedAt"];
const SORT_KEY_FIELDS_MAX = 3;
const DEFAULT_VALUE_SOURCES = ["", "createdAt", "updatedAt", "currentUser"];

/** PNG names must match files in public/ (see README-favicon.txt). Order: sized PNGs first, then .ico fallback — works reliably in Firefox + Chrome. */
const FAVICON_LINKS =
  '<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">' +
  '<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">' +
  '<link rel="icon" href="/favicon.ico" sizes="any" type="image/x-icon">' +
  '<link rel="apple-touch-icon" href="/apple-touch-icon.png">';

function normalizeFieldDefaultSources(fieldNames, raw) {
  const len = Array.isArray(fieldNames) ? fieldNames.length : 0;
  const arr = Array.isArray(raw) ? raw : [];
  const allowed = new Set(DEFAULT_VALUE_SOURCES);
  const result = [];
  for (let i = 0; i < len; i++) {
    const v = arr[i];
    const s = typeof v === "string" ? v.trim() : "";
    result.push(allowed.has(s) ? s : "");
  }
  return result;
}

/** Desktop list column display: Auto | Hide | 10%…50%. Stored parallel to fieldNames. */
const FIELD_DISPLAY_PCT_VALUES = new Set([10, 20, 30, 40, 50]);

function parseFieldDisplayToken(raw) {
  if (raw == null || typeof raw !== "string") return "auto";
  const t = raw.trim().toLowerCase();
  if (t === "auto" || t === "hide") return t;
  const m = t.match(/^(\d{1,2})%$/);
  if (m) {
    const n = parseInt(m[1], 10);
    if (FIELD_DISPLAY_PCT_VALUES.has(n)) return `${n}%`;
  }
  return "auto";
}

function normalizeFieldDisplay(fieldNames, raw) {
  const len = Array.isArray(fieldNames) ? fieldNames.length : 0;
  const arr = Array.isArray(raw) ? raw : [];
  const result = [];
  for (let i = 0; i < len; i++) {
    result.push(parseFieldDisplayToken(arr[i]));
  }
  return result;
}

/**
 * Desktop Elenko list table: Hide hides column on wide view only; %-columns are scaled so their widths sum to 100%.
 * Auto columns share remaining width (table-layout: fixed).
 */
function computeFieldDisplayForTable(fieldNames, fieldDisplayRaw) {
  const displays = normalizeFieldDisplay(fieldNames, fieldDisplayRaw);
  const n = fieldNames.length;
  const pctEntries = [];
  let sumRaw = 0;
  for (let i = 0; i < n; i++) {
    if (displays[i] === "hide") continue;
    const m = String(displays[i]).match(/^(\d+)%$/);
    if (m) {
      const v = parseInt(m[1], 10);
      pctEntries.push({ i, v });
      sumRaw += v;
    }
  }
  const normMap = new Map();
  if (pctEntries.length > 0 && sumRaw > 0) {
    const scale = 100 / sumRaw;
    for (const { i, v } of pctEntries) {
      normMap.set(i, v * scale);
    }
  }
  const out = [];
  for (let i = 0; i < n; i++) {
    if (displays[i] === "hide") {
      out.push({ desktopHidden: true, widthMode: "hide", widthStyle: "" });
    } else if (displays[i] === "auto") {
      out.push({ desktopHidden: false, widthMode: "auto", widthStyle: "" });
    } else if (normMap.has(i)) {
      const pct = normMap.get(i);
      const rounded = Math.round(pct * 10000) / 10000;
      out.push({
        desktopHidden: false,
        widthMode: "pct",
        widthStyle: `width: ${rounded}%;`,
      });
    } else {
      out.push({ desktopHidden: false, widthMode: "auto", widthStyle: "" });
    }
  }
  return out;
}

function formatDateTimeLocal(d) {
  const date = d instanceof Date ? d : new Date();
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const h = String(date.getHours()).padStart(2, "0");
  const min = String(date.getMinutes()).padStart(2, "0");
  const s = String(date.getSeconds()).padStart(2, "0");
  return `${y}-${m}-${day} ${h}:${min}:${s}`;
}

function formatDateOnly(d) {
  const date = d instanceof Date ? d : new Date(d);
  if (!date || Number.isNaN(date.getTime())) return "—";
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function resolveDefaultValue(source, req) {
  if (source === "createdAt" || source === "updatedAt") return formatDateTimeLocal(new Date());
  if (source === "currentUser") return req && req.session && req.session.user ? String(req.session.user) : "";
  return "";
}

const DEFAULT_ENTRY_VIEW_THEME = {
  background: "#0f1419",
  text: "#e6edf3",
  label: "#8b949e",
  link: "#58a6ff",
  fieldBorder: "#21262d",
  fieldBackground: "#161b22",
  fieldBackgroundEdit: "#161b22",
  textEdit: "#e6edf3",
};

const DEFAULT_PROFILE_THEME = {
  background: "#0f1419",
  text: "#e6edf3",
  label: "#8b949e",
  link: "#58a6ff",
  tableBg: "#161b22",
  tableHeaderBg: "#21262d",
  tableHeaderText: "#8b949e",
  tableBorder: "#21262d",
};

const DEFAULT_APP_THEME = {
  background: "#0f1419",
  text: "#e6edf3",
  label: "#8b949e",
  link: "#58a6ff",
  tableBg: "#161b22",
  tableHeaderBg: "#21262d",
  tableHeaderText: "#8b949e",
  tableBorder: "#21262d",
};

function normalizeAppTheme(theme) {
  if (!theme || typeof theme !== "object") return { ...DEFAULT_APP_THEME };
  const get = (key) => {
    const v = theme[key];
    return typeof v === "string" && v.trim() ? v.trim() : DEFAULT_APP_THEME[key];
  };
  return {
    background: get("background"),
    text: get("text"),
    label: get("label"),
    link: get("link"),
    tableBg: get("tableBg"),
    tableHeaderBg: get("tableHeaderBg"),
    tableHeaderText: get("tableHeaderText"),
    tableBorder: get("tableBorder"),
  };
}

function getAppThemeVars(theme) {
  const t = theme && typeof theme === "object" ? theme : { ...DEFAULT_APP_THEME };
  return `
    :root {
      --app-bg: ${escapeHtml(t.background)};
      --app-text: ${escapeHtml(t.text)};
      --app-label: ${escapeHtml(t.label)};
      --app-link: ${escapeHtml(t.link)};
      --app-table-bg: ${escapeHtml(t.tableBg)};
      --app-table-header-bg: ${escapeHtml(t.tableHeaderBg)};
      --app-table-header-text: ${escapeHtml(t.tableHeaderText)};
      --app-table-border: ${escapeHtml(t.tableBorder)};
    }`;
}

function normalizeProfileTheme(theme) {
  if (!theme || typeof theme !== "object") return { ...DEFAULT_PROFILE_THEME };
  const get = (key) => {
    const v = theme[key];
    return typeof v === "string" && v.trim() ? v.trim() : DEFAULT_PROFILE_THEME[key];
  };
  return {
    background: get("background"),
    text: get("text"),
    label: get("label"),
    link: get("link"),
    tableBg: get("tableBg"),
    tableHeaderBg: get("tableHeaderBg"),
    tableHeaderText: get("tableHeaderText"),
    tableBorder: get("tableBorder"),
  };
}

function normalizeEntryFormDoc(body) {
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const theme = body.theme && typeof body.theme === "object" ? body.theme : {};
  const layout = body.layout === "grid" || body.layout === "stack" ? body.layout : "table";
  const customCss = body.customCss != null ? String(body.customCss) : "";
  const parseNum = (v) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  };
  const rawLabels = Array.isArray(body.labels) ? body.labels : [];
  const labels = rawLabels
    .filter((item) => item && typeof item.id === "string" && item.id.trim() && typeof item.text === "string")
    .map((item) => ({ id: item.id.trim(), text: String(item.text).trim() }));

  const rawFieldLayout = Array.isArray(body.fieldLayout) ? body.fieldLayout : [];
  const fieldLayout = rawFieldLayout
    .filter((item) => {
      if (!item) return false;
      const hasField = typeof item.fieldName === "string" && item.fieldName.trim();
      const hasLabel = typeof item.labelId === "string" && item.labelId.trim();
      return hasField || hasLabel;
    })
    .map((item) => {
      const x = parseNum(item.x);
      const y = parseNum(item.y);
      const height = parseNum(item.height);
      const base = {
        order: typeof item.order === "number" && item.order >= 0 ? item.order : 0,
        width: typeof item.width === "string" ? item.width.trim() || "100%" : "100%",
        ...(x != null && { x }),
        ...(y != null && { y }),
        ...(height != null && { height }),
      };
      if (typeof item.fieldName === "string" && item.fieldName.trim()) {
        const fieldType = item.fieldType === "markdown" ? "markdown" : item.fieldType === "url" ? "url" : "text";
        return { ...base, fieldName: item.fieldName.trim(), fieldType };
      }
      return { ...base, labelId: item.labelId.trim() };
    });
  const flowButtonEnabled = !!(body.flowButtonEnabled === true || body.flowButtonEnabled === "true");
  const flowTargetRaw = typeof body.flowTarget === "string" ? body.flowTarget.trim() : "";
  const flowTarget = flowTargetRaw === "localDb" ? "localDb" : flowTargetRaw === "api" ? "api" : "log";
  const flowButtonLabel = typeof body.flowButtonLabel === "string" ? body.flowButtonLabel.trim() : "";
  const flowButtonParam = typeof body.flowButtonParam === "string" ? body.flowButtonParam.trim() : "";

  function normalizeFlowConfigItem(item) {
    if (!item || typeof item !== "object") return null;
    const enabled = !!(item.enabled === true || item.enabled === "true");
    const flowId = typeof item.flowId === "string" ? item.flowId.trim() : "";
    const targetRaw = typeof item.target === "string" ? item.target.trim() : "";
    const target = flowId ? (targetRaw === "localDb" ? "localDb" : targetRaw === "api" ? "api" : "") : (targetRaw === "localDb" ? "localDb" : targetRaw === "api" ? "api" : "log");
    const label = typeof item.label === "string" ? item.label.trim() : "";
    const param = typeof item.param === "string" ? item.param.trim() : "";
    return { enabled, target, label: label || "Send to Flow", param, flowId };
  }

  let flowConfigs;
  if (Array.isArray(body.flowConfigs) && body.flowConfigs.length > 0) {
    flowConfigs = body.flowConfigs.map(normalizeFlowConfigItem).filter(Boolean);
  } else {
    flowConfigs = [{ enabled: flowButtonEnabled, target: flowTarget, label: flowButtonLabel || "Send to Flow", param: flowButtonParam }];
  }

  return {
    name,
    labels,
    theme: {
      background: typeof theme.background === "string" ? theme.background.trim() || DEFAULT_ENTRY_VIEW_THEME.background : DEFAULT_ENTRY_VIEW_THEME.background,
      text: typeof theme.text === "string" ? theme.text.trim() || DEFAULT_ENTRY_VIEW_THEME.text : DEFAULT_ENTRY_VIEW_THEME.text,
      label: typeof theme.label === "string" ? theme.label.trim() || DEFAULT_ENTRY_VIEW_THEME.label : DEFAULT_ENTRY_VIEW_THEME.label,
      link: typeof theme.link === "string" ? theme.link.trim() || DEFAULT_ENTRY_VIEW_THEME.link : DEFAULT_ENTRY_VIEW_THEME.link,
      fieldBorder: typeof theme.fieldBorder === "string" ? theme.fieldBorder.trim() || DEFAULT_ENTRY_VIEW_THEME.fieldBorder : DEFAULT_ENTRY_VIEW_THEME.fieldBorder,
      fieldBackground: typeof theme.fieldBackground === "string" ? theme.fieldBackground.trim() || DEFAULT_ENTRY_VIEW_THEME.fieldBackground : DEFAULT_ENTRY_VIEW_THEME.fieldBackground,
      fieldBackgroundEdit: typeof theme.fieldBackgroundEdit === "string" ? theme.fieldBackgroundEdit.trim() || DEFAULT_ENTRY_VIEW_THEME.fieldBackgroundEdit : DEFAULT_ENTRY_VIEW_THEME.fieldBackgroundEdit,
      textEdit: typeof theme.textEdit === "string" ? theme.textEdit.trim() || DEFAULT_ENTRY_VIEW_THEME.textEdit : DEFAULT_ENTRY_VIEW_THEME.textEdit,
    },
    layout,
    fieldLayout,
    customCss,
    flowButtonEnabled: flowConfigs.length > 0 ? flowConfigs[0].enabled : false,
    flowTarget: flowConfigs.length > 0 ? flowConfigs[0].target : "log",
    flowButtonLabel: flowConfigs.length > 0 ? flowConfigs[0].label : "Send to Flow",
    flowButtonParam: flowConfigs.length > 0 ? flowConfigs[0].param : "",
    flowConfigs,
  };
}

/** Deep copy of an entry form document for insert (new _id). */
function buildEntryFormDocFromSource(baseForm, name) {
  return {
    type: "elenko_entry_form",
    name,
    labels: Array.isArray(baseForm.labels) ? baseForm.labels : [],
    theme: baseForm.theme && typeof baseForm.theme === "object" ? baseForm.theme : DEFAULT_ENTRY_VIEW_THEME,
    layout: baseForm.layout === "grid" || baseForm.layout === "stack" ? baseForm.layout : "table",
    fieldLayout: Array.isArray(baseForm.fieldLayout) ? baseForm.fieldLayout : [],
    customCss: baseForm.customCss != null ? String(baseForm.customCss) : "",
    flowButtonEnabled: !!baseForm.flowButtonEnabled,
    flowTarget: typeof baseForm.flowTarget === "string" ? baseForm.flowTarget : "log",
    flowButtonLabel:
      typeof baseForm.flowButtonLabel === "string" && baseForm.flowButtonLabel.trim()
        ? baseForm.flowButtonLabel.trim()
        : "Send to Flow",
    flowButtonParam: typeof baseForm.flowButtonParam === "string" ? baseForm.flowButtonParam : "",
    flowConfigs:
      Array.isArray(baseForm.flowConfigs) && baseForm.flowConfigs.length > 0
        ? baseForm.flowConfigs.map((c) => ({
            enabled: !!(c && c.enabled),
            target: c && c.target === "localDb" ? "localDb" : c && c.target === "api" ? "api" : "log",
            label: c && typeof c.label === "string" && c.label.trim() ? c.label.trim() : "Send to Flow",
            param: c && typeof c.param === "string" ? c.param.trim() : "",
            flowId: c && typeof c.flowId === "string" ? c.flowId.trim() : "",
          }))
        : [
            {
              enabled: !!baseForm.flowButtonEnabled,
              target: typeof baseForm.flowTarget === "string" ? baseForm.flowTarget : "log",
              label:
                typeof baseForm.flowButtonLabel === "string" && baseForm.flowButtonLabel.trim()
                  ? baseForm.flowButtonLabel.trim()
                  : "Send to Flow",
              param: typeof baseForm.flowButtonParam === "string" ? baseForm.flowButtonParam : "",
              flowId: "",
            },
          ],
  };
}

/** "Copy of Name", then "Copy of Name (2)", "(3)", … until unique in the given name set. */
function makeUniqueCopyOfLabel(originalName, existingNames, fallbackLabel) {
  const label = originalName && String(originalName).trim() ? String(originalName).trim() : fallbackLabel;
  const prefix = `Copy of ${label}`;
  if (!existingNames.has(prefix)) return prefix;
  let n = 2;
  let candidate;
  do {
    candidate = `${prefix} (${n})`;
    n++;
  } while (existingNames.has(candidate));
  return candidate;
}

function makeUniqueEntryFormCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "entry form");
}

function makeUniqueFlowCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "flow");
}

function makeUniqueApiCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "API");
}

function makeUniqueJsProcessingCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "script");
}

/** New elenko_js_processing document from an existing one (new _id; hash recomputed). */
function buildJsProcessingDocFromSource(baseDoc, name) {
  const script = typeof baseDoc.script === "string" ? baseDoc.script : "";
  const timeout = Math.min(Math.max(Number(baseDoc.timeout) || 5000, 100), 60000);
  return {
    type: "elenko_js_processing",
    name,
    description: typeof baseDoc.description === "string" ? baseDoc.description.trim() : "",
    script,
    timeout,
    hash: computeScriptHash(script),
  };
}

/** New elenko_api document from an existing API (new _id; apiKeyRef cleared). */
function buildApiDocFromSource(baseApi, name) {
  return {
    type: "elenko_api",
    name,
    description: typeof baseApi.description === "string" ? baseApi.description.trim() : "",
    url: typeof baseApi.url === "string" ? baseApi.url.trim() : "",
    method: baseApi.method === "POST" || baseApi.method === "PUT" || baseApi.method === "PATCH" ? baseApi.method : "GET",
    apiKeyRef: "",
    responseTarget:
      baseApi.responseTarget === "create" ? "create" : baseApi.responseTarget === "forward" ? "forward" : "update",
    template: typeof baseApi.template === "string" ? baseApi.template.trim() : "",
    responseField: typeof baseApi.responseField === "string" ? baseApi.responseField.trim() : "",
    responseStart: typeof baseApi.responseStart === "string" ? baseApi.responseStart : "",
    responseEnd: typeof baseApi.responseEnd === "string" ? baseApi.responseEnd : "",
  };
}

/** New elenko_flow document from an existing flow (new _id on insert). */
function buildFlowDocFromSource(baseFlow, name) {
  return {
    type: "elenko_flow",
    name,
    description: typeof baseFlow.description === "string" ? baseFlow.description.trim() : "",
    steps: normalizeFlowSteps(baseFlow.steps || []),
  };
}

function makeUniqueProfileCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "profile");
}

/** Deep clone elenko_profile for Copy (new _id on insert). */
function buildProfileDocFromSource(baseProfile, name) {
  const raw = JSON.parse(JSON.stringify(baseProfile));
  delete raw._id;
  delete raw._rev;
  raw.type = "elenko_profile";
  raw.name = name;
  raw.createdAt = new Date().toISOString();
  return raw;
}

function escapeRegex(s) {
  return String(s).replace(/[\\^$.*+?()|[\]{}]/g, "\\$&");
}

/** One semicolon-separated CSV line; supports "quoted" fields and doubled quotes (""). */
function splitSemicolonCsvLine(line) {
  const out = [];
  let cur = "";
  let i = 0;
  let inQuotes = false;
  const s = String(line);
  while (i < s.length) {
    const c = s[i];
    if (inQuotes) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          cur += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      cur += c;
      i++;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      i++;
      continue;
    }
    if (c === ";") {
      out.push(cur);
      cur = "";
      i++;
      continue;
    }
    cur += c;
    i++;
  }
  out.push(cur);
  return out.map((cell) => String(cell).trim());
}

function parseSemicolonCsvText(text) {
  const normalized = String(text).replace(/^\uFEFF/, "");
  const lines = normalized.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const rows = lines.map((line) => splitSemicolonCsvLine(line));
  while (rows.length > 0 && rows[rows.length - 1].every((c) => String(c).trim() === "")) {
    rows.pop();
  }
  return rows;
}

function csvDataRowIsEmpty(row) {
  if (!row || !row.length) return true;
  return row.every((c) => String(c).trim() === "");
}

const MAX_CSV_IMPORT_ROWS = 50000;

function normalizeFlowSteps(steps) {
  if (!Array.isArray(steps) || steps.length === 0) return [{ target: "log", param: "", label: "Log" }];
  return steps
    .map((s) => {
      const t = s && s.target;
      const target =
        t === "localDb"
          ? "localDb"
          : t === "api"
          ? "api"
          : t === "script"
          ? "script"
          : t === "update"
          ? "update"
          : t === "create"
          ? "create"
          : "log";
      const param = typeof (s && s.param) === "string" ? s.param.trim() : "";
      const label = typeof (s && s.label) === "string" ? s.label.trim() : "";
      return { target, param, label: label || target };
    })
    .filter(Boolean);
}

/** SHA-256 hash of script content for integrity verification when non-admin runs the flow. */
function computeScriptHash(script) {
  return crypto.createHash("sha256").update(typeof script === "string" ? script : "").digest("hex");
}

// JavaScript sandbox execution moved to `scriptWorker.js`.

function previewApiKey(apiKey) {
  const s = apiKey == null ? "" : String(apiKey);
  if (!s) return "";
  if (s.length <= 4) return s;
  return s.slice(0, 2) + "…" + s.slice(-2);
}

function apiKeyLookupErrorInfo(err) {
  if (!err) return { message: "unknown error", code: "" };
  const message = err && err.message ? String(err.message) : String(err);
  const code = err && (err.statusCode != null || err.code != null)
    ? String(err.statusCode != null ? err.statusCode : err.code)
    : "";
  return { message, code };
}

function buildSortKey(record, sortKeyFields) {
  if (!Array.isArray(sortKeyFields) || sortKeyFields.length === 0) return [];
  const out = [];
  for (let i = 0; i < Math.min(sortKeyFields.length, SORT_KEY_FIELDS_MAX); i++) {
    const f = sortKeyFields[i];
    if (!f || typeof f !== "string" || !f.trim()) continue;
    let key = f.trim();
    if (key === "_createdAt") key = "createdAt";
    if (key === "_updatedAt") key = "updatedAt";
    out.push(record[key] != null ? String(record[key]) : "");
  }
  return out;
}

function getProfileEntryFormIds(profileDoc) {
  if (!profileDoc || typeof profileDoc !== "object") return [];
  const fromArray = Array.isArray(profileDoc.entryFormIds) ? profileDoc.entryFormIds : [];
  const cleaned = fromArray
    .filter((id) => typeof id === "string" && id.trim())
    .map((id) => id.trim());
  const single = typeof profileDoc.entryFormId === "string" ? profileDoc.entryFormId.trim() : "";
  if (single && !cleaned.includes(single)) cleaned.unshift(single);
  return cleaned;
}

function getProfileDefaultEntryFormId(profileDoc) {
  const ids = getProfileEntryFormIds(profileDoc);
  return ids.length > 0 ? ids[0] : "";
}

function isMobileRequest(req) {
  try {
    const ua = String(req.get("user-agent") || "");
    if (!ua) return false;
    return /Mobile|Android|iPhone|iPad|iPod|Windows Phone|Opera Mini|IEMobile/i.test(ua);
  } catch {
    return false;
  }
}

/** Create an entry in the target profile from context.dataset. Returns the created document. Used by flow worker and pipeline. */
async function createEntryInProfileFromContext(dbInstance, context, targetProfileId) {
  const tid = (targetProfileId != null ? String(targetProfileId) : "").trim();
  if (!tid) throw new Error("createEntryInProfileFromContext: missing targetProfileId");
  let targetProfile = null;
  try {
    targetProfile = await dbInstance.get(tid);
  } catch (e) {
    if (e.statusCode !== 404) throw e;
  }
  if (!targetProfile || targetProfile.type !== "elenko_profile") {
    const byName = await dbInstance.find({
      selector: { type: "elenko_profile", name: tid },
      limit: 1,
    });
    targetProfile = byName.docs && byName.docs[0];
  }
  if (!targetProfile || targetProfile.type !== "elenko_profile") {
    throw new Error("Target profile not found or not a profile: " + tid);
  }
  const resolvedProfileId = targetProfile._id;
  const fieldNames = Array.isArray(targetProfile.fieldNames) ? targetProfile.fieldNames : [];
  const dataset = context.dataset && typeof context.dataset === "object" ? context.dataset : {};
  const record = {
    type: "elenko_record",
    profileId: resolvedProfileId,
    sourceDocId: (context.entryId != null ? String(context.entryId) : "") || (context.sourceDocId != null ? String(context.sourceDocId) : ""),
  };
  for (const fn of fieldNames) {
    record[fn] = dataset[fn] != null ? String(dataset[fn]).trim() : "";
  }
  const now = new Date().toISOString();
  record.createdAt = now;
  record.updatedAt = now;
  const sortKeyFields = Array.isArray(targetProfile.sortKeyFields) ? targetProfile.sortKeyFields : [];
  record.sortKey = buildSortKey(record, sortKeyFields);
  const profileFormIds = getProfileEntryFormIds(targetProfile);
  if (profileFormIds.length > 0) {
    record.entryFormId = profileFormIds[0];
  }
  const result = await dbInstance.insert(record);
  clearProfileListCache(resolvedProfileId);
  return { ...record, _id: result.id, _rev: result.rev };
}

/** Update the current entry (context.entryId) from context.dataset. Used by multi-step flows. */
async function updateCurrentEntryFromDataset(dbInstance, context) {
  if (!dbInstance) return;
  const entryId = context && context.entryId;
  const profileId = context && context.profileId;
  if (!entryId || !profileId) return;
  let existing;
  try {
    existing = await dbInstance.get(entryId);
  } catch (e) {
    return;
  }
  if (!existing || existing.type !== "elenko_record" || existing.profileId !== profileId) return;
  const dataset = context.dataset && typeof context.dataset === "object" ? context.dataset : {};
  const patch = { ...dataset };
  // Do not persist helper fields used only inside the pipeline
  delete patch._lastCreatedId;
  const updated = { ...existing, ...patch };
  await dbInstance.insert(updated);
  clearProfileListCache(profileId);
}

/** Run a single API call and return a Promise that resolves with the response. Used by pipeline. */
function runApiCallAndWait(apiDocId, context) {
  return new Promise((resolve, reject) => {
    const requestId = "pipe-" + Date.now() + "-" + Math.random().toString(36).slice(2);
    const timeout = setTimeout(() => {
      if (pendingApiRequests.has(requestId)) {
        const p = pendingApiRequests.get(requestId);
        pendingApiRequests.delete(requestId);
        if (p.timeoutId) clearTimeout(p.timeoutId);
        p.reject(new Error("API call timeout"));
      }
    }, 60000);
    pendingApiRequests.set(requestId, { resolve, reject, timeoutId: timeout, apiKeyPreview: "" });
    (async () => {
      try {
        if (!configDb || !apiWorker) {
          const p = pendingApiRequests.get(requestId);
          if (p) { pendingApiRequests.delete(requestId); clearTimeout(timeout); p.reject(new Error("Config store or API worker not available")); }
          return;
        }
        const tid = (apiDocId != null ? String(apiDocId) : "").trim();
        if (!tid) {
          const p = pendingApiRequests.get(requestId);
          if (p) { pendingApiRequests.delete(requestId); clearTimeout(timeout); p.reject(new Error("Missing API doc id")); }
          return;
        }
        let apiDoc = null;
        try {
          apiDoc = await configDb.get(tid);
        } catch (e) {
          if (e.statusCode !== 404) throw e;
        }
        if (!apiDoc || apiDoc.type !== "elenko_api") {
          const byName = await configDb.find({ selector: { type: "elenko_api", name: tid }, limit: 1 });
          apiDoc = byName.docs && byName.docs[0];
        }
        if (!apiDoc || apiDoc.type !== "elenko_api") {
          const p = pendingApiRequests.get(requestId);
          if (p) { pendingApiRequests.delete(requestId); clearTimeout(timeout); p.reject(new Error("API doc not found: " + tid)); }
          return;
        }
        let apiKey = null;
        let apiKeyRef = "";
        let apiKeyLookupError = null;
        if (apiDoc.apiKeyRef && typeof apiDoc.apiKeyRef === "string" && apiDoc.apiKeyRef.trim()) {
          apiKeyRef = apiDoc.apiKeyRef.trim();
          try {
            const keyDoc = await configDb.get(apiKeyRef);
            if (keyDoc && (keyDoc.key != null || keyDoc.value != null)) apiKey = keyDoc.key != null ? String(keyDoc.key) : String(keyDoc.value);
          } catch (e) {
            apiKeyLookupError = e;
          }
        }
        const p = pendingApiRequests.get(requestId);
        if (p) p.apiKeyPreview = previewApiKey(apiKey);
        if (flowWorker) {
          if (apiKeyLookupError) {
            const info = apiKeyLookupErrorInfo(apiKeyLookupError);
            sendFlowMessage("api.keyLookupError", {
              entryId: context.entryId,
              profileId: context.profileId,
              apiKeyRef: apiKeyRef || "",
              code: info.code,
              reason: info.message,
            });
          } else if (apiKeyRef && !apiKey) {
            sendFlowMessage("api.keyLookupError", {
              entryId: context.entryId,
              profileId: context.profileId,
              apiKeyRef,
              code: "",
              reason: "API key document has no key/value field",
            });
          }
        }
        apiWorker.postMessage({
          kind: "apiRequest",
          requestId,
          apiDoc: { url: apiDoc.url, method: apiDoc.method, responseTarget: apiDoc.responseTarget, template: apiDoc.template, responseField: apiDoc.responseField, responseStart: apiDoc.responseStart, responseEnd: apiDoc.responseEnd },
          apiKey,
          dataset: context.dataset,
          entryId: context.entryId,
          profileId: context.profileId,
        });
      } catch (err) {
        const p = pendingApiRequests.get(requestId);
        if (p) { pendingApiRequests.delete(requestId); clearTimeout(timeout); p.reject(err); }
      }
    })();
  });
}

/** Run a flow document's steps in order. Context is mutated (dataset, lastApiResponse, etc.). */
async function runPipeline(context, flowDoc) {
  const steps = Array.isArray(flowDoc && flowDoc.steps) ? flowDoc.steps : [];
  let hasExplicitPersistStep = false;
  const suppressSinglePersist = !!(context && context.suppressSinglePersist);
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const rawTarget = step && step.target;
    const target =
      rawTarget === "localDb"
        ? "localDb"
        : rawTarget === "api"
        ? "api"
        : rawTarget === "script"
        ? "script"
        : rawTarget === "update"
        ? "update"
        : rawTarget === "create"
        ? "create"
        : "log";
    if (target === "log") {
      sendFlowMessage("entry.sendToFlow", {
        target: "log",
        profileId: context.profileId,
        entryId: context.entryId,
        profileName: context.profileName,
        dataset: context.dataset,
        param: context.param,
      });
      continue;
    }
    if (target === "update") {
      if (suppressSinglePersist) continue;
      hasExplicitPersistStep = true;
      await updateCurrentEntryFromDataset(db, context);
      continue;
    }
    if (target === "create") {
      if (suppressSinglePersist) continue;
      hasExplicitPersistStep = true;
      if (context.profileId && db) {
        const created = await createEntryInProfileFromContext(db, context, context.profileId);
        context.dataset = { ...(context.dataset || {}), _lastCreatedId: created._id };
      }
      continue;
    }
    if (target === "script") {
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      if (!param || !configDb) continue;
      let jsDoc = null;
      try {
        jsDoc = await configDb.get(param);
      } catch (e) {
        if (e.statusCode !== 404) throw e;
      }
      if (!jsDoc || jsDoc.type !== "elenko_js_processing") {
        const byName = await configDb.find({ selector: { type: "elenko_js_processing", name: param }, limit: 1 });
        jsDoc = byName.docs && byName.docs[0];
      }
      if (!jsDoc || jsDoc.type !== "elenko_js_processing") {
        sendFlowMessage("flow.scriptError", { stepIndex: i, error: "JS Processing document not found", param });
        continue;
      }
      const script = typeof jsDoc.script === "string" ? jsDoc.script : "";
      const storedHash = typeof jsDoc.hash === "string" ? jsDoc.hash.trim() : "";
      const computedHash = computeScriptHash(script);
      if (script && !storedHash) {
        sendFlowMessage("flow.scriptError", { stepIndex: i, error: "Script has no integrity hash. Save the JS Processing document as admin first.", param });
        continue;
      }
      if (storedHash && computedHash !== storedHash) {
        sendFlowMessage("flow.scriptError", { stepIndex: i, error: "Script integrity check failed (hash mismatch). Only an admin can update the script.", param });
        continue;
      }
      const timeoutMs = Math.min(Math.max(Number(jsDoc.timeout) || 5000, 100), 60000);
      const input = context.dataset && typeof context.dataset === "object" ? { ...context.dataset } : {};
      const result = await runScriptInFlowWorker(script, input, timeoutMs);
      if (result.error) {
        sendFlowMessage("flow.scriptError", {
          stepIndex: i,
          param,
          error: "JavaScript error: " + result.error,
          profileId: context.profileId,
          entryId: context.entryId,
        });
        continue;
      }
      sendFlowMessage("flow.scriptReturn", {
        stepIndex: i,
        param,
        returnValue: result.returnValue,
        error: null,
        profileId: context.profileId,
        entryId: context.entryId,
      });
      if (Array.isArray(result.scriptLogs) && result.scriptLogs.length > 0) {
        for (const item of result.scriptLogs) {
          sendFlowMessage("flow.scriptLog", {
            stepIndex: i,
            param,
            profileId: context.profileId,
            entryId: context.entryId,
            item,
          });
        }
      }
      if (result.output && typeof result.output === "object") {
        const scriptOutput = { ...result.output };
        const createManyRaw = Array.isArray(scriptOutput._createMany) ? scriptOutput._createMany : null;
        delete scriptOutput._createMany;
        context.dataset = { ...(context.dataset || {}), ...scriptOutput };
        if (createManyRaw && context.profileId && db) {
          let createdCount = 0;
          for (const row of createManyRaw) {
            if (!row || typeof row !== "object") continue;
            await createEntryInProfileFromContext(db, { dataset: row }, context.profileId);
            createdCount++;
          }
          context.dataset._lastCreatedCount = createdCount;
          hasExplicitPersistStep = true;
        }
      }
      continue;
    }
    if (target === "localDb") {
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      if (!param) continue;
      const created = await createEntryInProfileFromContext(db, context, param);
      context.dataset = { ...(context.dataset || {}), _lastCreatedId: created._id };
      continue;
    }
    if (target === "api") {
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      if (!param) continue;
      const result = await runApiCallAndWait(param, context);
      const bodyStr = (result.body === undefined || result.body === null) ? "" : (typeof result.body === "string" ? result.body : JSON.stringify(result.body));
      context.lastApiResponse = { success: result.success, statusCode: result.statusCode, body: bodyStr, error: result.error };
      if (context.dataset && result.responseField && typeof result.responseField === "string" && result.responseField.trim()) {
        context.dataset[result.responseField.trim()] = bodyStr;
      }
    }
  }
}

const PBKDF2_ITERATIONS = 100000;
const SALT_LEN = 16;
const KEY_LEN = 32;

let flowWorker;
let apiWorker;

// Forward *server.js* console errors to the flow log as well.
// Keep console.log unchanged; only wrap console.error.
console.error = function (...args) {
  // Preserve existing stderr behavior.
  originalConsoleError(...args);
  // Avoid breaking anything if flow forwarding fails.
  try {
    sendFlowMessage("console.error", {
      args: serializeConsoleArgsForFlow(args),
    });
  } catch (_) {
    // no-op
  }
};

const pendingApiRequests = new Map();

const pendingScriptRequests = new Map();

function runScriptInFlowWorker(script, input, timeoutMs) {
  if (!flowWorker) return Promise.reject(new Error("Flow worker not available"));
  const requestId = "pipeScript-" + Date.now() + "-" + Math.random().toString(36).slice(2);
  const scriptTimeout = Math.min(Math.max(Number(timeoutMs) || 5000, 100), 60000) + 2000;

  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      if (pendingScriptRequests.has(requestId)) {
        pendingScriptRequests.delete(requestId);
        reject(new Error("Script execution timeout"));
      }
    }, scriptTimeout);
    pendingScriptRequests.set(requestId, { resolve, reject, timeoutId });

    try {
      flowWorker.postMessage({
        kind: "flow.scriptRequest",
        payload: {
          requestId,
          script,
          input,
          timeoutMs,
        },
        ts: new Date().toISOString(),
      });
    } catch (err) {
      clearTimeout(timeoutId);
      pendingScriptRequests.delete(requestId);
      reject(err);
    }
  });
}

let cachedAppConfig = null;
let cachedAppConfigLoadedAt = 0;

async function getAppUiConfig() {
  const now = Date.now();
  if (cachedAppConfig && now - cachedAppConfigLoadedAt < 30000) return cachedAppConfig;
  if (!configDb) {
    cachedAppConfig = { theme: { ...DEFAULT_APP_THEME }, logoUrl: "", logoWidth: 0, logoHeight: 0, loginTextAbove: "", loginTextBelow: "", couchdbPassword: "" };
    cachedAppConfigLoadedAt = now;
    return cachedAppConfig;
  }
  try {
    const result = await configDb.find({
      selector: { type: "elenko_app_config" },
      limit: 1,
    });
    const doc = (result.docs && result.docs[0]) || null;
    if (!doc) {
      cachedAppConfig = { theme: { ...DEFAULT_APP_THEME }, logoUrl: "", logoWidth: 0, logoHeight: 0, loginTextAbove: "", loginTextBelow: "", couchdbPassword: "" };
    } else {
      const theme = normalizeAppTheme(doc.theme);
      cachedAppConfig = {
        _id: doc._id,
        _rev: doc._rev,
        theme,
        logoUrl: typeof doc.logoUrl === "string" ? doc.logoUrl.trim() : "",
        logoWidth: Number.isFinite(doc.logoWidth) ? doc.logoWidth : 0,
        logoHeight: Number.isFinite(doc.logoHeight) ? doc.logoHeight : 0,
        loginTextAbove: typeof doc.loginTextAbove === "string" ? doc.loginTextAbove.trim() : "",
        loginTextBelow: typeof doc.loginTextBelow === "string" ? doc.loginTextBelow.trim() : "",
        couchdbPassword: typeof doc.couchdbPassword === "string" ? doc.couchdbPassword : "",
      };
    }
  } catch {
    cachedAppConfig = { theme: { ...DEFAULT_APP_THEME }, logoUrl: "", logoWidth: 0, logoHeight: 0, loginTextAbove: "", loginTextBelow: "", couchdbPassword: "" };
  }
  cachedAppConfigLoadedAt = now;
  // Ensure new fields always present for older config docs or cache
  if (cachedAppConfig && typeof cachedAppConfig.loginTextAbove !== "string") cachedAppConfig.loginTextAbove = "";
  if (cachedAppConfig && typeof cachedAppConfig.loginTextBelow !== "string") cachedAppConfig.loginTextBelow = "";
  if (cachedAppConfig && typeof cachedAppConfig.couchdbPassword !== "string") cachedAppConfig.couchdbPassword = "";
  return cachedAppConfig;
}

const CONFIG_EXPORT_VERSION = 1;
const EXPORTABLE_DB_TYPES = new Set(["elenko_profile", "elenko_entry_form"]);
const EXPORTABLE_CONFIG_TYPES = new Set(["elenko_app_config", "elenko_flow", "elenko_api", "elenko_js_processing"]);

function stripForExport(doc, type) {
  if (!doc || typeof doc !== "object") return null;
  const out = { ...doc };
  delete out._rev;
  if (type === "elenko_api") {
    out.apiKeyRef = "";
  }
  if (type === "elenko_app_config") {
    delete out.couchdbPassword;
  }
  return out;
}

async function getFlowIdsFromFormDocs(dbInstance, formDocs) {
  const flowIds = new Set();
  for (const form of formDocs) {
    const configs = Array.isArray(form.flowConfigs) ? form.flowConfigs : [];
    for (const c of configs) {
      const id = (c && typeof c.flowId === "string") ? c.flowId.trim() : "";
      if (id) flowIds.add(id);
    }
  }
  const result = [];
  if (!configDb) return result;
  for (const fid of flowIds) {
    let doc = null;
    try {
      doc = await configDb.get(fid);
    } catch (e) {
      if (e.statusCode !== 404) throw e;
    }
    if (!doc && fid) {
      const byName = await configDb.find({ selector: { type: "elenko_flow", name: fid }, limit: 1 });
      doc = byName.docs && byName.docs[0];
    }
    if (doc && doc.type === "elenko_flow" && doc._id) result.push(doc._id);
  }
  return [...new Set(result)];
}

function getApiAndJsIdsFromFlowDocs(flowDocs) {
  const apiIds = new Set();
  const jsIds = new Set();
  for (const flow of flowDocs) {
    const steps = Array.isArray(flow.steps) ? flow.steps : [];
    for (const step of steps) {
      const target = step && step.target;
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      if (target === "api" && param) apiIds.add(param);
      if (target === "script" && param) jsIds.add(param);
    }
  }
  return { apiIds: [...apiIds], jsIds: [...jsIds] };
}

async function resolveConfigDocIds(configDbInstance, ids, type, nameField) {
  const result = [];
  for (const id of ids) {
    let doc = null;
    try {
      doc = await configDbInstance.get(id);
    } catch (e) {
      if (e.statusCode !== 404) throw e;
    }
    if (!doc && nameField) {
      const byName = await configDbInstance.find({
        selector: { type, [nameField]: id },
        limit: 1,
      });
      doc = byName.docs && byName.docs[0];
    }
    if (doc && doc._id) result.push(doc._id);
  }
  return [...new Set(result)];
}

async function buildConfigExport(scope, profileId) {
  const docsDb = [];
  const docsConfig = [];
  const seenConfig = new Set();
  const seenDb = new Set();

  const addDb = (doc) => {
    if (!doc || !EXPORTABLE_DB_TYPES.has(doc.type)) return;
    const id = doc._id;
    if (seenDb.has(id)) return;
    seenDb.add(id);
    docsDb.push(stripForExport(doc, doc.type));
  };
  const addConfig = (doc) => {
    if (!doc || !EXPORTABLE_CONFIG_TYPES.has(doc.type)) return;
    const id = doc._id;
    if (seenConfig.has(id)) return;
    seenConfig.add(id);
    docsConfig.push(stripForExport(doc, doc.type));
  };

  if (scope === "all" && configDb) {
    const appResult = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
    const appDoc = appResult.docs && appResult.docs[0];
    if (appDoc) addConfig(appDoc);
  }

  const profileIds = scope === "all"
    ? (await db.find({ selector: { type: "elenko_profile" }, fields: ["_id"], limit: 1000 })).docs.map((p) => p._id)
    : (profileId ? [profileId] : []);

  for (const pid of profileIds) {
    let profile;
    try {
      profile = await db.get(pid);
    } catch (e) {
      if (e.statusCode === 404) continue;
      throw e;
    }
    if (!profile || profile.type !== "elenko_profile") continue;
    addDb(profile);

    const mobileSingleFormId =
      typeof profile.mobileSingleEntryFormId === "string" && profile.mobileSingleEntryFormId.trim()
        ? profile.mobileSingleEntryFormId.trim()
        : "";
    const formIdSet = new Set(getProfileEntryFormIds(profile));
    if (mobileSingleFormId) formIdSet.add(mobileSingleFormId);
    const formIds = [...formIdSet];
    for (const fid of formIds) {
      try {
        const formDoc = await db.get(fid);
        if (formDoc && formDoc.type === "elenko_entry_form") addDb(formDoc);
      } catch (_) {}
    }

    const formDocs = [];
    for (const fid of formIds) {
      try {
        const formDoc = await db.get(fid);
        if (formDoc && formDoc.type === "elenko_entry_form") formDocs.push(formDoc);
      } catch (_) {}
    }

    // Flows referenced from entry forms (flow buttons)
    const flowIdSet = new Set(await getFlowIdsFromFormDocs(db, formDocs));
    // Also include profile-level Information Import flow linkage (new field, with legacy fallback).
    const profileInfoFlowId =
      typeof profile.infoImportFlowId === "string" && profile.infoImportFlowId.trim()
        ? profile.infoImportFlowId.trim()
        : (typeof profile.guardianFlowId === "string" && profile.guardianFlowId.trim() ? profile.guardianFlowId.trim() : "");
    if (profileInfoFlowId) {
      const resolvedProfileFlowIds = await resolveConfigDocIds(configDb, [profileInfoFlowId], "elenko_flow", "name");
      for (const rf of resolvedProfileFlowIds) flowIdSet.add(rf);
    }
    const flowIds = [...flowIdSet];
    const flowDocs = [];
    for (const flid of flowIds) {
      try {
        const flowDoc = await configDb.get(flid);
        if (flowDoc && flowDoc.type === "elenko_flow") flowDocs.push(flowDoc);
      } catch (_) {}
    }
    for (const f of flowDocs) addConfig(f);

    // APIs referenced directly from entry forms (Single step with target = "api")
    if (configDb) {
      const directApiNames = new Set();
      for (const form of formDocs) {
        const cfgs = Array.isArray(form.flowConfigs) ? form.flowConfigs : [];
        for (const c of cfgs) {
          const flowId = (c && typeof c.flowId === "string") ? c.flowId.trim() : "";
          const target = c && c.target;
          const param = (c && typeof c.param === "string") ? c.param.trim() : "";
          if (!flowId && target === "api" && param) {
            directApiNames.add(param);
          }
        }
      }
      if (directApiNames.size > 0) {
        const resolvedDirectApiIds = await resolveConfigDocIds(configDb, [...directApiNames], "elenko_api", "name");
        for (const aid of resolvedDirectApiIds) {
          try {
            const apiDoc = await configDb.get(aid);
            if (apiDoc && apiDoc.type === "elenko_api") addConfig(apiDoc);
          } catch (_) {}
        }
      }
    }

    const { apiIds, jsIds } = getApiAndJsIdsFromFlowDocs(flowDocs);
    const resolvedApiIds = await resolveConfigDocIds(configDb, apiIds, "elenko_api", "name");
    const resolvedJsIds = await resolveConfigDocIds(configDb, jsIds, "elenko_js_processing", "name");
    for (const aid of resolvedApiIds) {
      try {
        const apiDoc = await configDb.get(aid);
        if (apiDoc && apiDoc.type === "elenko_api") addConfig(apiDoc);
      } catch (_) {}
    }
    for (const jid of resolvedJsIds) {
      try {
        const jsDoc = await configDb.get(jid);
        if (jsDoc && jsDoc.type === "elenko_js_processing") addConfig(jsDoc);
      } catch (_) {}
    }
  }

  return {
    version: CONFIG_EXPORT_VERSION,
    scope,
    profileId: scope === "profile" ? profileId || null : null,
    exportedAt: new Date().toISOString(),
    documents: { db: docsDb, configDb: docsConfig },
  };
}

async function applyConfigImport(data, overwrite) {
  const errors = [];
  let importedDb = 0;
  let importedConfig = 0;
  const payload = data && data.documents;
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "Invalid export format: missing documents" };
  }
  const docsDb = Array.isArray(payload.db) ? payload.db : [];
  const docsConfig = Array.isArray(payload.configDb) ? payload.configDb : [];

  for (const doc of docsDb) {
    if (!doc || typeof doc !== "object" || !EXPORTABLE_DB_TYPES.has(doc.type)) continue;
    const id = doc._id;
    const toInsert = { ...doc };
    delete toInsert._rev;
    try {
      if (id) {
        try {
          const existing = await db.get(id);
          if (existing && overwrite) {
            toInsert._rev = existing._rev;
            await db.insert(toInsert);
            importedDb++;
          }
        } catch (e) {
          if (e.statusCode === 404) {
            await db.insert(toInsert);
            importedDb++;
          } else throw e;
        }
      } else {
        await db.insert(toInsert);
        importedDb++;
      }
    } catch (err) {
      errors.push({ id: id || "(new)", type: doc.type, message: err.message || String(err) });
    }
  }

  for (const doc of docsConfig) {
    if (!doc || typeof doc !== "object" || !EXPORTABLE_CONFIG_TYPES.has(doc.type)) continue;
    const id = doc._id;
    const toInsert = { ...doc };
    delete toInsert._rev;
    if (toInsert.type === "elenko_api") toInsert.apiKeyRef = toInsert.apiKeyRef || "";
    try {
      if (!configDb) {
        errors.push({ id: id || "(new)", type: doc.type, message: "Config store not available" });
        continue;
      }
      if (id) {
        try {
          const existing = await configDb.get(id);
          if (existing && overwrite) {
            toInsert._rev = existing._rev;
            await configDb.insert(toInsert);
            importedConfig++;
          }
        } catch (e) {
          if (e.statusCode === 404) {
            await configDb.insert(toInsert);
            importedConfig++;
          } else throw e;
        }
      } else {
        await configDb.insert(toInsert);
        importedConfig++;
      }
    } catch (err) {
      errors.push({ id: id || "(new)", type: doc.type, message: err.message || String(err) });
    }
  }

  if (importedConfig > 0 || docsConfig.some((d) => d && d.type === "elenko_app_config")) {
    cachedAppConfig = null;
    cachedAppConfigLoadedAt = 0;
  }
  return {
    ok: errors.length === 0,
    importedDb,
    importedConfig,
    errors: errors.length > 0 ? errors : undefined,
  };
}

function startApiWorker() {
  const workerPath = path.join(__dirname, "apiWorker.js");
  apiWorker = new Worker(workerPath);
  apiWorker.on("error", (err) => {
    console.error("API worker error:", err);
  });
  apiWorker.on("exit", (code) => {
    if (code !== 0) {
      console.error(`API worker exited with code ${code}`);
    }
  });
  apiWorker.on("message", (msg) => {
    if (msg.kind !== "apiResponse") return;
    const requestId = msg.requestId;
    if (requestId != null && pendingApiRequests.has(requestId)) {
      const p = pendingApiRequests.get(requestId);
      pendingApiRequests.delete(requestId);
      if (p.timeoutId) clearTimeout(p.timeoutId);
      const apiKeyPreview = p.apiKeyPreview;
      const responseStart = msg.responseStart;
      const responseEnd = msg.responseEnd;
      let bodyToResolve = msg.body;
      if (bodyToResolve != null && (responseStart || responseEnd)) {
        const bodyStr = typeof bodyToResolve === "string" ? bodyToResolve : JSON.stringify(bodyToResolve);
        const start = typeof responseStart === "string" && responseStart ? bodyStr.indexOf(responseStart) : 0;
        const startIdx = start === -1 ? 0 : start + (typeof responseStart === "string" && responseStart ? responseStart.length : 0);
        const endIdx = (typeof responseEnd === "string" && responseEnd)
          ? (bodyStr.indexOf(responseEnd, startIdx) === -1 ? bodyStr.length : bodyStr.indexOf(responseEnd, startIdx))
          : bodyStr.length;
        bodyToResolve = bodyStr.slice(startIdx, endIdx).trim();
      }
      p.resolve({
        success: !!msg.success,
        statusCode: msg.statusCode ?? null,
        body: bodyToResolve,
        error: msg.error ?? null,
        responseTarget: msg.responseTarget || "update",
        responseField: msg.responseField,
        responseStart: msg.responseStart,
        responseEnd: msg.responseEnd,
      });
      if (flowWorker) {
        // Don't log the full secret; only a safe preview.
        sendFlowMessage("api.keyPreview", {
          entryId: msg.entryId,
          profileId: msg.profileId,
          apiKeyPreview: apiKeyPreview || "",
        });
      }
      return;
    }
    const { entryId, profileId, success, statusCode, body, error, responseTarget, responseField, responseStart, responseEnd } = msg;
    const bodyForLog = body != null ? (typeof body === "string" ? body : JSON.stringify(body)) : null;
    const bodyTruncated = bodyForLog && bodyForLog.length > 2048 ? bodyForLog.slice(0, 2048) + "…[truncated]" : bodyForLog;
    sendFlowMessage("api.response", {
      entryId,
      profileId,
      success: !!success,
      statusCode: statusCode ?? null,
      body: bodyTruncated,
      error: error ?? null,
      responseTarget: responseTarget || "update",
    });
    (async () => {
      try {
        if (!configDb || !db) return;
        // For direct API calls (no requestId), always update the current document.
        const now = new Date().toISOString();
        const bodyStr = (body === undefined || body === null) ? "" : (typeof body === "string" ? body : JSON.stringify(body));
        let bodyToStore = bodyStr;
        if ((responseStart || responseEnd) && bodyStr) {
          const start = typeof responseStart === "string" && responseStart ? bodyStr.indexOf(responseStart) : 0;
          const startIdx = start === -1 ? 0 : start + (typeof responseStart === "string" && responseStart ? responseStart.length : 0);
          const endIdx = (typeof responseEnd === "string" && responseEnd)
            ? (bodyStr.indexOf(responseEnd, startIdx) === -1 ? bodyStr.length : bodyStr.indexOf(responseEnd, startIdx))
            : bodyStr.length;
          bodyToStore = bodyStr.slice(startIdx, endIdx).trim();
        }
        const lastApiResponse = { statusCode: statusCode ?? null, body: bodyToStore, ts: now, success: !!success, error: error ?? null };
        const record = await db.get(entryId);
        if (!record || record.type !== "elenko_record" || record.profileId !== profileId) return;
        record.lastApiResponse = lastApiResponse;
        if (responseField && typeof responseField === "string" && responseField.trim()) {
          const fieldName = responseField.trim();
          record[fieldName] = bodyToStore;
        }
        await db.insert(record);
        clearProfileListCache(profileId);
      } catch (err) {
        console.error("API worker: apiResponse handling failed:", err);
      }
    })();
  });
}

function startFlowWorker() {
  const workerPath = path.join(__dirname, "flowWorker.js");
  flowWorker = new Worker(workerPath, {
    workerData: { envPath: path.join(__dirname, ".env") },
  });
  flowWorker.on("error", (err) => {
    console.error("Flow worker error:", err);
  });
  flowWorker.on("exit", (code) => {
    if (code !== 0) {
      console.error(`Flow worker exited with code ${code}`);
    }
  });
  flowWorker.on("message", (msg) => {
    if (msg && msg.kind === "flow.scriptResponse") {
      const requestId = msg.requestId;
      if (requestId != null && pendingScriptRequests.has(requestId)) {
        const p = pendingScriptRequests.get(requestId);
        pendingScriptRequests.delete(requestId);
        if (p.timeoutId) clearTimeout(p.timeoutId);
        p.resolve({
          returnValue: msg.returnValue,
          output: msg.output && typeof msg.output === "object" ? msg.output : {},
          scriptLogs: Array.isArray(msg.scriptLogs) ? msg.scriptLogs : [],
          error: msg.error,
        });
      }
      return;
    }
    if (msg && msg.kind === "scriptWorker.error") {
      console.error("Script worker error:", msg.error || msg);
      return;
    }
    if (msg.kind === "callApi") {
      const apiDocId = (msg.apiDocId != null ? String(msg.apiDocId) : "").trim();
      if (!apiDocId || !apiWorker) {
        if (!apiDocId) {
          console.error("Flow worker: callApi missing apiDocId");
          sendFlowMessage("api.callRejected", {
            reason: "missing apiDocId",
            hint: "Set the entry form Additional parameter to the API document ID or name (Call API target).",
            entryId: msg.entryId,
            profileId: msg.profileId,
          });
        }
        return;
      }
      (async () => {
        try {
          let apiDoc = null;
          try {
            apiDoc = await configDb.get(apiDocId);
          } catch (e) {
            if (e.statusCode !== 404) throw e;
          }
          if (!apiDoc || apiDoc.type !== "elenko_api") {
            const byName = await configDb.find({ selector: { type: "elenko_api", name: apiDocId }, limit: 1 });
            apiDoc = byName.docs && byName.docs[0];
          }
          if (!apiDoc || apiDoc.type !== "elenko_api") {
            console.error("Flow worker: callApi API doc not found:", apiDocId);
            sendFlowMessage("api.callRejected", {
              reason: "apiDoc not found",
              apiDocId,
              entryId: msg.entryId,
              profileId: msg.profileId,
            });
            return;
          }
          sendFlowMessage("api.request", {
            apiDocId,
            apiName: apiDoc.name,
            entryId: msg.entryId,
            profileId: msg.profileId,
            url: apiDoc.url,
            method: apiDoc.method || "GET",
            responseTarget: apiDoc.responseTarget || "update",
            dataset: msg.dataset,
          });
          let apiKey = null;
          let apiKeyRef = "";
          let apiKeyLookupError = null;
          if (apiDoc.apiKeyRef && typeof apiDoc.apiKeyRef === "string" && apiDoc.apiKeyRef.trim()) {
            apiKeyRef = apiDoc.apiKeyRef.trim();
            try {
              const keyDoc = await configDb.get(apiKeyRef);
              if (keyDoc && (keyDoc.key != null || keyDoc.value != null)) apiKey = keyDoc.key != null ? String(keyDoc.key) : String(keyDoc.value);
            } catch (e) {
              apiKeyLookupError = e;
            }
          }
          if (apiKeyLookupError) {
            const info = apiKeyLookupErrorInfo(apiKeyLookupError);
            sendFlowMessage("api.keyLookupError", {
              entryId: msg.entryId,
              profileId: msg.profileId,
              apiKeyRef: apiKeyRef || "",
              code: info.code,
              reason: info.message,
            });
          } else if (apiKeyRef && !apiKey) {
            sendFlowMessage("api.keyLookupError", {
              entryId: msg.entryId,
              profileId: msg.profileId,
              apiKeyRef,
              code: "",
              reason: "API key document has no key/value field",
            });
          }
          const apiKeyPreview = previewApiKey(apiKey);
          apiWorker.postMessage({
            kind: "apiRequest",
            apiDoc: { url: apiDoc.url, method: apiDoc.method, responseTarget: apiDoc.responseTarget, template: apiDoc.template, responseField: apiDoc.responseField, responseStart: apiDoc.responseStart, responseEnd: apiDoc.responseEnd },
            apiKey,
            dataset: msg.dataset,
            entryId: msg.entryId,
            profileId: msg.profileId,
          });
          sendFlowMessage("api.keyPreview", {
            entryId: msg.entryId,
            profileId: msg.profileId,
            apiKeyPreview: apiKeyPreview || "",
          });
        } catch (err) {
          console.error("Flow worker: callApi failed:", err);
        }
      })();
      return;
    }
    if (msg.kind !== "createEntryInProfile") return;
    const targetProfileId = (msg.targetProfileId != null ? String(msg.targetProfileId) : "").trim();
    if (!targetProfileId) {
      console.error("Flow worker: createEntryInProfile missing targetProfileId");
      return;
    }
    (async () => {
      try {
        await createEntryInProfileFromContext(db, { dataset: msg.dataset, entryId: msg.sourceDocId }, targetProfileId);
      } catch (err) {
        console.error("Flow worker: createEntryInProfile failed:", err);
      }
    })();
  });
}

function sendFlowMessage(kind, payload) {
  if (!flowWorker) return;
  try {
    flowWorker.postMessage({
      kind,
      payload,
      ts: new Date().toISOString(),
    });
  } catch (err) {
    // Use the original console implementation to avoid recursion into this wrapper.
    originalConsoleError("Failed to send flow message:", err);
  }
}

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(SALT_LEN);
  const h = crypto.pbkdf2Sync(password, s, PBKDF2_ITERATIONS, KEY_LEN, "sha256");
  return { hash: h.toString("hex"), salt: s.toString("hex") };
}

function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = hashPassword(password, Buffer.from(storedSalt, "hex"));
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(storedHash, "hex"));
}

/** API routes should return JSON so fetch().json() does not fail on HTML error pages. */
function wantsJsonApiResponse(req) {
  return typeof req.path === "string" && req.path.startsWith("/api/");
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.method === "GET" && req.path === "/") return res.redirect("/login");
  if (wantsJsonApiResponse(req)) {
    return res.status(401).json({ error: "Authentication required" });
  }
  res.status(401).set("Content-Type", "text/html; charset=utf-8").send(renderLoginRequiredPage());
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.role === "admin") return next();
  if (wantsJsonApiResponse(req)) {
    return res.status(403).json({ error: "Admin access required" });
  }
  res.status(403).set("Content-Type", "text/html; charset=utf-8").send(renderForbiddenPage());
}

function requireEditor(req, res, next) {
  const role = req.session && req.session.role;
  if (role === "admin" || role === "editor" || role === "user") return next();
  if (wantsJsonApiResponse(req)) {
    return res.status(403).json({ error: "Access denied" });
  }
  res.status(403).set("Content-Type", "text/html; charset=utf-8").send(renderForbiddenPage());
}

let db;
let configDb;

const profileListCache = new Map();
const searchListCache = new Map();
const SEARCH_CACHE_KEY_SEP = "::";

function clearProfileListCache(profileId) {
  if (profileId) {
    profileListCache.delete(profileId);
    clearSearchListCache(profileId);
  } else {
    profileListCache.clear();
    searchListCache.clear();
  }
}

function clearSearchListCache(profileId) {
  if (!profileId) {
    searchListCache.clear();
    return;
  }
  const prefix = profileId + SEARCH_CACHE_KEY_SEP;
  for (const key of searchListCache.keys()) {
    if (key.startsWith(prefix)) searchListCache.delete(key);
  }
}

function buildCouchUrlFromBase(password) {
  try {
    const u = new URL(COUCHDB_URL);
    const host = u.host || "localhost:5984";
    const protocol = u.protocol || "http:";
    const encoded = encodeURIComponent(password || "");
    return `${protocol}//${COUCHDB_USER}:${encoded}@${host}`;
  } catch {
    return `http://${COUCHDB_USER}:${encodeURIComponent(password || "")}@localhost:5984`;
  }
}

function buildCouchOrigin() {
  try {
    const u = new URL(COUCHDB_URL);
    return `${u.protocol}//${u.host || "localhost:5984"}`;
  } catch {
    return "http://localhost:5984";
  }
}

function encryptCouchPassword(plain) {
  if (plain == null || plain === "") return "";
  const cipher = crypto.createCipheriv("aes-256-cbc", COUCHDB_ENC_KEY, COUCHDB_ENC_IV);
  const enc = Buffer.concat([cipher.update(Buffer.from(plain, "utf8")), cipher.final()]);
  return enc.toString("hex");
}

function decryptCouchPassword(encryptedHex) {
  if (!encryptedHex || typeof encryptedHex !== "string") return null;
  try {
    const buf = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", COUCHDB_ENC_KEY, COUCHDB_ENC_IV);
    return Buffer.concat([decipher.update(buf), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

function readBootstrapPassword() {
  try {
    const raw = fs.readFileSync(COUCHDB_BOOTSTRAP_FILE, "utf8");
    const data = JSON.parse(raw);
    const enc = data && (data.passwordEncrypted || data.encrypted);
    if (!enc) return null;
    return decryptCouchPassword(enc);
  } catch {
    return null;
  }
}

function isBootstrapFileMissing() {
  try {
    if (!fs.existsSync(COUCHDB_BOOTSTRAP_FILE)) return true;
    const raw = fs.readFileSync(COUCHDB_BOOTSTRAP_FILE, "utf8");
    const data = JSON.parse(raw);
    const enc = data && (data.passwordEncrypted || data.encrypted);
    return !enc;
  } catch {
    return true;
  }
}

function writeBootstrapFile(password) {
  if (password == null) password = "";
  const encrypted = encryptCouchPassword(password);
  fs.writeFileSync(
    COUCHDB_BOOTSTRAP_FILE,
    JSON.stringify({ passwordEncrypted: encrypted }, null, 2),
    "utf8"
  );
}

async function setCouchDbAdminPassword(currentPassword, newPassword) {
  const origin = buildCouchOrigin();
  const pathSegment = "_node/_local/_config/admins/" + encodeURIComponent(COUCHDB_USER);
  const url = origin.replace(/\/?$/, "") + "/" + pathSegment;
  const auth = Buffer.from(COUCHDB_USER + ":" + (currentPassword || ""), "utf8").toString("base64");
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Basic " + auth,
    },
    body: JSON.stringify(newPassword),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(res.status === 401 || res.status === 403
      ? "Current CouchDB password is incorrect or access denied."
      : (text || res.statusText || "Failed to update CouchDB admin password."));
  }
}

async function tryRestoreBootstrapFromStoredPassword() {
  if (!db || !configDb || !isBootstrapFileMissing()) return false;
  try {
    const result = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
    const doc = result.docs && result.docs[0];
    const stored = typeof (doc && doc.couchdbPassword) === "string" ? doc.couchdbPassword.trim() : "";
    if (stored === "" || stored === "admin") return false;
    const testUrl = buildCouchUrlFromBase(stored);
    let storedIsCurrentPassword = false;
    try {
      const testClient = nano(testUrl);
      await testClient.db.get(COUCHDB_DB);
      storedIsCurrentPassword = true;
    } catch (e) {
      if (!isCouchAuthError(e)) throw e;
    }
    if (storedIsCurrentPassword) {
      writeBootstrapFile(stored);
      return true;
    }
    await setCouchDbAdminPassword("admin", stored);
    writeBootstrapFile(stored);
    await initCouch({ password: stored });
    cachedAppConfig = null;
    cachedAppConfigLoadedAt = 0;
    return true;
  } catch (e) {
    console.error("Restore bootstrap from stored password failed:", e);
    return false;
  }
}

function isCouchAuthError(err) {
  if (!err) return false;
  if (err.statusCode === 401 || err.statusCode === 403) return true;
  const msg = String(err.message || err.reason || "");
  return /name or password|unauthorized|authentication|incorrect/i.test(msg);
}

async function initCouch(options) {
  let password = options && options.password;
  if (password === undefined || password === null) {
    password = readBootstrapPassword();
    if (password === null) {
      db = null;
      configDb = null;
      return;
    }
  }
  const url = buildCouchUrlFromBase(password);
  let client;
  try {
    client = nano(url);
  } catch (err) {
    console.warn("CouchDB connection failed (will show setup page):", err.message || err);
    db = null;
    configDb = null;
    return;
  }
  const dbName = COUCHDB_DB;
  try {
    await client.db.get(dbName);
  } catch (err) {
    if (err?.statusCode === 404) {
      await client.db.create(dbName);
    } else if (isCouchAuthError(err)) {
      console.warn("CouchDB authentication failed (will show setup page):", err.message || err.reason || err);
      db = null;
      configDb = null;
      return;
    } else {
      throw err;
    }
  }
  db = client.db.use(dbName);

  const configDbName = ELENKO_CONFIG_DB;
  try {
    await client.db.get(configDbName);
  } catch (err) {
    if (err?.statusCode === 404) {
      await client.db.create(configDbName);
    } else if (isCouchAuthError(err)) {
      console.warn("CouchDB authentication failed (will show setup page):", err.message || err.reason || err);
      db = null;
      configDb = null;
      return;
    } else {
      throw err;
    }
  }
  configDb = client.db.use(configDbName);
  try {
    await configDb.createIndex({
      index: { fields: ["type", "name"] },
      name: "apis-by-type-name",
    });
  } catch (e) {
    // Index may already exist
  }
  try {
    await configDb.createIndex({
      index: { fields: ["type"] },
      name: "flows-by-type",
    });
  } catch (e) {
    // Index may already exist
  }

  // Ensure Mango index for querying and sorting profiles (sort requires index on sort fields)
  try {
    await db.createIndex({
      index: { fields: ["type", "name"] },
      name: "profiles-by-type-name",
    });
  } catch (e) {
    // Index may already exist
  }

  // Index for Elenko database records (documents linked to a profile), with _id for stable pagination
  try {
    await db.createIndex({
      index: { fields: ["type", "profileId", "_id"] },
      name: "records-by-profile-id",
    });
  } catch (e) {
    // Index may already exist
  }

  // Index for sorting entries by sortKey (profile's sort key fields)
  try {
    await db.createIndex({
      index: { fields: ["type", "profileId", "sortKey"] },
      name: "records-by-profile-sortkey",
    });
  } catch (e) {
    // Index may already exist
  }

  // View to count entries per profile (for pagination "Page x of N")
  try {
    await db.insert({
      _id: "_design/records",
      views: {
        countByProfile: {
          map: "function(doc) {\n  if (doc.type === 'elenko_record' && doc.profileId)\n    emit(doc.profileId, 1);\n}",
          reduce: "_count",
        },
      },
    });
  } catch (e) {
    if (e.statusCode !== 409) throw e;
  }

  // Index for pending-deletions list and all-documents list
  try {
    await db.createIndex({
      index: { fields: ["type"] },
      name: "by-type",
    });
  } catch (e) {
    // Index may already exist
  }

  try {
    await db.createIndex({
      index: { fields: ["type", "_id"] },
      name: "by-type-id",
    });
  } catch (e) {
    // Index may already exist
  }

  try {
    await db.createIndex({
      index: { fields: ["type", "username"] },
      name: "users-by-username",
    });
  } catch (e) {
    // Index may already exist
  }

  // Seed admin user if none exist
  try {
    const usersResult = await db.find({
      selector: { type: "elenko_user", username: "admin" },
      limit: 1,
    });
    if (!usersResult.docs || usersResult.docs.length === 0) {
      const { hash, salt } = hashPassword("admin");
      await db.insert({
        type: "elenko_user",
        username: "admin",
        passwordHash: hash,
        salt,
        role: "admin",
      });
      console.log("Seeded admin user (username: admin, password: admin).");
    }
  } catch (e) {
    console.warn("User seed skip:", e.message);
  }

  // Optional: seed one sample profile if none exist
  try {
    const existing = await db.find({
      selector: { type: "elenko_profile" },
      limit: 1,
    });
    if (!existing.docs || existing.docs.length === 0) {
      await db.insert({
        type: "elenko_profile",
        name: "Example profile",
        description: "Sample Elenko database profile (CouchDB documents). Edit or delete in CouchDB.",
        createdAt: new Date().toISOString(),
      });
      console.log("Seeded one sample Elenko profile.");
    }
  } catch (e) {
    console.warn("Seed skip:", e.message);
  }
}

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "elenko-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

app.use(async (req, res, next) => {
  const isSetupPath = req.path === "/setup" || req.path === "/setup/change-couchdb-password";
  if (!db) {
    if (isSetupPath) return next();
    if (isBootstrapFileMissing()) {
      try {
        await initCouch({ password: "admin" });
        if (db) return next();
      } catch (_) {}
    }
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderSetupRequiredPage());
  }
  if (db && isBootstrapFileMissing()) {
    const restored = await tryRestoreBootstrapFromStoredPassword();
    if (restored) return next();
    if (!isSetupPath) return res.redirect("/setup");
  }
  next();
});

app.get("/setup", async (req, res) => {
  if (db && isBootstrapFileMissing()) {
    const restored = await tryRestoreBootstrapFromStoredPassword();
    if (restored) return res.redirect("/login");
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, null, null, "/setup/change-couchdb-password", true));
  }
  if (!db) {
    if (isBootstrapFileMissing()) {
      try {
        await initCouch({ password: "admin" });
        if (db) {
          const appUi = await getAppUiConfig();
          return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, null, null, "/setup/change-couchdb-password", true));
        }
      } catch (_) {}
    }
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderSetupRequiredPage());
  }
  return res.redirect("/login");
});

app.post("/setup", async (req, res) => {
  const password = typeof (req.body && req.body.couchdbPassword) === "string" ? req.body.couchdbPassword : "";
  if (!password.trim()) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderSetupRequiredPage("Password is required."));
  }
  try {
    writeBootstrapFile(password.trim());
    await initCouch({ password: password.trim() });
    if (!db || !configDb) {
      return res.set("Content-Type", "text/html; charset=utf-8").send(renderSetupRequiredPage("Connection failed. Check the password and that CouchDB is reachable."));
    }
    const existing = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
    const doc = existing.docs && existing.docs[0];
    if (!doc) {
      await configDb.insert({
        type: "elenko_app_config",
        theme: { ...DEFAULT_APP_THEME },
        logoUrl: "",
        logoWidth: 0,
        logoHeight: 0,
        loginTextAbove: "",
        loginTextBelow: "",
        couchdbPassword: password.trim(),
      });
    } else {
      // Do not overwrite couchdbPassword on existing doc: after a rebuild the user may
      // re-enter only to create the bootstrap file; the stored password should stay.
      if (typeof doc.couchdbPassword !== "string" || doc.couchdbPassword === "") {
        doc.couchdbPassword = password.trim();
      }
      await configDb.insert(doc);
    }
    cachedAppConfig = null;
    cachedAppConfigLoadedAt = 0;
    return res.redirect("/login");
  } catch (err) {
    console.error("Setup error:", err);
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderSetupRequiredPage(err.message || "Setup failed."));
  }
});

app.post("/setup/change-couchdb-password", async (req, res) => {
  const currentPassword = typeof (req.body && req.body.currentPassword) === "string" ? req.body.currentPassword.trim() : "";
  const newPassword = typeof (req.body && req.body.newPassword) === "string" ? req.body.newPassword.trim() : "";
  const confirmPassword = typeof (req.body && req.body.confirmPassword) === "string" ? req.body.confirmPassword.trim() : "";
  if (!db || !configDb) {
    return res.redirect("/setup");
  }
  if (!isBootstrapFileMissing()) {
    return res.redirect("/login");
  }
  if (currentPassword !== "admin") {
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, "Current password must be the default (admin).", null, "/setup/change-couchdb-password", true));
  }
  if (!newPassword || !confirmPassword) {
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, "All fields are required.", null, "/setup/change-couchdb-password", true));
  }
  if (newPassword !== confirmPassword) {
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, "New password and confirmation do not match.", null, "/setup/change-couchdb-password", true));
  }
  if (newPassword === "admin") {
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, "New password must be different from the default.", null, "/setup/change-couchdb-password", true));
  }
  try {
    await setCouchDbAdminPassword("admin", newPassword);
  } catch (e) {
    console.error("CouchDB admin password update failed:", e);
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, e.message || "Failed to update CouchDB password.", null, "/setup/change-couchdb-password", true));
  }
  try {
    writeBootstrapFile(newPassword);
  } catch (e) {
    console.error("Failed to write bootstrap file:", e);
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, "Password updated in CouchDB but failed to write bootstrap file.", null, "/setup/change-couchdb-password", true));
  }
  try {
    await initCouch({ password: newPassword });
  } catch (e) {
    console.error("Failed to reconnect with new password:", e);
    const appUi = await getAppUiConfig();
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, "Bootstrap file saved but reconnection failed: " + (e.message || "connection error"), null, "/setup/change-couchdb-password", true));
  }
  try {
    if (configDb) {
      const result = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
      const doc = result.docs && result.docs[0];
      if (doc) {
        doc.couchdbPassword = newPassword;
        await configDb.insert(doc);
      } else {
        await configDb.insert({
          type: "elenko_app_config",
          theme: { ...DEFAULT_APP_THEME },
          logoUrl: "",
          logoWidth: 0,
          logoHeight: 0,
          loginTextAbove: "",
          loginTextBelow: "",
          couchdbPassword: newPassword,
        });
      }
    }
    cachedAppConfig = null;
    cachedAppConfigLoadedAt = 0;
  } catch (e) {
    console.error("Failed to update app config with new password:", e);
  }
  return res.redirect("/login");
});

app.get("/login", async (req, res) => {
  if (req.session && req.session.user) return res.redirect("/");
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8").send(renderLoginPage(null, appUi));
});

app.post("/login", async (req, res) => {
  const appUi = await getAppUiConfig();
  const username = String((req.body && req.body.username) || "").trim();
  const password = (req.body && req.body.password) || "";
  if (!username) {
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderLoginPage("Invalid username or password.", appUi));
  }
  try {
    const result = await db.find({
      selector: { type: "elenko_user", username },
      limit: 1,
    });
    const user = result.docs && result.docs[0];
    if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
      return res
        .set("Content-Type", "text/html; charset=utf-8")
        .send(renderLoginPage("Invalid username or password.", appUi));
    }
    req.session.user = user.username;
    req.session.role = (user.role === "user" ? "editor" : user.role) || "editor";
    sendFlowMessage("auth.login", { username: user.username, role: req.session.role });
    return res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderLoginPage("Invalid username or password.", appUi));
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {});
  res.redirect("/login");
});

/** Favicon: correct Content-Type + cache; legacy redirects for old misspelled PNG URLs (404 broke Firefox tab icons). */
function servePublicAsset(relPath, contentType) {
  return (req, res) => {
    const filePath = path.join(PUBLIC_DIR, relPath);
    res.setHeader("Cache-Control", "public, max-age=86400");
    res.setHeader("Content-Type", contentType);
    res.sendFile(filePath, (err) => {
      if (err && !res.headersSent) res.status(404).end();
    });
  };
}
app.get("/favicon.ico", servePublicAsset("favicon.ico", "image/x-icon"));
app.get("/favicon-16x16.png", servePublicAsset("favicon-16x16.png", "image/png"));
app.get("/favicon-32x32.png", servePublicAsset("favicon-32x32.png", "image/png"));
app.get("/apple-touch-icon.png", servePublicAsset("apple-touch-icon.png", "image/png"));
app.get("/favicon16.png", (_req, res) => res.redirect(301, "/favicon-16x16.png"));
app.get("/favicon32.png", (_req, res) => res.redirect(301, "/favicon-32x32.png"));

app.use(express.static(path.join(__dirname, "public")));
app.use(requireAuth);

app.get("/", async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "_rev", "name", "description", "createdAt"],
      sort: [{ name: "asc" }],
    });
    const profiles = result.docs || [];
    const appUi = await getAppUiConfig();
    const role = (req.session && req.session.role) || "editor";
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderStartPage(profiles, role, appUi));
  } catch (err) {
    console.error("Error loading profiles:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/profiles", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "_rev", "name", "description", "createdAt"],
      sort: [{ name: "asc" }],
    });
    const profiles = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderProfilesListPage(profiles, appUi));
  } catch (err) {
    console.error("Error loading profiles list:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/account/change-password", async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8").send(renderChangePasswordPage(null, appUi));
});

app.post("/account/change-password", async (req, res) => {
  const appUi = await getAppUiConfig();
  const current = (req.body && req.body.currentPassword) || "";
  const newPass = (req.body && req.body.newPassword) || "";
  const confirm = (req.body && req.body.confirmPassword) || "";
  const username = req.session && req.session.user;
  if (!username) return res.redirect("/login");
  if (!newPass || newPass.length < 1) {
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderChangePasswordPage("New password is required.", appUi));
  }
  if (newPass !== confirm) {
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderChangePasswordPage("New password and confirmation do not match.", appUi));
  }
  try {
    const result = await db.find({ selector: { type: "elenko_user", username }, limit: 1 });
    const user = result.docs && result.docs[0];
    if (!user || !verifyPassword(current, user.passwordHash, user.salt)) {
      return res
        .set("Content-Type", "text/html; charset=utf-8")
        .send(renderChangePasswordPage("Current password is incorrect.", appUi));
    }
    const { hash, salt } = hashPassword(newPass);
    user.passwordHash = hash;
    user.salt = salt;
    await db.insert(user);
    res.redirect("/?password=changed");
  } catch (err) {
    console.error("Change password error:", err);
    res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderChangePasswordPage("An error occurred. Please try again.", appUi));
  }
});

app.get("/account/couchdb-password", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  const err = typeof req.query.err === "string" ? req.query.err : null;
  const ok = typeof req.query.ok === "string" ? req.query.ok : null;
  res.set("Content-Type", "text/html; charset=utf-8").send(renderCouchDbPasswordPage(appUi, err, ok));
});

app.post("/account/couchdb-password", requireAdmin, async (req, res) => {
  const currentPassword = typeof (req.body && req.body.currentPassword) === "string" ? req.body.currentPassword.trim() : "";
  const newPassword = typeof (req.body && req.body.newPassword) === "string" ? req.body.newPassword.trim() : "";
  const confirmPassword = typeof (req.body && req.body.confirmPassword) === "string" ? req.body.confirmPassword.trim() : "";
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent("All fields are required."));
  }
  if (newPassword !== confirmPassword) {
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent("New password and confirmation do not match."));
  }
  if (newPassword === currentPassword) {
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent("New password must be different from current."));
  }
  try {
    await setCouchDbAdminPassword(currentPassword, newPassword);
  } catch (e) {
    console.error("CouchDB admin password update failed:", e);
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent(e.message || "Failed to update CouchDB password."));
  }
  try {
    const testClient = nano(buildCouchUrlFromBase(newPassword));
    await testClient.db.get(COUCHDB_DB);
  } catch (e) {
    console.error("CouchDB reconnect test failed:", e);
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent("Password was set but reconnection test failed: " + (e.message || "connection error")));
  }
  try {
    writeBootstrapFile(newPassword);
  } catch (e) {
    console.error("Failed to write bootstrap file:", e);
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent("Password updated in CouchDB but failed to write bootstrap file."));
  }
  try {
    await initCouch({ password: newPassword });
  } catch (e) {
    console.error("Failed to reconnect to CouchDB with new password:", e);
    return res.redirect("/account/couchdb-password?err=" + encodeURIComponent("Password and bootstrap file saved but reconnection failed: " + (e.message || "connection error")));
  }
  try {
    if (configDb) {
      const result = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
      const doc = result.docs && result.docs[0];
      if (doc) {
        doc.couchdbPassword = newPassword;
        await configDb.insert(doc);
      }
    }
    cachedAppConfig = null;
    cachedAppConfigLoadedAt = 0;
  } catch (e) {
    console.error("Failed to update app config with new password:", e);
  }
  return res.redirect("/account/couchdb-password?ok=" + encodeURIComponent("CouchDB password updated. Bootstrap file and app config saved. You can continue using the app."));
});

app.get("/app-config", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditAppConfigPage(appUi, null));
  } catch (err) {
    console.error("Error loading app config:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/config-export-import", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "name"],
      sort: [{ name: "asc" }],
    });
    const profiles = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderConfigExportImportPage(profiles, appUi));
  } catch (err) {
    console.error("Error loading config export/import page:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/data-export-import", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "name"],
      sort: [{ name: "asc" }],
    });
    const profiles = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderDataExportImportPage(profiles, appUi));
  } catch (err) {
    console.error("Error loading data export/import page:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/profiles/:id/import-data", requireAdmin, async (req, res) => {
  const profileId = req.params.id;
  try {
    const body = req.body || {};
    const csvText = typeof body.csvText === "string" ? body.csvText : "";
    const firstRowHeaders = !!body.firstRowHeaders;
    console.log("[import-data] request", {
      profileId,
      method: req.method,
      path: req.path,
      contentType: req.get("content-type"),
      contentLength: req.get("content-length"),
      bodyKeys: body && typeof body === "object" ? Object.keys(body) : [],
      confirmUnmatchedHeaders: !!body.confirmUnmatchedHeaders,
      csvTextType: typeof body.csvText,
      csvTextLength: typeof csvText === "string" ? csvText.length : 0,
      csvTextPreview:
        typeof csvText === "string" && csvText.length > 0
          ? csvText.slice(0, 200).replace(/\r/g, "\\r").replace(/\n/g, "\\n")
          : "",
      firstRowHeaders,
      user: req.session && req.session.user,
      role: req.session && req.session.role,
    });
    if (!csvText.trim()) {
      console.warn("[import-data] rejected: empty csvText", { profileId });
      return res.status(400).json({ error: "CSV content is empty." });
    }
    let profileDoc;
    try {
      profileDoc = await db.get(profileId);
    } catch (e) {
      if (e.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
      throw e;
    }
    if (!profileDoc || profileDoc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const fieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
    if (fieldNames.length === 0) {
      return res.status(400).json({ error: "This profile has no field names defined." });
    }

    const rows = parseSemicolonCsvText(csvText);
    if (rows.length === 0) {
      return res.status(400).json({ error: "No rows found in the CSV file." });
    }

    const confirmUnmatchedHeaders = !!body.confirmUnmatchedHeaders;

    let dataRows;
    let colToField = null;
    if (firstRowHeaders) {
      const headerRow = rows[0];
      const fnByLower = new Map(fieldNames.map((fn) => [String(fn).trim().toLowerCase(), fn]));
      colToField = new Map();
      headerRow.forEach((cell, colIdx) => {
        const key = String(cell).trim().toLowerCase();
        if (fnByLower.has(key)) colToField.set(colIdx, fnByLower.get(key));
      });
      if (colToField.size === 0) {
        return res.status(400).json({
          error:
            "No column in the first row matched a profile field name. Fix headers or turn off the header-matching option.",
        });
      }
      if (!confirmUnmatchedHeaders) {
        const seenUnmatched = new Set();
        const unmatchedHeaders = [];
        for (const cell of headerRow) {
          const raw = String(cell).trim();
          if (!raw) continue;
          const lk = raw.toLowerCase();
          if (fnByLower.has(lk)) continue;
          if (seenUnmatched.has(lk)) continue;
          seenUnmatched.add(lk);
          unmatchedHeaders.push(raw);
        }
        if (unmatchedHeaders.length > 0) {
          console.log("[import-data] confirmation required (CSV headers not in profile)", {
            profileId,
            unmatchedHeaders,
            matchedColumnCount: colToField.size,
            profileFieldCount: fieldNames.length,
          });
          return res.json({
            ok: false,
            needUnmatchedHeadersConfirm: true,
            unmatchedHeaders,
            matchedColumnCount: colToField.size,
          });
        }
      }
      dataRows = rows.slice(1);
    } else {
      dataRows = rows;
    }

    const nonEmptyDataRows = dataRows.filter((row) => !csvDataRowIsEmpty(row));
    if (nonEmptyDataRows.length > MAX_CSV_IMPORT_ROWS) {
      return res.status(400).json({ error: `Too many data rows (max ${MAX_CSV_IMPORT_ROWS}).` });
    }

    const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
    const profileFormIds = getProfileEntryFormIds(profileDoc);
    const defaultFormId = profileFormIds.length > 0 ? profileFormIds[0] : "";
    const now = new Date().toISOString();
    let imported = 0;
    const errors = [];

    for (let r = 0; r < dataRows.length; r++) {
      const row = dataRows[r];
      const lineNo = firstRowHeaders ? r + 2 : r + 1;
      if (csvDataRowIsEmpty(row)) continue;
      try {
        const record = { type: "elenko_record", profileId };
        if (defaultFormId) record.entryFormId = defaultFormId;
        if (firstRowHeaders && colToField) {
          for (const fn of fieldNames) {
            record[fn] = "";
          }
          for (const [colIdx, fn] of colToField) {
            const cell = row[colIdx];
            record[fn] = cell != null ? String(cell) : "";
          }
        } else {
          for (let i = 0; i < fieldNames.length; i++) {
            record[fieldNames[i]] = row[i] != null ? String(row[i]) : "";
          }
        }
        record.createdAt = now;
        record.updatedAt = now;
        record.sortKey = buildSortKey(record, sortKeyFields);
        await db.insert(record);
        imported++;
      } catch (e) {
        const msg = e && e.message ? String(e.message) : String(e);
        if (errors.length < 50) {
          errors.push({ row: lineNo, message: msg });
        }
      }
    }

    clearProfileListCache(profileId);
    console.log("[import-data] success", {
      profileId,
      imported,
      failed: errors.length,
      rowErrorSample: errors.slice(0, 3),
    });
    res.json({
      ok: true,
      imported,
      failed: errors.length,
      rowErrors: errors.slice(0, 50),
    });
  } catch (err) {
    console.error("[import-data] error", {
      profileId,
      message: err && err.message,
      name: err && err.name,
      code: err && err.code,
      statusCode: err && err.statusCode,
      stack: err && err.stack,
      contentType: req.get("content-type"),
      contentLength: req.get("content-length"),
    });
    res.status(500).json({ error: err.message || "Import failed" });
  }
});

app.post("/api/config-export", requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const scope = body.scope === "all" ? "all" : "profile";
    const profileId = scope === "profile" && typeof body.profileId === "string" ? body.profileId.trim() : null;
    if (scope === "profile" && !profileId) {
      return res.status(400).json({ error: "Select an Elenko database for export." });
    }
    const data = await buildConfigExport(scope, profileId);
    res.json({ ok: true, data });
  } catch (err) {
    console.error("Config export error:", err);
    res.status(500).json({ error: err.message || "Export failed" });
  }
});

app.post("/api/config-import", requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const data = body.data;
    if (!data || typeof data !== "object") {
      return res.status(400).json({ error: "Invalid import: missing data. Upload an export JSON file." });
    }
    if (data.version !== CONFIG_EXPORT_VERSION || !data.documents) {
      return res.status(400).json({ error: "Invalid export format. Use a file exported from this Export / Import configuration page." });
    }
    const result = await applyConfigImport(data, true);
    res.json(result);
  } catch (err) {
    console.error("Config import error:", err);
    res.status(500).json({ ok: false, error: err.message || "Import failed" });
  }
});

app.post("/api/config-backup", requireAdmin, async (req, res) => {
  try {
    const data = await buildConfigExport("all", null);
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    const h = String(now.getHours()).padStart(2, "0");
    const min = String(now.getMinutes()).padStart(2, "0");
    const s = String(now.getSeconds()).padStart(2, "0");
    const timestamp = `${y}${m}${d}-${h}${min}${s}`;
    const filename = `elenko-config-backup-${timestamp}.json`;
    await fs.promises.mkdir(CONFIG_BACKUPS_DIR, { recursive: true });
    const filePath = path.join(CONFIG_BACKUPS_DIR, filename);
    await fs.promises.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
    res.json({ ok: true, filename, url: "/backups/" + filename });
  } catch (err) {
    console.error("Config backup error:", err);
    res.status(500).json({ error: err.message || "Backup failed" });
  }
});

app.get("/api/config-backups", requireAdmin, async (req, res) => {
  try {
    await fs.promises.mkdir(CONFIG_BACKUPS_DIR, { recursive: true });
    const entries = await fs.promises.readdir(CONFIG_BACKUPS_DIR, { withFileTypes: true });
    const backups = entries
      .filter((e) => e.isFile() && e.name.startsWith("elenko-config-backup-") && e.name.endsWith(".json"))
      .map((e) => ({ name: e.name, url: "/backups/" + e.name }))
      .sort((a, b) => b.name.localeCompare(a.name));
    res.json({ backups });
  } catch (err) {
    console.error("Config backups list error:", err);
    res.status(500).json({ error: err.message || "Failed to list backups" });
  }
});

app.post("/api/app-config", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const body = req.body || {};
    const theme = normalizeAppTheme(body.theme || {});
    const logoUrl = typeof body.logoUrl === "string" ? body.logoUrl.trim() : "";
    const logoWidth = Number(body.logoWidth) || 0;
    const logoHeight = Number(body.logoHeight) || 0;
    const loginTextAbove = typeof body.loginTextAbove === "string" ? body.loginTextAbove.trim() : "";
    const loginTextBelow = typeof body.loginTextBelow === "string" ? body.loginTextBelow.trim() : "";
    let doc = null;
    const id = typeof body._id === "string" && body._id.trim() ? body._id.trim() : "";
    if (id) {
      try {
        const existing = await configDb.get(id);
        if (existing && existing.type === "elenko_app_config") doc = existing;
      } catch (_) {}
    }
    if (!doc) {
      const result = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
      doc = result.docs && result.docs[0];
    }
    if (!doc || doc.type !== "elenko_app_config") {
      doc = { type: "elenko_app_config" };
    }
    doc.theme = theme;
    doc.logoUrl = logoUrl;
    doc.logoWidth = logoWidth;
    doc.logoHeight = logoHeight;
    doc.loginTextAbove = loginTextAbove;
    doc.loginTextBelow = loginTextBelow;
    const result = await configDb.insert(doc);
    cachedAppConfig = null;
    cachedAppConfigLoadedAt = 0;
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error saving app config:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/account/users/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  const created = req.query.created === "1";
  res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage(null, created, appUi));
});

app.post("/account/users/create", requireAdmin, async (req, res) => {
  const username = String((req.body && req.body.username) || "").trim();
  const password = (req.body && req.body.password) || "";
  const roleRaw = (req.body && req.body.role) || "editor";
    const role = roleRaw === "admin" || roleRaw === "reader" ? roleRaw : "editor";
  const appUi = await getAppUiConfig();
  if (!username) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("Username is required.", false, appUi));
  }
  if (password.length < 1) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("Password is required.", false, appUi));
  }
  try {
    const existing = await db.find({ selector: { type: "elenko_user", username }, limit: 1 });
    if (existing.docs && existing.docs.length > 0) {
      return res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("Username already exists.", false, appUi));
    }
    const { hash, salt } = hashPassword(password);
    await db.insert({
      type: "elenko_user",
      username,
      passwordHash: hash,
      salt,
      role,
    });
    res.redirect("/account/users/create?created=1");
  } catch (err) {
    console.error("Create user error:", err);
    res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("An error occurred. Please try again.", false, appUi));
  }
});

app.get("/account/users", requireAdmin, async (req, res) => {
  try {
    const appUi = await getAppUiConfig();
    const result = await db.find({
      selector: { type: "elenko_user" },
      fields: ["_id", "_rev", "username", "role"],
      sort: [{ username: "asc" }],
    });
    const users = result.docs || [];
    res.set("Content-Type", "text/html; charset=utf-8").send(renderManageUsersPage(users, req.session && req.session.user, appUi));
  } catch (err) {
    console.error("Error loading users:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.put("/api/account/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_user") {
      return res.status(404).json({ error: "User not found" });
    }
    const roleRaw = req.body && req.body.role;
    const newPassword = req.body && req.body.newPassword;
    if (roleRaw !== undefined) {
      doc.role = roleRaw === "admin" || roleRaw === "reader" ? roleRaw : "editor";
    }
    if (typeof newPassword === "string" && newPassword.length > 0) {
      const { hash, salt } = hashPassword(newPassword);
      doc.passwordHash = hash;
      doc.salt = salt;
    }
    await db.insert(doc);
    res.json({ ok: true });
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ error: err.message || "Update failed" });
  }
});

app.delete("/api/account/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_user") {
      return res.status(404).json({ error: "User not found" });
    }
    const currentUsername = req.session && req.session.user;
    if (doc.username === currentUsername) {
      return res.status(400).json({ error: "Cannot delete your own account" });
    }
    await db.destroy(id, doc._rev);
    res.json({ ok: true });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: err.message || "Delete failed" });
  }
});

app.get("/api/profiles", async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "_rev", "name", "description", "createdAt"],
      sort: [{ name: "asc" }],
    });
    res.json({ profiles: result.docs || [] });
  } catch (err) {
    console.error("Error loading profiles:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/documents", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: { $in: ["elenko_profile", "elenko_record", "elenko_pending_deletions", "elenko_entry_form"] } },
      sort: [{ type: "asc" }, { _id: "asc" }],
      limit: MAX_ENTRIES_PER_PROFILE * 2,
    });
    const docs = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderAllDocumentsPage(docs, appUi));
  } catch (err) {
    console.error("Error loading documents:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/documents/delete", requireAdmin, async (req, res) => {
  try {
    const items = req.body?.items;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Missing or empty items array" });
    }
    let deleted = 0;
    for (const it of items) {
      const id = it?.id;
      const rev = it?.rev;
      if (!id || !rev) continue;
      try {
        await db.destroy(id, rev);
        deleted++;
      } catch (err) {
        if (err?.statusCode !== 404) throw err;
      }
    }
    res.json({ ok: true, deleted });
  } catch (err) {
    console.error("Error deleting documents:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/entry-forms", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_entry_form" },
      fields: ["_id", "name"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    res.json({ forms: result.docs || [] });
  } catch (err) {
    console.error("Error loading entry forms:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/entry-forms", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_entry_form" },
      fields: ["_id", "name"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    const forms = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEntryFormsListPage(forms, appUi));
  } catch (err) {
    console.error("Error loading entry forms:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/entry-forms/create", requireAdmin, async (req, res) => {
  try {
    const appUi = await getAppUiConfig();
    let flows = [];
    if (configDb) {
      try {
        const result = await configDb.find({ selector: { type: "elenko_flow" }, fields: ["_id", "name"], sort: [{ name: "asc" }], limit: 500 });
        flows = result.docs || [];
      } catch (_) {}
    }
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderCreateEntryFormPage(null, flows, appUi));
  } catch (err) {
    console.error("Error loading create form page:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/entry-forms/css-help", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderEntryFormCssHelpPage(appUi));
});

app.post("/api/entry-forms", requireAdmin, async (req, res) => {
  try {
    const normalized = normalizeEntryFormDoc(req.body || {});
    if (!normalized.name) {
      return res.status(400).json({ error: "Name is required." });
    }
    const flowConfigsRaw = Array.isArray(req.body.flowConfigs) ? req.body.flowConfigs : [];
    for (let i = 0; i < flowConfigsRaw.length; i++) {
      const c = flowConfigsRaw[i];
      const flowId = (c && typeof c.flowId === "string") ? c.flowId.trim() : "";
      const target = (c && typeof c.target === "string") ? c.target.trim() : "";
      if (!flowId && target !== "log" && target !== "localDb" && target !== "api") {
        return res.status(400).json({ error: "When using Single step, please select a Target (Log file, Send to Local Database, or Call API) for each flow button." });
      }
    }
    const doc = {
      type: "elenko_entry_form",
      name: normalized.name,
      labels: normalized.labels,
      theme: normalized.theme,
      layout: normalized.layout,
      fieldLayout: normalized.fieldLayout,
      customCss: normalized.customCss,
      flowButtonEnabled: normalized.flowButtonEnabled,
      flowTarget: normalized.flowTarget,
      flowButtonLabel: normalized.flowButtonLabel,
      flowButtonParam: normalized.flowButtonParam,
      flowConfigs: normalized.flowConfigs,
    };
    const result = await db.insert(doc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating entry form:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/entry-forms/:id/edit", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_entry_form") {
      return res.status(404).send(renderErrorPage("Entry form not found"));
    }
    let flows = [];
    if (configDb) {
      try {
        const result = await configDb.find({ selector: { type: "elenko_flow" }, fields: ["_id", "name"], sort: [{ name: "asc" }], limit: 500 });
        flows = result.docs || [];
      } catch (_) {}
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditEntryFormPage(doc, null, flows, appUi));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Entry form not found"));
    console.error("Error loading entry form:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.put("/api/entry-forms/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_entry_form") {
      return res.status(404).json({ error: "Entry form not found" });
    }
    const flowConfigsRaw = Array.isArray(req.body.flowConfigs) ? req.body.flowConfigs : [];
    for (let i = 0; i < flowConfigsRaw.length; i++) {
      const c = flowConfigsRaw[i];
      const flowId = (c && typeof c.flowId === "string") ? c.flowId.trim() : "";
      const target = (c && typeof c.target === "string") ? c.target.trim() : "";
      if (!flowId && target !== "log" && target !== "localDb" && target !== "api") {
        return res.status(400).json({ error: "When using Single step, please select a Target (Log file, Send to Local Database, or Call API) for each flow button." });
      }
    }
    const normalized = normalizeEntryFormDoc(req.body || {});
    if (!normalized.name) {
      return res.status(400).json({ error: "Name is required." });
    }
    doc.name = normalized.name;
    doc.labels = normalized.labels;
    doc.theme = normalized.theme;
    doc.layout = normalized.layout;
    doc.fieldLayout = normalized.fieldLayout;
    doc.customCss = normalized.customCss;
    doc.flowButtonEnabled = normalized.flowButtonEnabled;
    doc.flowTarget = normalized.flowTarget;
    doc.flowButtonLabel = normalized.flowButtonLabel;
    doc.flowButtonParam = normalized.flowButtonParam;
    doc.flowConfigs = normalized.flowConfigs;
    const result = await db.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry form not found" });
    console.error("Error updating entry form:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/entry-forms/:id/delete", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_entry_form") {
      return res.status(404).send(renderErrorPage("Entry form not found"));
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderDeleteEntryFormPage(doc, appUi));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Entry form not found"));
    console.error("Error loading entry form for delete:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/entry-forms/:id/delete", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { _rev } = req.body || {};
    if (!_rev) return res.status(400).json({ error: "Missing _rev" });
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_entry_form") {
      return res.status(404).json({ error: "Entry form not found" });
    }
    if (doc._rev !== _rev) {
      return res.status(409).json({ error: "Entry form was modified; refresh and try again" });
    }
    await db.destroy(id, _rev);
    res.json({ ok: true, redirect: "/entry-forms" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry form not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict" });
    console.error("Error deleting entry form:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/entry-forms/:id/copy", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    let baseForm;
    try {
      baseForm = await db.get(id);
    } catch (e) {
      if (e.statusCode === 404) return res.status(404).json({ error: "Entry form not found" });
      throw e;
    }
    if (!baseForm || baseForm.type !== "elenko_entry_form") {
      return res.status(404).json({ error: "Entry form not found" });
    }
    const nameResult = await db.find({
      selector: { type: "elenko_entry_form" },
      fields: ["name"],
      limit: 5000,
    });
    const existing = new Set();
    for (const d of nameResult.docs || []) {
      if (d && typeof d.name === "string" && d.name.trim()) existing.add(d.name.trim());
    }
    const newName = makeUniqueEntryFormCopyName(baseForm.name, existing);
    const newFormDoc = buildEntryFormDocFromSource(baseForm, newName);
    const formResult = await db.insert(newFormDoc);
    res.status(201).json({ ok: true, id: formResult.id, rev: formResult.rev, name: newName });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry form not found" });
    console.error("Error copying entry form:", err);
    res.status(500).json({ error: err.message || "Copy failed" });
  }
});

app.get("/api/apis", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const result = await configDb.find({
      selector: { type: "elenko_api" },
      fields: ["_id", "_rev", "name", "description", "url", "method"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    res.json({ apis: result.docs || [] });
  } catch (err) {
    console.error("Error loading APIs:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/apis", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const result = await configDb.find({
      selector: { type: "elenko_api" },
      fields: ["_id", "_rev", "name", "description", "url", "method"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    const apis = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderApisListPage(apis, appUi));
  } catch (err) {
    console.error("Error loading APIs:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

function getQueryApiKeyRef(req) {
  const v = req.query && req.query.apiKeyRef;
  if (typeof v === "string") return v.trim();
  if (Array.isArray(v) && typeof v[0] === "string") return v[0].trim();
  return "";
}

app.get("/apis/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  const prefillKeyRef = getQueryApiKeyRef(req);
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderEditApiPage(null, null, req.originalUrl || "/apis/create", appUi, prefillKeyRef));
});

app.get("/apis/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const doc = await configDb.get(req.params.id);
    if (!doc || doc.type !== "elenko_api") {
      return res.status(404).send(renderErrorPage("API not found"));
    }
    const qRef = getQueryApiKeyRef(req);
    // After Create/Update API key, browser returns here with ?apiKeyRef=key_... — persist to CouchDB
    // (export strips apiKeyRef; slug sync in the form is UI-only until Save unless we save here).
    if (qRef) {
      doc.apiKeyRef = qRef;
      await configDb.insert(doc);
      return res.redirect(303, "/apis/" + encodeURIComponent(req.params.id) + "/edit");
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditApiPage(doc, null, "/apis/" + encodeURIComponent(req.params.id) + "/edit", appUi, ""));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("API not found"));
    console.error("Error loading API:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/apis", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const doc = {
      type: "elenko_api",
      name,
      description: typeof body.description === "string" ? body.description.trim() : "",
      url: typeof body.url === "string" ? body.url.trim() : "",
      method: (body.method === "POST" || body.method === "PUT" || body.method === "PATCH") ? body.method : "GET",
      apiKeyRef: typeof body.apiKeyRef === "string" ? body.apiKeyRef.trim() : "",
      responseTarget: body.responseTarget === "create" ? "create" : body.responseTarget === "forward" ? "forward" : "update",
      template: typeof body.template === "string" ? body.template.trim() : "",
      responseField: typeof body.responseField === "string" ? body.responseField.trim() : "",
      responseStart: typeof body.responseStart === "string" ? body.responseStart : "",
      responseEnd: typeof body.responseEnd === "string" ? body.responseEnd : "",
    };
    const result = await configDb.insert(doc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating API:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/apis/:id", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_api") {
      return res.status(404).json({ error: "API not found" });
    }
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    doc.name = name;
    doc.description = typeof body.description === "string" ? body.description.trim() : "";
    doc.url = typeof body.url === "string" ? body.url.trim() : "";
    doc.method = (body.method === "POST" || body.method === "PUT" || body.method === "PATCH") ? body.method : "GET";
    doc.apiKeyRef = typeof body.apiKeyRef === "string" ? body.apiKeyRef.trim() : "";
    doc.responseTarget = body.responseTarget === "create" ? "create" : body.responseTarget === "forward" ? "forward" : "update";
    doc.template = typeof body.template === "string" ? body.template.trim() : "";
    doc.responseField = typeof body.responseField === "string" ? body.responseField.trim() : "";
    doc.responseStart = typeof body.responseStart === "string" ? body.responseStart : "";
    doc.responseEnd = typeof body.responseEnd === "string" ? body.responseEnd : "";
    const result = await configDb.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "API not found" });
    console.error("Error updating API:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/apis/:id/copy", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_api") {
      return res.status(404).json({ error: "API not found" });
    }
    const nameResult = await configDb.find({
      selector: { type: "elenko_api" },
      fields: ["name"],
      limit: 5000,
    });
    const existing = new Set();
    for (const d of nameResult.docs || []) {
      if (d && typeof d.name === "string" && d.name.trim()) existing.add(d.name.trim());
    }
    const newName = makeUniqueApiCopyName(doc.name, existing);
    const newDoc = buildApiDocFromSource(doc, newName);
    const result = await configDb.insert(newDoc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev, name: newName });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "API not found" });
    console.error("Error copying API:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/apis/:id/delete", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const { _rev } = req.body || {};
    if (!_rev) return res.status(400).json({ error: "Missing _rev" });
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_api") {
      return res.status(404).json({ error: "API not found" });
    }
    if (doc._rev !== _rev) {
      return res.status(409).json({ error: "API was modified; refresh and try again" });
    }
    await configDb.destroy(id, _rev);
    res.json({ ok: true, redirect: "/apis" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "API not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict" });
    console.error("Error deleting API:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/apis/keys/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8");
  const defaultName = typeof req.query.defaultName === "string" ? req.query.defaultName.trim() : "";
  const defaultApiKeyDocId =
    typeof req.query.apiKeyDocId === "string" && req.query.apiKeyDocId.trim()
      ? req.query.apiKeyDocId.trim()
      : "";
  res.send(renderEditApiKeyPage(null, null, req.query.returnTo, defaultName, appUi, defaultApiKeyDocId));
});

app.post("/api/apis/keys", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const name = typeof (req.body && req.body.name) === "string" ? req.body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const apiKeyDocIdRaw = typeof (req.body && req.body.apiKeyDocId) === "string" ? req.body.apiKeyDocId : "";
    const apiKeyDocId = apiKeyDocIdRaw != null ? String(apiKeyDocIdRaw).trim() : "";
    const key = typeof (req.body && req.body.key) === "string" ? req.body.key : "";
    const id = apiKeyDocId || slugifyForApiKeyId(name);
    let doc = { type: "elenko_api_key", name, key };
    try {
      const existing = await configDb.get(id);
      doc._id = existing._id;
      doc._rev = existing._rev;
      if (key !== "") doc.key = key;
      else if (existing.key != null) doc.key = existing.key;
    } catch (e) {
      if (e.statusCode !== 404) throw e;
      doc._id = id;
    }
    const result = await configDb.insert(doc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating/updating API key:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/apis/keys/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const doc = await configDb.get(req.params.id);
    const hasKey = doc && (doc.key != null || doc.value != null);
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditApiKeyPage(doc, null, req.query.returnTo, "", appUi, ""));
  } catch (err) {
    if (err?.statusCode === 404) {
      // If key doc does not exist yet, open the create/upsert page with prefilled id.
      const qs = new URLSearchParams();
      if (typeof req.query.returnTo === "string" && req.query.returnTo.trim()) qs.set("returnTo", req.query.returnTo.trim());
      qs.set("apiKeyDocId", req.params.id);
      return res.redirect("/apis/keys/create?" + qs.toString());
    }
    console.error("Error loading API key:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.put("/api/apis/keys/:id", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const doc = await configDb.get(id);
    const name = typeof (req.body && req.body.name) === "string" ? req.body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const keyRaw = req.body && req.body.key;
    doc.name = name;
    if (typeof keyRaw === "string" && keyRaw !== "") doc.key = keyRaw;
    else if (doc.key == null && doc.value != null) doc.key = doc.value;
    const result = await configDb.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "API key not found" });
    console.error("Error updating API key:", err);
    res.status(500).json({ error: err.message });
  }
});

// —— Flows (multi-step pipeline) ——
app.get("/api/flows", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const result = await configDb.find({
      selector: { type: "elenko_flow" },
      fields: ["_id", "_rev", "name", "description", "steps"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    res.json({ flows: result.docs || [] });
  } catch (err) {
    console.error("Error loading flows:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/flows", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const result = await configDb.find({
      selector: { type: "elenko_flow" },
      fields: ["_id", "_rev", "name", "description", "steps"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    const flows = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderFlowsListPage(flows, appUi));
  } catch (err) {
    console.error("Error loading flows:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/flows/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderEditFlowPage(null, null, appUi));
});

app.get("/flows/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const doc = await configDb.get(req.params.id);
    if (!doc || doc.type !== "elenko_flow") {
      return res.status(404).send(renderErrorPage("Flow not found"));
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditFlowPage(doc, null, appUi));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Flow not found"));
    console.error("Error loading flow:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/flows", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const steps = normalizeFlowSteps(body.steps);
    const doc = {
      type: "elenko_flow",
      name,
      description: typeof body.description === "string" ? body.description.trim() : "",
      steps,
    };
    const result = await configDb.insert(doc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating flow:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/flows/:id", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_flow") {
      return res.status(404).json({ error: "Flow not found" });
    }
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    doc.name = name;
    doc.description = typeof body.description === "string" ? body.description.trim() : "";
    doc.steps = normalizeFlowSteps(body.steps);
    const result = await configDb.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Flow not found" });
    console.error("Error updating flow:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/flows/:id/copy", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    let baseFlow;
    try {
      baseFlow = await configDb.get(id);
    } catch (e) {
      if (e.statusCode === 404) return res.status(404).json({ error: "Flow not found" });
      throw e;
    }
    if (!baseFlow || baseFlow.type !== "elenko_flow") {
      return res.status(404).json({ error: "Flow not found" });
    }
    const nameResult = await configDb.find({
      selector: { type: "elenko_flow" },
      fields: ["name"],
      limit: 5000,
    });
    const existing = new Set();
    for (const d of nameResult.docs || []) {
      if (d && typeof d.name === "string" && d.name.trim()) existing.add(d.name.trim());
    }
    const newName = makeUniqueFlowCopyName(baseFlow.name, existing);
    const newDoc = buildFlowDocFromSource(baseFlow, newName);
    const result = await configDb.insert(newDoc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev, name: newName });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Flow not found" });
    console.error("Error copying flow:", err);
    res.status(500).json({ error: err.message || "Copy failed" });
  }
});

app.post("/api/flows/:id/delete", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const { _rev } = req.body || {};
    if (!_rev) return res.status(400).json({ error: "Missing _rev" });
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_flow") {
      return res.status(404).json({ error: "Flow not found" });
    }
    if (doc._rev !== _rev) {
      return res.status(409).json({ error: "Flow was modified; refresh and try again" });
    }
    await configDb.destroy(id, _rev);
    res.json({ ok: true, redirect: "/flows" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Flow not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict" });
    console.error("Error deleting flow:", err);
    res.status(500).json({ error: err.message });
  }
});

// —— JS Processing (admin-only; hash protects script when non-admin runs flow) ——
app.get("/api/js-processing", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const result = await configDb.find({
      selector: { type: "elenko_js_processing" },
      fields: ["_id", "_rev", "name", "description", "timeout"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    res.json({ list: result.docs || [] });
  } catch (err) {
    console.error("Error loading JS Processing:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/js-processing", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const result = await configDb.find({
      selector: { type: "elenko_js_processing" },
      fields: ["_id", "_rev", "name", "description", "timeout"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    const list = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderJsProcessingListPage(list, appUi));
  } catch (err) {
    console.error("Error loading JS Processing:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/js-processing/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderEditJsProcessingPage(null, null, appUi));
});

app.get("/js-processing/help", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderJsProcessingHelpPage(appUi));
});

app.get("/js-processing/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const doc = await configDb.get(req.params.id);
    if (!doc || doc.type !== "elenko_js_processing") {
      return res.status(404).send(renderErrorPage("JS Processing document not found"));
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditJsProcessingPage(doc, null, appUi));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("JS Processing document not found"));
    console.error("Error loading JS Processing:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/js-processing", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const script = typeof body.script === "string" ? body.script : "";
    const timeout = Math.min(Math.max(Number(body.timeout) || 5000, 100), 60000);
    const doc = {
      type: "elenko_js_processing",
      name,
      description: typeof body.description === "string" ? body.description.trim() : "",
      script,
      timeout,
      hash: computeScriptHash(script),
    };
    const result = await configDb.insert(doc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating JS Processing:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/js-processing/:id", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_js_processing") {
      return res.status(404).json({ error: "JS Processing document not found" });
    }
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const script = typeof body.script === "string" ? body.script : "";
    doc.name = name;
    doc.description = typeof body.description === "string" ? body.description.trim() : "";
    doc.script = script;
    doc.timeout = Math.min(Math.max(Number(body.timeout) || 5000, 100), 60000);
    doc.hash = computeScriptHash(script);
    const result = await configDb.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "JS Processing document not found" });
    console.error("Error updating JS Processing:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/js-processing/:id/copy", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    let baseDoc;
    try {
      baseDoc = await configDb.get(id);
    } catch (e) {
      if (e.statusCode === 404) return res.status(404).json({ error: "JS Processing document not found" });
      throw e;
    }
    if (!baseDoc || baseDoc.type !== "elenko_js_processing") {
      return res.status(404).json({ error: "JS Processing document not found" });
    }
    const nameResult = await configDb.find({
      selector: { type: "elenko_js_processing" },
      fields: ["name"],
      limit: 5000,
    });
    const existing = new Set();
    for (const d of nameResult.docs || []) {
      if (d && typeof d.name === "string" && d.name.trim()) existing.add(d.name.trim());
    }
    const newName = makeUniqueJsProcessingCopyName(baseDoc.name, existing);
    const newDoc = buildJsProcessingDocFromSource(baseDoc, newName);
    const result = await configDb.insert(newDoc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev, name: newName });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "JS Processing document not found" });
    console.error("Error copying JS Processing:", err);
    res.status(500).json({ error: err.message || "Copy failed" });
  }
});

app.post("/api/js-processing/:id/delete", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const { _rev } = req.body || {};
    if (!_rev) return res.status(400).json({ error: "Missing _rev" });
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_js_processing") {
      return res.status(404).json({ error: "JS Processing document not found" });
    }
    if (doc._rev !== _rev) {
      return res.status(409).json({ error: "JS Processing was modified; refresh and try again" });
    }
    await configDb.destroy(id, _rev);
    res.json({ ok: true, redirect: "/js-processing" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "JS Processing document not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict" });
    console.error("Error deleting JS Processing:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/profile/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderCreateProfilePage(appUi));
});

app.post("/api/profiles", requireAdmin, async (req, res) => {
  try {
    const { name, description, fieldNames, fieldDefaultSources, fieldDisplay, customCss, listFields: rawListFields } = req.body || {};
    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Name is required" });
    }
    const fields = Array.isArray(fieldNames)
      ? fieldNames.filter((f) => typeof f === "string" && f.trim()).map((f) => f.trim())
      : [];
    const listFields =
      Array.isArray(rawListFields)
        ? rawListFields
            .filter((f) => typeof f === "string" && f.trim())
            .map((f) => f.trim())
            .filter((f) => fields.includes(f))
            .slice(0, 3)
        : fields.slice(0, 3);
    const doc = {
      type: "elenko_profile",
      name: name.trim(),
      description: description != null ? String(description).trim() : "",
      customCss: customCss != null ? String(customCss) : "",
      fieldNames: fields,
      fieldDefaultSources: normalizeFieldDefaultSources(fields, fieldDefaultSources),
      fieldDisplay: normalizeFieldDisplay(fields, fieldDisplay),
      listFields,
      createdAt: new Date().toISOString(),
    };
    const result = await db.insert(doc);
    sendFlowMessage("profile.created", { id: result.id, name: doc.name });
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating profile:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/io-config-files", requireAdmin, async (req, res) => {
  try {
    const entries = await fs.promises.readdir(IO_DIR, { withFileTypes: true });
    const files = entries.filter((e) => e.isFile() && e.name.toLowerCase().endsWith(".eld")).map((e) => e.name);
    files.sort();
    res.json({ files });
  } catch (err) {
    if (err.code === "ENOENT") {
      return res.json({ files: [] });
    }
    console.error("Error reading io directory:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/import-profile", requireAdmin, async (req, res) => {
  try {
    const { configFile } = req.body || {};
    const cfgName = (configFile || "").trim();
    if (!cfgName) {
      return res.status(400).json({ error: "Config file name is required." });
    }
    const safeName = path.basename(cfgName);
    const cfgPath = path.join(IO_DIR, safeName);
    if (!fs.existsSync(cfgPath)) {
      return res.status(400).json({ error: `Config file not found in /io: ${safeName}` });
    }
    const rawCfg = await fs.promises.readFile(cfgPath, "utf8");
    const lines = rawCfg.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
    if (lines.length < 3) {
      return res.status(400).json({ error: "Config file must contain at least data file, charset, and one field line." });
    }
    const dataFileName = lines[0];
    const charset = lines[1] || "UTF-8";
    const fieldNames = [];
    const fieldLengths = [];
    for (let i = 2; i < lines.length; i++) {
      const line = lines[i];
      const parts = line.split(/[;\s]+/).filter(Boolean);
      if (parts.length < 2) continue;
      const name = (parts[0] || "").replace(/["]/g, "").replace(/,/g, "").trim();
      const len = parseInt(parts[1], 10);
      if (!name || !Number.isFinite(len) || len <= 0) continue;
      fieldNames.push(name);
      fieldLengths.push(len);
    }
    if (fieldNames.length === 0) {
      return res.status(400).json({ error: "No valid field definitions found in config file." });
    }
    const totalLen = fieldLengths.reduce((a, b) => a + b, 0);

    const dataPath = path.join(IO_DIR, path.basename(dataFileName));
    if (!fs.existsSync(dataPath)) {
      return res.status(400).json({ error: `Data file not found in /io: ${dataFileName}` });
    }

    // Map config charset to iconv-lite encoding (fixes umlauts e.g. Pöntinen)
    const charsetNorm = (charset || "").trim().toLowerCase();
    const iconvEncoding =
      /^utf-?8$/i.test(charsetNorm) ? "utf8"
      : /^(iso-?8859-?1|latin-?1)$/i.test(charsetNorm) ? "iso-8859-1"
      : /^(windows-?1252|cp-?1252|win1252)$/i.test(charsetNorm) ? "win1252"
      : iconv.encodingExists(charsetNorm) ? charsetNorm
      : "utf8";
    const dataBuffer = await fs.promises.readFile(dataPath);
    let rawData = iconv.decode(dataBuffer, iconvEncoding);
    if (rawData.charCodeAt(0) === 0xFEFF) rawData = rawData.slice(1);
    const dataLines = rawData.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");

    // Create profile document
    const profileName = path.basename(safeName, path.extname(safeName));
    const profileDoc = {
      type: "elenko_profile",
      name: profileName,
      description: `Imported from ${safeName} (data: ${dataFileName}, charset: ${charset})`,
      customCss: "",
      fieldNames,
      importConfigFile: safeName,
      importDataFile: dataFileName,
      importCharset: charset,
      importFieldLengths: fieldLengths,
      createdAt: new Date().toISOString(),
    };
    const profileResult = await db.insert(profileDoc);
    const profileId = profileResult.id;

    // Build entry documents
    const docs = [];
    for (const line of dataLines) {
      const row = line.replace(/\r$/, "").trimEnd();
      if (!row) continue;
      const dataRow = row.endsWith("*") ? row.slice(0, -1) : row;
      if (dataRow.length < totalLen) continue;
      const rowSlice = dataRow.slice(0, totalLen);
      let offset = 0;
      const entry = { type: "elenko_record", profileId };
      for (let i = 0; i < fieldNames.length; i++) {
        const len = fieldLengths[i];
        const part = rowSlice.slice(offset, offset + len);
        offset += len;
        entry[fieldNames[i]] = part.trim();
      }
      const now = new Date().toISOString();
      entry.createdAt = now;
      entry.updatedAt = now;
      const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
      entry.sortKey = buildSortKey(entry, sortKeyFields);
      const profileFormIds = getProfileEntryFormIds(profileDoc);
      if (profileFormIds.length > 0) {
        entry.entryFormId = profileFormIds[0];
      }
      docs.push(entry);
      sendFlowMessage("profile.import.line", {
        profileId,
        lineNumber: docs.length,
        firstField: fieldNames[0] ? entry[fieldNames[0]] : "",
      });
    }

    const BULK_BATCH = 500;
    for (let i = 0; i < docs.length; i += BULK_BATCH) {
      const batch = docs.slice(i, i + BULK_BATCH);
      await db.bulk({ docs: batch });
    }

    sendFlowMessage("profile.imported", {
      id: profileId,
      configFile: safeName,
      dataFile: dataFileName,
      entries: docs.length,
    });

    res.json({ ok: true, profileId });
  } catch (err) {
    console.error("Error importing profile:", err);
    res.status(500).json({ error: err.message || "Import failed." });
  }
});

app.get("/profile/:id/edit", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    let forms = [];
    try {
      const result = await db.find({
        selector: { type: "elenko_entry_form" },
        fields: ["_id", "name"],
        sort: [{ name: "asc" }],
        limit: 500,
      });
      forms = result.docs || [];
    } catch (e) {}
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditProfilePage(doc, forms, appUi));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Profile not found"));
    console.error("Error loading profile:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.put("/api/profiles/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const {
      _rev,
      name,
      description,
      fieldNames,
      customCss,
      entryFormId,
      entryFormIds,
      theme,
      listFields: rawListFields,
      mobileSingleEntryFormId,
      infoImportFlowId,
      infoImportButtonTitle,
      guardianFlowId,
      sortKeyFields: rawSortKeyFields,
      sortDirection,
    } = req.body || {};
    if (!_rev || !name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Name and _rev are required" });
    }
    const doc = await db.get(id);
    if (doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const fields = Array.isArray(fieldNames)
      ? fieldNames.filter((f) => typeof f === "string" && f.trim()).map((f) => f.trim())
      : (Array.isArray(doc.fieldNames) ? doc.fieldNames : []);
    doc.name = name.trim();
    doc.description = description != null ? String(description).trim() : "";
    doc.customCss = customCss != null ? String(customCss) : "";
    doc.fieldNames = fields;
    doc.fieldDefaultSources = normalizeFieldDefaultSources(fields, req.body.fieldDefaultSources);
    doc.fieldDisplay = normalizeFieldDisplay(fields, req.body.fieldDisplay);
    let updatedEntryFormIds;
    if (Array.isArray(entryFormIds)) {
      updatedEntryFormIds = entryFormIds
        .filter((f) => typeof f === "string" && f.trim())
        .map((f) => f.trim());
    } else {
      updatedEntryFormIds = Array.isArray(doc.entryFormIds) ? doc.entryFormIds : [];
    }
    doc.entryFormIds = updatedEntryFormIds;
    const requestedEntryFormId =
      entryFormId != null && typeof entryFormId === "string" ? entryFormId.trim() : undefined;
    if (updatedEntryFormIds.length > 0) {
      doc.entryFormId = updatedEntryFormIds[0];
    } else if (requestedEntryFormId !== undefined) {
      doc.entryFormId = requestedEntryFormId;
    } else {
      doc.entryFormId = "";
    }
    doc.theme = normalizeProfileTheme(theme);
    const listFields =
      Array.isArray(rawListFields)
        ? rawListFields
            .filter((f) => typeof f === "string" && f.trim())
            .map((f) => f.trim())
            .filter((f) => fields.includes(f))
            .slice(0, 3)
        : Array.isArray(doc.listFields)
          ? doc.listFields
          : fields.slice(0, 3);
    doc.listFields = listFields;
    const mobileSingleId =
      typeof mobileSingleEntryFormId === "string" && mobileSingleEntryFormId.trim()
        ? mobileSingleEntryFormId.trim()
        : "";
    // Dropdown lists all entry forms; mobile form may differ from profile-linked forms.
    // Persist if the id exists as an elenko_entry_form (not only when in entryFormIds).
    let mobileToSave = "";
    if (mobileSingleId) {
      try {
        const formDoc = await db.get(mobileSingleId);
        if (formDoc && formDoc.type === "elenko_entry_form") mobileToSave = mobileSingleId;
      } catch (e) {
        if (e.statusCode !== 404) throw e;
      }
    }
    doc.mobileSingleEntryFormId = mobileToSave;
    const importFlowIdNormalized =
      typeof infoImportFlowId === "string" && infoImportFlowId.trim()
        ? infoImportFlowId.trim()
        : (typeof guardianFlowId === "string" && guardianFlowId.trim() ? guardianFlowId.trim() : "");
    doc.infoImportFlowId = importFlowIdNormalized;
    // Keep legacy field for backward compatibility with existing data/routes.
    doc.guardianFlowId = importFlowIdNormalized;
    const importButtonTitle =
      typeof infoImportButtonTitle === "string" && infoImportButtonTitle.trim()
        ? infoImportButtonTitle.trim()
        : "Import from Guardian";
    doc.infoImportButtonTitle = importButtonTitle;
    const sortKeyFields = Array.isArray(rawSortKeyFields)
      ? rawSortKeyFields
          .filter((f) => typeof f === "string" && f.trim())
          .slice(0, SORT_KEY_FIELDS_MAX)
          .map((f) => f.trim())
          .filter((f) => fields.includes(f) || SORT_KEY_SPECIAL.includes(f))
      : [];
    doc.sortKeyFields = sortKeyFields;
    doc.sortDirection = sortDirection === "desc" ? "desc" : "asc";
    const result = await db.insert(doc);
    clearProfileListCache(id);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict; refresh and try again" });
    if (err?.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
    console.error("Error updating profile:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/profiles/:id/entry-forms/clone-default", requireAdmin, async (req, res) => {
  try {
    const profileId = req.params.id;
    const nameRaw = req.body && typeof req.body.name === "string" ? req.body.name.trim() : "";
    if (!nameRaw) {
      return res.status(400).json({ error: "Name is required" });
    }
    const profile = await db.get(profileId);
    if (!profile || profile.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const formIds = getProfileEntryFormIds(profile);
    if (!formIds.length) {
      return res.status(400).json({ error: "Profile does not have a default entry form to clone." });
    }
    const defaultFormId = formIds[0];
    let baseForm;
    try {
      baseForm = await db.get(defaultFormId);
    } catch (e) {
      return res.status(404).json({ error: "Default entry form not found" });
    }
    if (!baseForm || baseForm.type !== "elenko_entry_form") {
      return res.status(404).json({ error: "Default entry form not found" });
    }
    const newFormDoc = buildEntryFormDocFromSource(baseForm, nameRaw);
    const formResult = await db.insert(newFormDoc);
    let latestProfile = await db.get(profileId);
    if (!latestProfile || latestProfile.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found after creating form" });
    }
    const updatedIds = getProfileEntryFormIds(latestProfile);
    if (!updatedIds.includes(formResult.id)) {
      updatedIds.push(formResult.id);
    }
    latestProfile.entryFormIds = updatedIds;
    if (updatedIds.length > 0) {
      latestProfile.entryFormId = updatedIds[0];
    }
    const profileResult = await db.insert(latestProfile);
    clearProfileListCache(profileId);
    res.status(201).json({ ok: true, id: formResult.id, rev: formResult.rev, profileRev: profileResult.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict; refresh and try again" });
    console.error("Error cloning default entry form:", err);
    res.status(500).json({ error: err.message || "Clone failed" });
  }
});

app.post("/api/profiles/:id/rebuild-sort-keys", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const result = await db.find({
      selector: { type: "elenko_record", profileId: id },
      limit: 50000,
    });
    const docs = result.docs || [];
    const now = new Date().toISOString();
    let updated = 0;
    for (const rec of docs) {
      if (!rec.createdAt) rec.createdAt = now;
      rec.updatedAt = now;
      rec.sortKey = buildSortKey(rec, sortKeyFields);
      await db.insert(rec);
      updated++;
    }
    clearProfileListCache(id);
    res.json({ ok: true, updated });
  } catch (err) {
    console.error("Rebuild sort keys error:", err);
    res.status(500).json({ error: err.message || "Rebuild failed" });
  }
});

app.post("/api/profiles/:id/reassign-entries", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const previousProfileId = typeof (req.body && req.body.previousProfileId) === "string" ? req.body.previousProfileId.trim() : "";
    if (!previousProfileId) {
      return res.status(400).json({ error: "previousProfileId is required" });
    }
    if (previousProfileId === id) {
      return res.status(400).json({ error: "Previous profile ID is the same as current profile; nothing to reassign." });
    }
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const result = await db.find({
      selector: { type: "elenko_record", profileId: previousProfileId },
      limit: 50000,
    });
    const docs = result.docs || [];
    const now = new Date().toISOString();
    let reassigned = 0;
    for (const rec of docs) {
      rec.profileId = id;
      if (!rec.createdAt) rec.createdAt = now;
      rec.updatedAt = now;
      rec.sortKey = buildSortKey(rec, sortKeyFields);
      await db.insert(rec);
      reassigned++;
    }
    clearProfileListCache(id);
    clearProfileListCache(previousProfileId);
    res.json({ ok: true, reassigned });
  } catch (err) {
    console.error("Reassign entries error:", err);
    res.status(500).json({ error: err.message || "Reassign failed" });
  }
});

app.get("/profile/:id/entry/new", requireEditor, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const sources = Array.isArray(doc.fieldDefaultSources) ? doc.fieldDefaultSources : [];
    const now = new Date().toISOString();
    const currentUser = req.session && req.session.user ? String(req.session.user) : "";
    const initialValues = {};
    for (let i = 0; i < fieldNames.length; i++) {
      const src = sources[i];
      initialValues[fieldNames[i]] = resolveDefaultValue(src, req);
    }
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderCreateEntryPage(doc, initialValues));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Profile not found"));
    console.error("Error loading profile:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/profiles/:id/entries", requireEditor, async (req, res) => {
  try {
    const profileId = req.params.id;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const values = req.body || {};
    const record = { type: "elenko_record", profileId };
    for (const fn of fieldNames) {
      record[fn] = values[fn] != null ? String(values[fn]).trim() : "";
    }
    const now = new Date().toISOString();
    record.createdAt = now;
    record.updatedAt = now;
    const sources = Array.isArray(doc.fieldDefaultSources) ? doc.fieldDefaultSources : [];
    for (let i = 0; i < fieldNames.length; i++) {
      const src = sources[i];
      if (src === "createdAt" || src === "updatedAt" || src === "currentUser") {
        record[fieldNames[i]] = resolveDefaultValue(src, req);
      }
    }
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    record.sortKey = buildSortKey(record, sortKeyFields);
    const requestedEntryFormId = typeof values.entryFormId === "string" ? values.entryFormId.trim() : "";
    const profileFormIds = getProfileEntryFormIds(doc);
    if (requestedEntryFormId && profileFormIds.includes(requestedEntryFormId)) {
      record.entryFormId = requestedEntryFormId;
    } else if (profileFormIds.length > 0) {
      record.entryFormId = profileFormIds[0];
    }
    const result = await db.insert(record);
    clearProfileListCache(profileId);
     sendFlowMessage("entry.created", { id: result.id, profileId, fields: fieldNames });
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
    console.error("Error creating entry:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/profile/:id/entry/:entryId/send-to-flow", requireAuth, async (req, res) => {
  try {
    const profileId = req.params.id;
    const entryId = req.params.entryId;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      return res.status(404).json({ error: "Entry not found" });
    }
    let formDoc = null;
    const profileFormIds = getProfileEntryFormIds(doc);
    let formId = "";
    if (record.entryFormId && typeof record.entryFormId === "string" && record.entryFormId.trim()) {
      formId = record.entryFormId.trim();
    } else if (profileFormIds.length > 0) {
      formId = profileFormIds[0];
    }
    if (formId) {
      try {
        const loaded = await db.get(formId);
        if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
      } catch (e) {
        // form missing
      }
    }
    const flowIndex = req.body && typeof req.body.flowIndex === "number" ? req.body.flowIndex : (req.body && typeof req.body.flowIndex === "string" ? parseInt(req.body.flowIndex, 10) : undefined);
    const flowConfigs = Array.isArray(formDoc && formDoc.flowConfigs) ? formDoc.flowConfigs : [];
    const flowConfig = (typeof flowIndex === "number" && flowIndex >= 0 && flowConfigs[flowIndex]) ? flowConfigs[flowIndex] : null;
    const target = flowConfig
      ? (flowConfig.target === "api" || flowConfig.target === "localDb" || flowConfig.target === "log" ? flowConfig.target : "log")
      : (formDoc && (formDoc.flowTarget === "api" || formDoc.flowTarget === "localDb" || formDoc.flowTarget === "log") ? formDoc.flowTarget : "log");
    const flowButtonParam = flowConfig ? (typeof flowConfig.param === "string" ? flowConfig.param : "") : (formDoc && typeof formDoc.flowButtonParam === "string" ? formDoc.flowButtonParam : "");
    const flowId = flowConfig && typeof flowConfig.flowId === "string" ? flowConfig.flowId.trim() : "";
    if (flowId && configDb) {
      try {
        let flowDoc = null;
        try {
          flowDoc = await configDb.get(flowId);
        } catch (e) {
          if (e.statusCode !== 404) throw e;
        }
        if (!flowDoc || flowDoc.type !== "elenko_flow") {
          const byName = await configDb.find({ selector: { type: "elenko_flow", name: flowId }, limit: 1 });
          flowDoc = byName.docs && byName.docs[0];
        }
        if (flowDoc && flowDoc.type === "elenko_flow") {
          const context = {
            profileId,
            entryId,
            profileName: doc.name || profileId,
            dataset: record,
            param: flowButtonParam,
          };
          await runPipeline(context, flowDoc);
          return res.json({ ok: true });
        }
      } catch (pipeErr) {
        console.error("Pipeline error:", pipeErr);
        return res.status(500).json({ error: pipeErr.message || "Pipeline failed" });
      }
    }
    sendFlowMessage("entry.sendToFlow", {
      target,
      profileId,
      entryId,
      profileName: doc.name || profileId,
      dataset: record,
      param: flowButtonParam,
    });
    res.json({ ok: true });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Not found" });
    console.error("Send to flow error:", err);
    res.status(500).json({ error: err.message || "Send failed" });
  }
});

app.post("/api/profile/:id/run-flow", requireEditor, async (req, res) => {
  try {
    const profileId = req.params.id;
    const profileDoc = await db.get(profileId);
    if (!profileDoc || profileDoc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    if (!configDb) {
      return res.status(503).json({ error: "Config store not available" });
    }
    const body = req.body || {};
    const flowRefRaw = typeof body.flowId === "string" ? body.flowId.trim() : "";
    const profileConfiguredFlowId =
      typeof profileDoc.infoImportFlowId === "string" && profileDoc.infoImportFlowId.trim()
        ? profileDoc.infoImportFlowId.trim()
        : (typeof profileDoc.guardianFlowId === "string" ? profileDoc.guardianFlowId.trim() : "");
    const flowRef = flowRefRaw || profileConfiguredFlowId;
    if (!flowRef) {
      return res.status(400).json({ error: "Flow ID is required." });
    }
    let flowDoc = null;
    try {
      flowDoc = await configDb.get(flowRef);
    } catch (e) {
      if (e.statusCode !== 404) throw e;
    }
    if (!flowDoc || flowDoc.type !== "elenko_flow") {
      const byName = await configDb.find({ selector: { type: "elenko_flow", name: flowRef }, limit: 1 });
      flowDoc = byName.docs && byName.docs[0];
    }
    if (!flowDoc || flowDoc.type !== "elenko_flow") {
      return res.status(404).json({ error: "Flow not found: " + flowRef });
    }

    const query = typeof body.query === "string" ? body.query.trim() : "";
    const dataset = { query, guardianQuery: query };
    const context = {
      profileId,
      entryId: "",
      profileName: profileDoc.name || profileId,
      dataset,
      param: "",
      // Profile-page imports should only create rows from JS output._createMany.
      // Prevent accidental single-record create/update steps from persisting a helper document.
      suppressSinglePersist: true,
    };
    await runPipeline(context, flowDoc);
    const created = Number(context.dataset && context.dataset._lastCreatedCount) || 0;
    return res.json({ ok: true, created });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Not found" });
    console.error("Run profile flow error:", err);
    return res.status(500).json({ error: err.message || "Flow failed" });
  }
});

app.get("/profile/:id/entry/:entryId", async (req, res) => {
  try {
    const profileId = req.params.id;
    const entryId = req.params.entryId;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      return res.status(404).send(renderErrorPage("Entry not found"));
    }
    let formDoc = null;
    const profileFormIds = getProfileEntryFormIds(doc);
    let formId = "";
    const mobileFormIdRaw =
      typeof doc.mobileSingleEntryFormId === "string" && doc.mobileSingleEntryFormId.trim()
        ? doc.mobileSingleEntryFormId.trim()
        : "";
    const useMobileForm = mobileFormIdRaw && isMobileRequest(req);
    if (useMobileForm) {
      formId = mobileFormIdRaw;
    } else if (record.entryFormId && typeof record.entryFormId === "string" && record.entryFormId.trim()) {
      formId = record.entryFormId.trim();
    } else if (profileFormIds.length > 0) {
      formId = profileFormIds[0];
    }
    if (formId) {
      try {
        const loaded = await db.get(formId);
        if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
      } catch (e) {
        // form missing or not found – use default
      }
    }
    const role = (req.session && req.session.role) || "editor";
    const returnQuery = { q: req.query.q, page: req.query.page };
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderViewEntryPage(doc, record, role, formDoc, returnQuery));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Entry not found"));
    console.error("Error loading entry:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/profile/:id/entry/:entryId/edit", requireEditor, async (req, res) => {
  try {
    const profileId = req.params.id;
    const entryId = req.params.entryId;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      return res.status(404).send(renderErrorPage("Entry not found"));
    }
    const profileFormIds = getProfileEntryFormIds(doc);
    let formDoc = null;
    let currentFormId = "";
    if (record.entryFormId && typeof record.entryFormId === "string" && record.entryFormId.trim()) {
      currentFormId = record.entryFormId.trim();
    } else if (profileFormIds.length > 0) {
      currentFormId = profileFormIds[0];
    }
    if (currentFormId) {
      try {
        const loaded = await db.get(currentFormId);
        if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
      } catch (_) {
        // ignore
      }
    }
    const formChoices = [];
    const seenIds = new Set();
    if (currentFormId && formDoc) {
      formChoices.push({ _id: formDoc._id, name: formDoc.name || formDoc._id });
      seenIds.add(formDoc._id);
    }
    for (const fid of profileFormIds) {
      if (!fid || typeof fid !== "string") continue;
      const trimmed = fid.trim();
      if (!trimmed || seenIds.has(trimmed)) continue;
      try {
        const f = await db.get(trimmed);
        if (f && f.type === "elenko_entry_form") {
          formChoices.push({ _id: f._id, name: f.name || f._id });
          seenIds.add(f._id);
        }
      } catch (_) {
        // ignore missing
      }
    }
    const returnQuery = { q: req.query.q, page: req.query.page };
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditEntryPage(doc, record, formDoc, returnQuery, formChoices, currentFormId));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Entry not found"));
    console.error("Error loading entry:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.put("/api/profiles/:id/entries/:entryId", requireEditor, async (req, res) => {
  try {
    const profileId = req.params.id;
    const entryId = req.params.entryId;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      return res.status(404).json({ error: "Entry not found" });
    }
    const values = req.body || {};
    if (values._rev && values._rev !== record._rev) {
      return res.status(409).json({ error: "Entry was modified elsewhere; refresh and try again" });
    }
    const profileFieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    let formDoc = null;
    const profileFormIds = getProfileEntryFormIds(doc);
    const formId = (record.entryFormId && typeof record.entryFormId === "string" && record.entryFormId.trim())
      ? record.entryFormId.trim()
      : (profileFormIds.length > 0 ? profileFormIds[0] : "");
    if (formId) {
      try {
        const loaded = await db.get(formId);
        if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
      } catch (_) {}
    }
    const formFieldNames = getFieldNamesFromFormLayout(formDoc);
    const fieldNames = [...new Set([...profileFieldNames, ...formFieldNames])];
    for (const fn of fieldNames) {
      record[fn] = values[fn] != null ? String(values[fn]).trim() : "";
    }
    if (Object.prototype.hasOwnProperty.call(values, "entryFormId")) {
      const newEntryFormId =
        typeof values.entryFormId === "string" ? values.entryFormId.trim() : "";
      record.entryFormId = newEntryFormId;
    }
    const now = new Date().toISOString();
    record.updatedAt = now;
    if (!record.createdAt) record.createdAt = now;
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    record.sortKey = buildSortKey(record, sortKeyFields);
    const result = await db.insert(record);
    clearProfileListCache(profileId);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict; refresh and try again" });
    console.error("Error updating entry:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/profiles/:id/entries/:entryId", requireEditor, async (req, res) => {
  try {
    const profileId = req.params.id;
    const entryId = req.params.entryId;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      return res.status(404).json({ error: "Entry not found" });
    }
    await db.destroy(entryId, record._rev);
    clearProfileListCache(profileId);
    const returnParts = [];
    if (req.query.page) returnParts.push("page=" + encodeURIComponent(String(req.query.page)));
    if (req.query.q) returnParts.push("q=" + encodeURIComponent(req.query.q));
    const returnQueryStr = returnParts.length > 0 ? "?" + returnParts.join("&") : "";
    const redirect = "/profile/" + encodeURIComponent(profileId) + returnQueryStr;
    res.json({ ok: true, redirect });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry not found" });
    console.error("Error deleting entry:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/deletions", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_pending_deletions" },
    });
    const batches = result.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderDeletionsPage(batches, appUi));
  } catch (err) {
    console.error("Error loading deletions:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/deletions/:batchId/execute", requireAdmin, async (req, res) => {
  try {
    const batchId = req.params.batchId;
    const batch = await db.get(batchId);
    if (!batch || batch.type !== "elenko_pending_deletions") {
      return res.status(404).json({ error: "Batch not found" });
    }
    const entries = Array.isArray(batch.entries) ? batch.entries : [];
    for (const e of entries) {
      try {
        await db.destroy(e.id, e.rev);
      } catch (err) {
        if (err?.statusCode !== 404) throw err;
      }
    }
    await db.destroy(batchId, batch._rev);
    clearProfileListCache();
    res.json({ ok: true, deleted: entries.length });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Batch not found" });
    console.error("Error executing deletions:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/profile/:id/delete", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderDeleteProfilePage(doc));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Profile not found"));
    console.error("Error loading profile:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/profiles/:id/copy", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    let baseDoc;
    try {
      baseDoc = await db.get(id);
    } catch (e) {
      if (e.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
      throw e;
    }
    if (!baseDoc || baseDoc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const nameResult = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["name"],
      limit: 5000,
    });
    const existing = new Set();
    for (const d of nameResult.docs || []) {
      if (d && typeof d.name === "string" && d.name.trim()) existing.add(d.name.trim());
    }
    const newName = makeUniqueProfileCopyName(baseDoc.name, existing);
    const newDoc = buildProfileDocFromSource(baseDoc, newName);
    const result = await db.insert(newDoc);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev, name: newName });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
    console.error("Error copying profile:", err);
    res.status(500).json({ error: err.message || "Copy failed" });
  }
});

app.post("/api/profiles/:id/delete", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { _rev } = req.body || {};
    if (!_rev) return res.status(400).json({ error: "Missing _rev" });
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    if (doc._rev !== _rev) {
      return res.status(409).json({ error: "Profile was modified; refresh and try again" });
    }
    const recordsResult = await db.find({
      selector: { type: "elenko_record", profileId: id },
      fields: ["_id", "_rev"],
      limit: MAX_ENTRIES_PER_PROFILE,
    });
    const entries = (recordsResult.docs || []).map((r) => ({ id: r._id, rev: r._rev }));
    await db.destroy(id, _rev);
    let redirect = "/";
    if (entries.length > 0) {
      await db.insert({
        type: "elenko_pending_deletions",
        profileName: doc.name || id,
        entries,
        createdAt: new Date().toISOString(),
      });
      redirect = "/deletions";
    }
    res.json({ ok: true, redirect });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict" });
    console.error("Error deleting profile:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/profile/:id", async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    const profileId = doc._id;
    if (req.query.clearSearch) {
      clearSearchListCache(profileId);
      const profileBase = "/profile/" + encodeURIComponent(profileId);
      return res.redirect(profileBase);
    }
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const searchQuery = (req.query.q || "").trim();
    const skip = (page - 1) * ENTRIES_PAGE_SIZE;

    const selector = { type: "elenko_record", profileId };
    if (searchQuery && fieldNames.length > 0) {
      const pattern = ".*" + escapeRegex(searchQuery) + ".*";
      selector.$or = fieldNames.map((fn) => ({ [fn]: { $regex: pattern } }));
    }

    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    const useSortKey = sortKeyFields.length > 0;
    const sortDirection = doc.sortDirection === "desc" ? "desc" : "asc";
    const fieldsForFind = fieldNames.length ? ["_id", "_rev", "sortKey", ...fieldNames] : ["_id", "_rev", "sortKey"];
    const SORT_FETCH_LIMIT = 50000;

    let totalPages = null;
    let allDocs = [];
    if (!searchQuery) {
      try {
        const countResult = await db.view("records", "countByProfile", { key: profileId });
        const totalEntries = countResult.rows && countResult.rows[0] ? countResult.rows[0].value : 0;
        totalPages = Math.max(1, Math.ceil(totalEntries / ENTRIES_PAGE_SIZE));
      } catch (e) {
        totalPages = 1;
      }
    }

    if (useSortKey && !searchQuery) {
      const cacheKey = profileId;
      const sortConfig = JSON.stringify({ sortKeyFields, sortDirection });
      const cached = profileListCache.get(cacheKey);
      if (cached && cached.sortConfig === sortConfig && Array.isArray(cached.docs)) {
        totalPages = Math.max(1, Math.ceil(cached.docs.length / ENTRIES_PAGE_SIZE));
        allDocs = cached.docs.slice(skip, skip + ENTRIES_PAGE_SIZE + 1);
      } else {
        const sortResult = await db.find({
          selector,
          fields: fieldsForFind,
          limit: SORT_FETCH_LIMIT,
        });
        const fullDocs = sortResult.docs || [];
        // Lexicographic comparison for all tiers (e.g. "01", "02", "10", "A01", "B02"); same direction for every level
        const cmp = (a, b) => {
          const sa = Array.isArray(a.sortKey) ? a.sortKey : [];
          const sb = Array.isArray(b.sortKey) ? b.sortKey : [];
          for (let i = 0; i < Math.max(sa.length, sb.length); i++) {
            const va = sa[i] != null ? String(sa[i]) : "";
            const vb = sb[i] != null ? String(sb[i]) : "";
            const c = va.localeCompare(vb, undefined, { sensitivity: "base" });
            if (c !== 0) return sortDirection === "desc" ? -c : c;
          }
          return 0;
        };
        fullDocs.sort(cmp);
        profileListCache.set(cacheKey, { docs: fullDocs, sortConfig });
        totalPages = Math.max(1, Math.ceil(fullDocs.length / ENTRIES_PAGE_SIZE));
        allDocs = fullDocs.slice(skip, skip + ENTRIES_PAGE_SIZE + 1);
      }
    } else if (useSortKey && searchQuery) {
      // Search with sort-key profile: use cached sorted docs or fetch, sort, cache, then paginate
      const sortConfig = JSON.stringify({ sortKeyFields, sortDirection });
      const searchCacheKey = profileId + SEARCH_CACHE_KEY_SEP + sortConfig + SEARCH_CACHE_KEY_SEP + searchQuery;
      const cached = searchListCache.get(searchCacheKey);
      if (cached && Array.isArray(cached.docs)) {
        totalPages = Math.max(1, Math.ceil(cached.docs.length / ENTRIES_PAGE_SIZE));
        allDocs = cached.docs.slice(skip, skip + ENTRIES_PAGE_SIZE + 1);
      } else {
        const sortResult = await db.find({
          selector,
          fields: fieldsForFind,
          limit: SORT_FETCH_LIMIT,
        });
        const fullDocs = sortResult.docs || [];
        const cmp = (a, b) => {
          const sa = Array.isArray(a.sortKey) ? a.sortKey : [];
          const sb = Array.isArray(b.sortKey) ? b.sortKey : [];
          for (let i = 0; i < Math.max(sa.length, sb.length); i++) {
            const va = sa[i] != null ? String(sa[i]) : "";
            const vb = sb[i] != null ? String(sb[i]) : "";
            const c = va.localeCompare(vb, undefined, { sensitivity: "base" });
            if (c !== 0) return sortDirection === "desc" ? -c : c;
          }
          return 0;
        };
        fullDocs.sort(cmp);
        searchListCache.set(searchCacheKey, { docs: fullDocs });
        totalPages = Math.max(1, Math.ceil(fullDocs.length / ENTRIES_PAGE_SIZE));
        allDocs = fullDocs.slice(skip, skip + ENTRIES_PAGE_SIZE + 1);
      }
    } else {
      const recordsResult = await db.find({
        selector,
        fields: fieldsForFind,
        sort: [{ _id: "asc" }],
        limit: ENTRIES_PAGE_SIZE + 1,
        skip,
      });
      allDocs = recordsResult.docs || [];
      if (searchQuery && allDocs.length > 0) totalPages = null; // unknown total for search without sort key
    }
    const records = allDocs.slice(0, ENTRIES_PAGE_SIZE);
    const hasNext = allDocs.length > ENTRIES_PAGE_SIZE;
    const hasPrev = page > 1;
    const role = (req.session && req.session.role) || "editor";
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderElenkoDatabasePage(doc, records, role, { page, totalPages, hasNext, hasPrev, searchQuery }));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Profile not found"));
    console.error("Error loading profile:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

function renderCreateEntryPage(doc, initialValues = {}) {
  const title = escapeHtml(doc.name || "Elenko database");
  const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const profileId = doc._id;
  const backUrl = "/profile/" + encodeURIComponent(profileId);
  const customCss = doc.customCss || "";

  const rows =
    fieldNames.length > 0
      ? fieldNames
          .map(
            (fn) => {
              const val = initialValues[fn] != null ? String(initialValues[fn]) : "";
              return `
        <tr>
          <td class="label">${escapeHtml(fn)}</td>
          <td><input type="text" class="entry-field" name="${escapeHtml(fn)}" placeholder="${escapeHtml(fn)}" value="${escapeHtml(val)}"></td>
        </tr>`;
            }
          )
          .join("")
      : `<tr><td colspan="2" class="empty">No fields defined. Edit the profile to add field names.</td></tr>`;

  const fieldNamesJson = JSON.stringify(fieldNames);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – New entry</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 36rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #21262d; }
    .label { color: #8b949e; width: 40%; }
    tr:last-child td { border-bottom: none; }
    input[type="text"] { width: 100%; padding: 0.5rem; background: #0f1419; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input:focus { outline: none; border-color: #58a6ff; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; margin-top: 1rem; }
    .btn:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; text-decoration: none; }
    .btn-secondary:hover { background: #30363d; }
    .empty { color: #8b949e; font-style: italic; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
  ${customCss ? `<style>${customCss}</style>` : ""}
</head>
<body>
  <div class="actions"><a href="${escapeHtml(backUrl)}">← Back to database</a></div>
  <h1>${title}</h1>
  <p class="sub">New entry</p>
  <form id="entry-form">
    <table>
      <tbody>${rows}
      </tbody>
    </table>
    <div>
      <button type="submit" class="btn">Create entry</button>
      <a href="${escapeHtml(backUrl)}" class="btn btn-secondary" style="margin-left: 0.5rem;">Cancel</a>
    </div>
  </form>
  <div id="msg"></div>
  <script>
    const profileId = ${JSON.stringify(profileId)};
    const fieldNames = ${fieldNamesJson};
    const form = document.getElementById('entry-form');
    const msgEl = document.getElementById('msg');

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const inputs = form.querySelectorAll('.entry-field');
      const data = {};
      fieldNames.forEach((fn, i) => { data[fn] = (inputs[i] && inputs[i].value) ? String(inputs[i].value).trim() : ''; });
      try {
        const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/entries', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const result = await r.json();
        if (!r.ok) { msgEl.textContent = result.error || 'Failed'; msgEl.className = 'msg err'; return; }
        msgEl.textContent = 'Entry created.';
        msgEl.className = 'msg ok';
        const entryViewUrl = '/profile/' + encodeURIComponent(profileId) + '/entry/' + encodeURIComponent(result.id);
        setTimeout(() => { window.location.href = entryViewUrl; }, 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function getFieldNamesFromFormLayout(formDoc) {
  if (!formDoc || !Array.isArray(formDoc.fieldLayout)) return [];
  return formDoc.fieldLayout
    .filter((item) => item && typeof item.fieldName === "string" && item.fieldName.trim())
    .map((item) => item.fieldName.trim());
}

function buildOrderedItems(profileFieldNames, formDoc) {
  const names = Array.isArray(profileFieldNames) ? profileFieldNames : [];
  const set = new Set(names);
  const labelsArr = Array.isArray(formDoc && formDoc.labels) ? formDoc.labels : [];
  const labelsById = {};
  for (const l of labelsArr) {
    if (l && l.id) labelsById[l.id] = l.text || "";
  }

  if (!formDoc || !Array.isArray(formDoc.fieldLayout) || formDoc.fieldLayout.length === 0) {
    return names.map((fn) => ({ type: "field", fieldName: fn, width: "100%" }));
  }

  const byFieldName = {};
  for (const item of formDoc.fieldLayout) {
    if (item && item.fieldName) byFieldName[item.fieldName] = item;
  }
  const seenFields = new Set();
  const seenLabels = new Set();
  const ordered = [];
  const sorted = formDoc.fieldLayout
    .filter((item) => item && (item.fieldName || item.labelId))
    .sort((a, b) => (a.order != null ? Number(a.order) : 0) - (b.order != null ? Number(b.order) : 0));

  for (const item of sorted) {
    if (item.fieldName && !seenFields.has(item.fieldName)) {
      seenFields.add(item.fieldName);
      ordered.push({
        type: "field",
        fieldName: item.fieldName,
        width: item.width || "100%",
        x: item.x,
        y: item.y,
        height: item.height,
        fieldType: item.fieldType === "markdown" ? "markdown" : item.fieldType === "url" ? "url" : "text",
      });
    } else if (item.labelId && labelsById[item.labelId] !== undefined && !seenLabels.has(item.labelId)) {
      seenLabels.add(item.labelId);
      ordered.push({
        type: "label",
        id: item.labelId,
        text: labelsById[item.labelId],
        width: item.width || "100%",
        x: item.x,
        y: item.y,
        height: item.height,
      });
    }
  }
  // When field layout is configured, show only fields/labels explicitly listed there.
  return ordered;
}

function positionStyle(o) {
  const parts = [];
  if (o.x != null) parts.push("left:" + o.x + "ch");
  if (o.y != null) parts.push("top:" + o.y + "em");
  if (o.height != null) parts.push("min-height:" + o.height + "em");
  if (parts.length === 0) return "";
  return "position:absolute;" + parts.join(";");
}

function blockOrCellStyle(o) {
  const parts = [];
  if (o.x != null) parts.push("left:" + o.x + "ch");
  if (o.y != null) parts.push("top:" + o.y + "em");
  if (o.height != null) parts.push("min-height:" + o.height + "em");
  if (o.width && typeof o.width === "string" && o.width.trim()) parts.push("width:" + o.width.trim());
  if (parts.length === 0) return "";
  const pos = o.x != null || o.y != null || o.height != null;
  if (pos) parts.unshift("position:absolute");
  return parts.join(";");
}

function gridCellStyle(o) {
  if (o.width && typeof o.width === "string" && o.width.trim()) return "width:" + o.width.trim();
  return "";
}

function renderViewEntryPage(doc, record, role, formDoc, returnQuery) {
  const canEdit = role === "admin" || role === "editor" || role === "user";
  const title = escapeHtml(doc.name || "Elenko database");
  const profileFieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const orderedItems = buildOrderedItems(profileFieldNames, formDoc);
  const profileId = doc._id;
  const entryId = record._id;
  const returnParts = [];
  if (returnQuery && returnQuery.page) returnParts.push("page=" + encodeURIComponent(String(returnQuery.page)));
  if (returnQuery && returnQuery.q) returnParts.push("q=" + encodeURIComponent(returnQuery.q));
  const returnQueryStr = returnParts.length > 0 ? "?" + returnParts.join("&") : "";
  const backUrl = "/profile/" + encodeURIComponent(profileId) + returnQueryStr;
  const editUrl = "/profile/" + encodeURIComponent(profileId) + "/entry/" + encodeURIComponent(entryId) + "/edit" + returnQueryStr;

  const theme = formDoc && formDoc.theme ? formDoc.theme : DEFAULT_ENTRY_VIEW_THEME;
  const bg = theme.background || DEFAULT_ENTRY_VIEW_THEME.background;
  const text = theme.text || DEFAULT_ENTRY_VIEW_THEME.text;
  const labelColor = theme.label || DEFAULT_ENTRY_VIEW_THEME.label;
  const linkColor = theme.link || DEFAULT_ENTRY_VIEW_THEME.link;
  const fieldBorder = theme.fieldBorder || DEFAULT_ENTRY_VIEW_THEME.fieldBorder;
  const fieldBg = theme.fieldBackground || DEFAULT_ENTRY_VIEW_THEME.fieldBackground;
  const layout = formDoc && (formDoc.layout === "grid" || formDoc.layout === "stack") ? formDoc.layout : "table";
  const formCustomCss = formDoc && formDoc.customCss ? formDoc.customCss : "";
  const flowConfigsArray = Array.isArray(formDoc && formDoc.flowConfigs) && formDoc.flowConfigs.length > 0
    ? formDoc.flowConfigs
    : (formDoc && formDoc.flowButtonEnabled ? [{ enabled: true, label: (formDoc.flowButtonLabel && typeof formDoc.flowButtonLabel === "string" && formDoc.flowButtonLabel.trim()) ? formDoc.flowButtonLabel.trim() : "Send to Flow" }] : []);
  const flowButtonsHtml = flowConfigsArray.map((c, i) => {
    const enabled = c && (c.enabled === true || c.enabled === "true");
    if (!enabled) return "";
    const label = (c && typeof c.label === "string" && c.label.trim()) ? c.label.trim() : "Send to Flow";
    const hasIndex = Array.isArray(formDoc.flowConfigs) && formDoc.flowConfigs.length > 0;
    const dataIndex = hasIndex ? ' data-flow-index="' + i + '"' : "";
    return '<button type="button" class="btn-flow" data-profile-id="' + escapeHtml(profileId) + '" data-entry-id="' + escapeHtml(entryId) + '"' + dataIndex + '>' + escapeHtml(label) + '</button>';
  }).join("");
  const hasFlowButtons = flowButtonsHtml.length > 0;
  const formLabel = formDoc && (formDoc.name || formDoc._id) ? String(formDoc.name || formDoc._id) : "";

  const themeVars = `
    :root {
      --entry-bg: ${escapeHtml(bg)};
      --entry-text: ${escapeHtml(text)};
      --entry-label: ${escapeHtml(labelColor)};
      --entry-link: ${escapeHtml(linkColor)};
      --entry-field-border: ${escapeHtml(fieldBorder)};
      --entry-field-bg: ${escapeHtml(fieldBg)};
    }`;

  const hasPositioning = orderedItems.some((o) => o.x != null || o.y != null || o.height != null);
  const containerPositionStyle = layout === "grid" ? "" : (hasPositioning ? "position:relative;min-height:40em;" : "");

  function itemLabel(o) {
    return o.type === "label" ? o.text : o.fieldName;
  }
  function labelClass(o) {
    return o.type === "label" ? "label static-label" : "label field-label";
  }
  function editControlHtml(o, value) {
    const escapedName = escapeHtml(o.fieldName);
    const escapedValue = escapeHtml(value);
    if (o.fieldType === "url") {
      return `<input type="url" class="entry-field" name="${escapedName}" placeholder="${escapedName}" value="${escapedValue}">`;
    }
    return `<textarea class="entry-field entry-field-textarea" name="${escapedName}" placeholder="${escapedName}" rows="3">${escapedValue}</textarea>`;
  }
  function itemValue(o) {
    if (o.type === "label") return "";
    const val = record[o.fieldName];
    return val != null ? String(val) : "";
  }
  function formatValueHtml(o, value) {
    if (o.type === "label") return "";
    if (o.fieldType === "markdown" && value) {
      try {
        const withNewlines = String(value).replace(/\\n/g, "\n").replace(/\\r/g, "\r");
        const html = marked.parse(withNewlines);
        return typeof html === "string" ? html : escapeHtml(value);
      } catch (_) {
        return escapeHtml(value);
      }
    }
    if (o.fieldType === "url" && value) {
      const raw = String(value).trim();
      const escapedText = escapeHtml(raw);
      const hrefRaw = /^(https?:\/\/|mailto:|tel:)/i.test(raw) ? raw : "https://" + raw;
      const escapedHref = escapeHtml(hrefRaw);
      return `<a href="${escapedHref}" target="_blank" rel="noopener noreferrer">${escapedText}</a>`;
    }
    return escapeHtml(value);
  }

  let contentHtml;
  if (orderedItems.length === 0) {
    contentHtml = '<div class="empty">No fields defined.</div>';
  } else if (layout === "stack") {
    contentHtml =
      '<div class="entry-view-stack" style="' + escapeHtml(containerPositionStyle) + '">' +
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const value = itemValue(o);
          const blockStyle = blockOrCellStyle(o);
          const styleAttr = blockStyle ? ' style="' + escapeHtml(blockStyle) + '"' : "";
          const labelOnlyClass = isLabel ? " entry-label-only" : "";
          const lc = labelClass(o);
          if (isLabel) {
            return `
        <div class="entry-field-block${labelOnlyClass}"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
        </div>`;
          }
          const valueHtml = formatValueHtml(o, value);
          const valueClass =
            o.fieldType === "markdown"
              ? " value entry-value-markdown"
              : o.fieldType === "url"
              ? " value entry-value-url"
              : " value";
          return `
        <div class="entry-field-block"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="${valueClass}">${valueHtml}</div>
        </div>`;
        })
        .join("") +
      "</div>";
  } else if (layout === "grid") {
    const widths = orderedItems.map((o) => o.width || "1fr").join(" ");
    contentHtml =
      `<div class="entry-view-grid" style="grid-template-columns: ${escapeHtml(widths)};${escapeHtml(containerPositionStyle)}">` +
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const value = itemValue(o);
          const cellStyle = gridCellStyle(o);
          const styleAttr = cellStyle ? ' style="' + escapeHtml(cellStyle) + '"' : "";
          const labelOnlyClass = isLabel ? " entry-label-only" : "";
          const lc = labelClass(o);
          if (isLabel) {
            return `
        <div class="entry-grid-cell${labelOnlyClass}"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
        </div>`;
          }
          const valueHtml = formatValueHtml(o, value);
          const valueClass =
            o.fieldType === "markdown"
              ? " value entry-value-markdown"
              : o.fieldType === "url"
              ? " value entry-value-url"
              : " value";
          return `
        <div class="entry-grid-cell"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="${valueClass}">${valueHtml}</div>
        </div>`;
        })
        .join("") +
      "</div>";
  } else {
    const rows =
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const value = itemValue(o);
          const lc = labelClass(o);
          if (isLabel) {
            const w = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
            return `
        <tr class="entry-label-row">
          <td class="${lc}" colspan="2"${w}>${escapeHtml(itemLabel(o))}</td>
        </tr>`;
          }
          const valueHtml = formatValueHtml(o, value);
          const valueClass =
            o.fieldType === "markdown"
              ? " value entry-value-markdown"
              : o.fieldType === "url"
              ? " value entry-value-url"
              : " value";
          return `
        <tr>
          <td class="${lc}">${escapeHtml(itemLabel(o))}</td>
          <td class="${valueClass}">${valueHtml}</td>
        </tr>`;
        })
        .join("");
    contentHtml = `<table><tbody>${rows}</tbody></table>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--entry-bg, #0f1419); color: var(--entry-text, #e6edf3); max-width: 36rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--entry-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--entry-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.75rem 1rem; text-align: left; }
    .label { color: var(--entry-label, #8b949e); width: 40%; }
    td.value { background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 6px; }
    .empty { color: var(--entry-label, #8b949e); font-style: italic; }
    .entry-view-stack { --entry-stack-field-max-height: 12rem; }
    .entry-view-stack .entry-field-block { margin-bottom: 1rem; min-width: 0; }
    .entry-view-stack .label { display: block; margin-bottom: 0.25rem; }
    .entry-view-stack .entry-field-block:not(.entry-label-only) .value {
      max-height: var(--entry-stack-field-max-height, 12rem);
      overflow-y: auto;
      overflow-x: hidden;
      background: var(--entry-field-bg, #161b22);
      border: 1px solid var(--entry-field-border, #21262d);
      border-radius: 6px;
      padding: 0.75rem 1rem;
    }
    .entry-view-stack .entry-label-only .label { white-space: nowrap; }
    .entry-view-grid { display: grid; gap: 1rem; }
    .entry-grid-cell .label { display: block; margin-bottom: 0.25rem; color: var(--entry-label, #8b949e); }
    .entry-grid-cell .value { background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 6px; padding: 0.75rem 1rem; }
    .entry-value-markdown { line-height: 1.5; }
    .entry-value-markdown p { margin: 0 0 0.75rem 0; }
    .entry-value-markdown p:last-child { margin-bottom: 0; }
    .entry-value-markdown ul, .entry-value-markdown ol { margin: 0 0 0.75rem 0; padding-left: 1.5rem; }
    .entry-value-markdown h1, .entry-value-markdown h2, .entry-value-markdown h3 { margin: 1rem 0 0.5rem 0; font-weight: 600; }
    .entry-value-markdown h1 { font-size: 1.25rem; }
    .entry-value-markdown h2 { font-size: 1.1rem; }
    .entry-value-markdown h3 { font-size: 1rem; }
    .entry-value-markdown a { color: var(--entry-link, #58a6ff); }
    .entry-value-url a { color: var(--entry-link, #58a6ff); word-break: break-all; }
    .entry-grid-cell.entry-label-only .label { white-space: nowrap; }
    .entry-label-row .label { white-space: nowrap; }
  </style>
  ${formCustomCss ? `<style>${formCustomCss}</style>` : ""}
</head>
<body>
  <div class="actions"><a href="${escapeHtml(backUrl)}">← Back to database</a>${canEdit ? ` <a href="${editUrl}">Edit</a>` : ""}</div>
  <div class="actions entry-flow-actions" style="margin-top:0.5rem;display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;">
    ${flowButtonsHtml}
    <button type="button" id="refresh-entry-btn" class="btn-flow btn-flow-secondary" style="${hasFlowButtons ? "margin-left:0;" : ""}">Refresh</button>
  </div>
  ${hasFlowButtons ? '<div id="flow-msg" class="flow-msg"></div>' : ""}
  <h1>${title}</h1>
  ${formLabel ? `<p class="sub">Form: ${escapeHtml(formLabel)}</p>` : ""}
  ${contentHtml}
  ${hasFlowButtons ? "\n  <style>.btn-flow { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; background: #238636; color: #fff; }.btn-flow:hover { background: #2ea043; }.btn-flow:disabled { opacity: 0.6; cursor: not-allowed; }.btn-flow-secondary { background: #21262d; }.btn-flow-secondary:hover { background: #30363d; }.flow-msg { margin-top: 0.5rem; font-size: 0.875rem; }.flow-msg.ok { color: #3fb950; }.flow-msg.err { color: #f85149; }</style>\n  <script>\n    (function() {\n      var msgEl = document.getElementById(\"flow-msg\");\n      document.querySelectorAll(\".entry-flow-actions .btn-flow[data-entry-id]\").forEach(function(btn) {\n        if (btn.id === \"refresh-entry-btn\") return;\n        btn.onclick = function() {\n          var pid = btn.getAttribute(\"data-profile-id\");\n          var eid = btn.getAttribute(\"data-entry-id\");\n          if (!pid || !eid) return;\n          btn.disabled = true;\n          if (msgEl) { msgEl.textContent = \"\"; msgEl.className = \"flow-msg\"; }\n          var body = {};\n          var idx = btn.getAttribute(\"data-flow-index\");\n          if (idx !== null && idx !== \"\") body.flowIndex = parseInt(idx, 10);\n          var url = \"/api/profile/\" + encodeURIComponent(pid) + \"/entry/\" + encodeURIComponent(eid) + \"/send-to-flow\";\n          fetch(url, { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify(body) })\n            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })\n            .then(function(o) {\n              if (o.ok && msgEl) { msgEl.textContent = \"Sent to Flow.\"; msgEl.className = \"flow-msg ok\"; }\n              else if (msgEl) { msgEl.textContent = o.data.error || \"Failed\"; msgEl.className = \"flow-msg err\"; }\n              btn.disabled = false;\n            })\n            .catch(function(e) { if (msgEl) { msgEl.textContent = e.message || \"Request failed\"; msgEl.className = \"flow-msg err\"; } btn.disabled = false; });\n        };\n      });\n      var refreshBtn = document.getElementById(\"refresh-entry-btn\");\n      if (refreshBtn) refreshBtn.onclick = function() { window.location.reload(); };\n    })();\n  </script>" : "\n  <style>.btn-flow { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }.btn-flow-secondary { background: #21262d; color: #e6edf3; }.btn-flow-secondary:hover { background: #30363d; }</style>\n  <script>\n    (function() {\n      var refreshBtn = document.getElementById(\"refresh-entry-btn\");\n      if (refreshBtn) refreshBtn.onclick = function() { window.location.reload(); };\n    })();\n  </script>"}
</body>
</html>`;
}

function renderEditEntryPage(doc, record, formDoc, returnQuery, formChoices = [], currentFormId = "") {
  const title = escapeHtml(doc.name || "Elenko database");
  const profileFieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const profileId = doc._id;
  const entryId = record._id;
  const rev = escapeHtml(record._rev || "");
  const returnParts = [];
  if (returnQuery && returnQuery.page) returnParts.push("page=" + encodeURIComponent(String(returnQuery.page)));
  if (returnQuery && returnQuery.q) returnParts.push("q=" + encodeURIComponent(returnQuery.q));
  const returnQueryStr = returnParts.length > 0 ? "?" + returnParts.join("&") : "";
  const backUrl = "/profile/" + encodeURIComponent(profileId) + returnQueryStr;
  const formCustomCss = formDoc && formDoc.customCss ? formDoc.customCss : "";

  const theme = formDoc && formDoc.theme ? formDoc.theme : DEFAULT_ENTRY_VIEW_THEME;
  const bg = theme.background || DEFAULT_ENTRY_VIEW_THEME.background;
  const text = theme.text || DEFAULT_ENTRY_VIEW_THEME.text;
  const labelColor = theme.label || DEFAULT_ENTRY_VIEW_THEME.label;
  const linkColor = theme.link || DEFAULT_ENTRY_VIEW_THEME.link;
  const fieldBgEdit = theme.fieldBackgroundEdit != null ? theme.fieldBackgroundEdit : DEFAULT_ENTRY_VIEW_THEME.fieldBackgroundEdit;
  const textEdit = theme.textEdit != null ? theme.textEdit : DEFAULT_ENTRY_VIEW_THEME.textEdit;
  const layout = formDoc && (formDoc.layout === "grid" || formDoc.layout === "stack") ? formDoc.layout : "table";

  const orderedItems = buildOrderedItems(profileFieldNames, formDoc || {});
  const orderedFieldNames = orderedItems.filter((o) => o.type === "field").map((o) => o.fieldName);

  const themeVars = `
    :root {
      --entry-bg: ${escapeHtml(bg)};
      --entry-text: ${escapeHtml(text)};
      --entry-label: ${escapeHtml(labelColor)};
      --entry-link: ${escapeHtml(linkColor)};
      --entry-field-bg-edit: ${escapeHtml(fieldBgEdit)};
      --entry-text-edit: ${escapeHtml(textEdit)};
    }`;

  const hasPositioning = orderedItems.some((o) => o.x != null || o.y != null || o.height != null);
  const containerPositionStyle = layout === "grid" ? "" : (hasPositioning ? "position:relative;min-height:40em;" : "");

  function itemLabel(o) {
    return o.type === "label" ? o.text : o.fieldName;
  }
  function labelClass(o) {
    return o.type === "label" ? "label static-label" : "label field-label";
  }

  let contentHtml;
  if (orderedItems.length === 0) {
    contentHtml = '<div class="empty">No fields defined.</div>';
  } else if (layout === "stack") {
    contentHtml =
      '<div class="entry-view-stack" style="' + escapeHtml(containerPositionStyle) + '">' +
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const blockStyle = blockOrCellStyle(o);
          const styleAttr = blockStyle ? ' style="' + escapeHtml(blockStyle) + '"' : "";
          const labelOnlyClass = isLabel ? " entry-label-only" : "";
          const lc = labelClass(o);
          if (isLabel) {
            return `
        <div class="entry-field-block${labelOnlyClass}"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
        </div>`;
          }
          const value = record[o.fieldName] != null ? String(record[o.fieldName]) : "";
          return `
        <div class="entry-field-block"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="value">${editControlHtml(o, value)}</div>
        </div>`;
        })
        .join("") +
      "</div>";
  } else if (layout === "grid") {
    const widths = orderedItems.map((o) => o.width || "1fr").join(" ");
    contentHtml =
      `<div class="entry-view-grid" style="grid-template-columns: ${escapeHtml(widths)};${escapeHtml(containerPositionStyle)}">` +
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const cellStyle = gridCellStyle(o);
          const styleAttr = cellStyle ? ' style="' + escapeHtml(cellStyle) + '"' : "";
          const labelOnlyClass = isLabel ? " entry-label-only" : "";
          const lc = labelClass(o);
          if (isLabel) {
            return `
        <div class="entry-grid-cell${labelOnlyClass}"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
        </div>`;
          }
          const value = record[o.fieldName] != null ? String(record[o.fieldName]) : "";
          return `
        <div class="entry-grid-cell"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="value">${editControlHtml(o, value)}</div>
        </div>`;
        })
        .join("") +
      "</div>";
  } else {
    const rows = orderedItems
      .map((o) => {
        const isLabel = o.type === "label";
        const lc = labelClass(o);
        if (isLabel) {
          const w = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
          return `
        <tr class="entry-label-row">
          <td class="${lc}" colspan="2"${w}>${escapeHtml(itemLabel(o))}</td>
        </tr>`;
        }
        const value = record[o.fieldName] != null ? String(record[o.fieldName]) : "";
        const valueCellWidth = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
        return `
        <tr>
          <td class="${lc}">${escapeHtml(itemLabel(o))}</td>
          <td class="value"${valueCellWidth}>${editControlHtml(o, value)}</td>
        </tr>`;
      })
      .join("");
    contentHtml = `<table><tbody>${rows}</tbody></table>`;
  }

  const orderedFieldNamesJson = JSON.stringify(orderedFieldNames);
  const formChoicesHtml =
    Array.isArray(formChoices) && formChoices.length > 0
      ? '<span style="margin-left:1rem;font-size:0.875rem;">Form: <select id="entryFormSelect" name="entryFormId" style="padding:0.25rem 0.5rem;background:var(--entry-field-bg-edit,#161b22);border:1px solid #30363d;border-radius:4px;color:var(--entry-text-edit,#e6edf3);">' +
        formChoices
          .map(
            (f) =>
              `<option value="${escapeHtml(f._id)}"${
                currentFormId === f._id ? " selected" : ""
              }>${escapeHtml(f.name || f._id)}</option>`
          )
          .join("") +
        "</select></span>"
      : "";
  const formLabel = formDoc && (formDoc.name || formDoc._id) ? String(formDoc.name || formDoc._id) : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Edit entry</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--entry-bg, #0f1419); color: var(--entry-text, #e6edf3); max-width: 36rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--entry-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--entry-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.75rem 1rem; text-align: left; }
    .label { color: var(--entry-label, #8b949e); width: 40%; }
    td.value { background: var(--entry-field-bg-edit, #161b22); border-radius: 6px; }
    .entry-view-stack { --entry-stack-field-max-height: 12rem; }
    .entry-view-stack .entry-field-block { margin-bottom: 1rem; min-width: 0; max-width: 100%; }
    .entry-view-stack .entry-field-block .value {
      min-width: 0;
      background: var(--entry-field-bg-edit, #161b22);
      border-radius: 6px;
      padding: 0.75rem 1rem;
    }
    .entry-view-stack .label { display: block; margin-bottom: 0.25rem; }
    .entry-view-stack .entry-label-only .label { white-space: nowrap; }
    .entry-view-stack textarea.entry-field-textarea {
      min-height: 5.5rem;
      height: 11rem;
      max-height: 11rem;
      resize: vertical;
      overflow-y: auto;
      box-sizing: border-box;
    }
    .entry-view-grid { display: grid; gap: 1rem; }
    .entry-grid-cell { min-width: 0; }
    .entry-grid-cell .label { display: block; margin-bottom: 0.25rem; color: var(--entry-label, #8b949e); }
    .entry-grid-cell .value { min-width: 0; overflow: hidden; background: var(--entry-field-bg-edit, #161b22); border-radius: 6px; padding: 0.75rem 1rem; }
    .entry-grid-cell.entry-label-only .label { white-space: nowrap; }
    .entry-label-row .label { white-space: nowrap; }
    td.value { min-width: 0; overflow: hidden; }
    input.entry-field, textarea.entry-field { width: 100%; min-width: 0; max-width: 100%; padding: 0.5rem; background: var(--entry-field-bg-edit, #161b22); color: var(--entry-text-edit, #e6edf3); border: 1px solid transparent; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
    input.entry-field:focus, textarea.entry-field:focus { outline: none; border-color: var(--entry-link, #58a6ff); }
    textarea.entry-field-textarea { resize: vertical; min-height: 5.5rem; line-height: 1.35; white-space: pre-wrap; overflow-wrap: break-word; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; margin-top: 1rem; }
    .btn:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; text-decoration: none; }
    .btn-secondary:hover { background: #30363d; }
    .btn-delete { background: #da3633; color: #fff; }
    .btn-delete:hover { background: #f85149; }
    .empty { color: var(--entry-label, #8b949e); font-style: italic; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
  ${formCustomCss ? `<style>${formCustomCss}</style>` : ""}
</head>
<body>
  <div class="actions">
    <a href="${escapeHtml(backUrl)}">← Back to database</a>
    ${formChoicesHtml}
    <button type="submit" form="entry-form" class="btn" style="margin-left:1rem;">Save</button>
    <a href="${escapeHtml(backUrl)}" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
    <button type="button" class="btn btn-delete" id="delete-entry-btn" style="margin-left:0.5rem;">Delete</button>
  </div>
  <h1>${title}</h1>
  <p class="sub">Edit entry${formLabel ? ` – Form: ${escapeHtml(formLabel)}` : ""}</p>
  <form id="entry-form">
    <input type="hidden" id="rev" value="${rev}">
    ${contentHtml}
  <div id="msg"></div>
  <script>
    const profileId = ${JSON.stringify(profileId)};
    const entryId = ${JSON.stringify(entryId)};
    const orderedFieldNames = ${orderedFieldNamesJson};
    const entryFormSelect = document.getElementById('entryFormSelect');
    const form = document.getElementById('entry-form');
    const msgEl = document.getElementById('msg');
    function autoResizeTextarea(el) {
      if (!el) return;
      el.style.height = 'auto';
      el.style.height = Math.max(el.scrollHeight, 88) + 'px';
    }
    Array.from(form.querySelectorAll('textarea.entry-field-textarea')).forEach((el) => {
      if (el.closest('.entry-view-stack')) return;
      autoResizeTextarea(el);
      el.addEventListener('input', function() { autoResizeTextarea(el); });
    });

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const inputs = form.querySelectorAll('.entry-field');
      const data = { _rev: document.getElementById('rev').value };
      if (entryFormSelect) {
        data.entryFormId = entryFormSelect.value;
      }
      orderedFieldNames.forEach((fn, i) => { data[fn] = (inputs[i] && inputs[i].value) ? String(inputs[i].value).trim() : ''; });
      try {
        const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/entries/' + encodeURIComponent(entryId), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const result = await r.json();
        if (!r.ok) { msgEl.textContent = result.error || 'Failed'; msgEl.className = 'msg err'; return; }
        if (result.rev) document.getElementById('rev').value = result.rev;
        msgEl.textContent = 'Entry saved.';
        msgEl.className = 'msg ok';
        setTimeout(() => { window.location.href = ${JSON.stringify(backUrl)}; }, 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };

    const deleteBtn = document.getElementById('delete-entry-btn');
    if (deleteBtn) {
      deleteBtn.onclick = async () => {
        if (!confirm('Are you sure you want to delete this entry? This cannot be undone.')) return;
        deleteBtn.disabled = true;
        try {
          const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/entries/' + encodeURIComponent(entryId), { method: 'DELETE' });
          const result = await r.json();
          if (!r.ok) { msgEl.textContent = result.error || 'Delete failed'; msgEl.className = 'msg err'; deleteBtn.disabled = false; return; }
          window.location.href = ${JSON.stringify(backUrl)};
        } catch (err) {
          msgEl.textContent = err.message || 'Request failed';
          msgEl.className = 'msg err';
          deleteBtn.disabled = false;
        }
      };
    }
  </script>
</body>
</html>`;
}

function renderElenkoDatabasePage(doc, records, role, pagination = {}) {
  const canEdit = role === "admin" || role === "editor" || role === "user";
  const isAdmin = role === "admin";
  const title = escapeHtml(doc.name || "Elenko database");
  const description = escapeHtml(doc.description || "").replace(/\n/g, "<br>");
  const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const customCss = doc.customCss || "";
  const theme = normalizeProfileTheme(doc.theme);
  const { page = 1, totalPages = null, hasNext = false, hasPrev = false, searchQuery = "" } = pagination;
  const profileBase = "/profile/" + encodeURIComponent(doc._id);
  const qParam = searchQuery ? "&q=" + encodeURIComponent(searchQuery) : "";
  const prevUrl = hasPrev ? profileBase + "?page=" + (page - 1) + qParam : null;
  const nextUrl = hasNext ? profileBase + "?page=" + (page + 1) + qParam : null;
  const pageOfTotal = totalPages != null ? " of " + totalPages : "";
  const infoImportFlowId =
    typeof doc.infoImportFlowId === "string" && doc.infoImportFlowId.trim()
      ? doc.infoImportFlowId.trim()
      : (typeof doc.guardianFlowId === "string" && doc.guardianFlowId.trim() ? doc.guardianFlowId.trim() : "");
  const infoImportButtonTitle =
    typeof doc.infoImportButtonTitle === "string" && doc.infoImportButtonTitle.trim()
      ? doc.infoImportButtonTitle.trim()
      : "Import from Guardian";

  const maxMobileListFields = 3;
  const rawMobileListFields = Array.isArray(doc.listFields) ? doc.listFields : [];
  const mobileListFields =
    rawMobileListFields
      .filter((f) => typeof f === "string" && f.trim())
      .map((f) => f.trim())
      .filter((f) => fieldNames.includes(f))
      .slice(0, maxMobileListFields);
  const effectiveMobileListFields =
    mobileListFields.length > 0
      ? mobileListFields
      : fieldNames.slice(0, maxMobileListFields);
  const mobileVisibleSet = new Set(effectiveMobileListFields);
  let colMeta = computeFieldDisplayForTable(fieldNames, doc.fieldDisplay);
  if (fieldNames.length > 0 && colMeta.length === fieldNames.length && colMeta.every((m) => m.desktopHidden)) {
    colMeta = fieldNames.map(() => ({ desktopHidden: false, widthMode: "auto", widthStyle: "" }));
  }
  /** First non–desktop-hidden field — link target on wide layout. */
  let desktopLinkField = null;
  for (let i = 0; i < fieldNames.length; i++) {
    if (colMeta[i] && !colMeta[i].desktopHidden) {
      desktopLinkField = fieldNames[i];
      break;
    }
  }
  /** First field in the mobile list — link target on narrow layout (must work when it is not profile field #1). */
  const mobileLinkField =
    effectiveMobileListFields.length > 0 ? effectiveMobileListFields[0] : desktopLinkField;

  const themeVars = `
    :root {
      --profile-bg: ${escapeHtml(theme.background)};
      --profile-text: ${escapeHtml(theme.text)};
      --profile-label: ${escapeHtml(theme.label)};
      --profile-link: ${escapeHtml(theme.link)};
      --profile-table-bg: ${escapeHtml(theme.tableBg)};
      --profile-table-header-bg: ${escapeHtml(theme.tableHeaderBg)};
      --profile-table-header-text: ${escapeHtml(theme.tableHeaderText)};
      --profile-table-border: ${escapeHtml(theme.tableBorder)};
    }`;

  const headerRow =
    fieldNames.length > 0
      ? `<tr>${fieldNames
          .map((f, idx) => {
            const bodyTextCls = (typeof f === "string" && f.trim().toLowerCase() === "bodytext") ? " col-bodytext" : "";
            const mobileCls = (mobileVisibleSet.has(f) ? "col col-mobile-visible" : "col col-mobile-hidden") + bodyTextCls;
            const m = colMeta[idx] || { desktopHidden: false, widthMode: "auto", widthStyle: "" };
            const deskCls = m.desktopHidden ? " col-desktop-hidden" : "";
            const dispCls = m.desktopHidden ? "" : m.widthMode === "pct" ? " col-disp-pct" : " col-disp-auto";
            const styleAttr = !m.desktopHidden && m.widthStyle ? ` style="${escapeHtml(m.widthStyle)}"` : "";
            return `<th class="${mobileCls}${deskCls}${dispCls}"${styleAttr}>${escapeHtml(f)}</th>`;
          })
          .join("")}</tr>`
      : "<tr><th>—</th></tr>";

  const returnQuery = [];
    if (page > 1) returnQuery.push("page=" + encodeURIComponent(String(page)));
    if (searchQuery) returnQuery.push("q=" + encodeURIComponent(searchQuery));
    const returnQueryStr = returnQuery.length > 0 ? "?" + returnQuery.join("&") : "";

  const dataRows =
    fieldNames.length > 0
      ? records.map((rec) => {
          const cells = fieldNames.map((fn, colIdx) => {
            const val = rec[fn];
            const text = val != null ? String(val) : "";
            const escaped = escapeHtml(text);
            const bodyTextCls = (typeof fn === "string" && fn.trim().toLowerCase() === "bodytext") ? " col-bodytext" : "";
            const mobileCls = (mobileVisibleSet.has(fn) ? " col-mobile-visible" : " col-mobile-hidden") + bodyTextCls;
            const m = colMeta[colIdx] || { desktopHidden: false, widthMode: "auto", widthStyle: "" };
            const deskCls = m.desktopHidden ? " col-desktop-hidden" : "";
            const dispCls = m.desktopHidden ? "" : m.widthMode === "pct" ? " col-disp-pct" : " col-disp-auto";
            const styleAttr = !m.desktopHidden && m.widthStyle ? ` style="${escapeHtml(m.widthStyle)}"` : "";
            const entryUrl = "/profile/" + encodeURIComponent(doc._id) + "/entry/" + encodeURIComponent(rec._id) + returnQueryStr;
            const linkText = text.trim().length > 0 ? escaped : "empty";
            const isDesktopLink = desktopLinkField != null && fn === desktopLinkField;
            const isMobileLink = mobileLinkField != null && fn === mobileLinkField;

            if (isDesktopLink && isMobileLink) {
              return `<td class="entry-link-cell${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp"><a href="${entryUrl}">${linkText}</a></span></td>`;
            }
            if (isDesktopLink && !isMobileLink) {
              return `<td class="entry-link-cell${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp"><span class="entry-link-desktop-only"><a href="${entryUrl}">${linkText}</a></span><span class="entry-plain-mobile-only">${escaped}</span></span></td>`;
            }
            if (!isDesktopLink && isMobileLink) {
              return `<td class="entry-link-cell${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp"><span class="entry-plain-desktop-only">${escaped}</span><span class="entry-link-mobile-only"><a href="${entryUrl}">${linkText}</a></span></span></td>`;
            }
            return `<td class="${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp">${escaped}</span></td>`;
          });
          return `\n        <tr>${cells.join("")}</tr>`;
        })
      : [];

  const emptyRow =
    fieldNames.length > 0 && records.length === 0
      ? '\n        <tr><td colspan="' + fieldNames.length + '" class="empty">' + (searchQuery ? "No entries match your search." : "No entries yet.") + "</td></tr>"
      : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--profile-bg, #0f1419); color: var(--profile-text, #e6edf3); min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--profile-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--profile-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.35rem 0.75rem; border-radius: 6px; text-decoration: none; font-size: 0.9rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    table.elenko-db-table { width: 100%; border-collapse: collapse; background: var(--profile-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.35rem 1rem; text-align: left; border-bottom: 1px solid var(--profile-table-border, #21262d); line-height: 1.35; }
    th { background: var(--profile-table-header-bg, #21262d); color: var(--profile-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .entry-cell-clamp { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; word-break: break-word; }
    .entry-link-cell a { color: var(--profile-link, #58a6ff); text-decoration: none; }
    .entry-link-cell a:hover { text-decoration: underline; }
    .empty { color: var(--profile-label, #8b949e); font-style: italic; }
    .search-bar { margin-bottom: 1rem; display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .search-bar input[type="search"] { padding: 0.5rem 0.75rem; background: var(--profile-table-bg, #161b22); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; color: var(--profile-text, #e6edf3); font-size: 1rem; min-width: 12rem; }
    .search-bar input[type="search"]:focus { outline: none; border-color: var(--profile-link, #58a6ff); }
    .search-bar .btn-search { padding: 0.5rem 0.75rem; background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
    .search-bar .btn-search:hover { background: #30363d; }
    .search-bar .btn-clear { padding: 0.5rem 0.75rem; background: transparent; color: var(--profile-label, #8b949e); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .search-bar .btn-clear:hover { background: #30363d; color: var(--profile-text, #e6edf3); }
    .pagination { margin-bottom: 1rem; display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
    .pagination .btn-pag { display: inline-block; padding: 0.5rem 0.75rem; border-radius: 6px; text-decoration: none; font-size: 0.875rem; }
    .pagination .btn-pag-prev, .pagination .btn-pag-next { background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); }
    .pagination .btn-pag-prev:hover, .pagination .btn-pag-next:hover { background: #30363d; }
    .pagination .btn-pag.disabled { color: #484f58; pointer-events: none; }
    .pagination .page-num { color: var(--profile-label, #8b949e); font-size: 0.875rem; }
    th.col-bodytext, td.col-bodytext { max-width: 50vw; width: 50%; }
    th.col-bodytext.col-disp-pct, td.col-bodytext.col-disp-pct { max-width: none; }
    .guardian-import { margin: 0 0 1rem 0; display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
    .guardian-import input[type="text"] { padding: 0.5rem 0.75rem; background: var(--profile-table-bg, #161b22); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; color: var(--profile-text, #e6edf3); font-size: 1rem; min-width: 12rem; max-width: 100%; box-sizing: border-box; }
    @media (min-width: 769px) {
      .guardian-import input[type="text"] { min-width: 36rem; flex: 1 1 36rem; max-width: min(100%, 48rem); }
    }
    .guardian-import button { padding: 0.4rem 0.75rem; background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
    .guardian-import button:hover { background: #30363d; }
    .guardian-import .guardian-msg { font-size: 0.875rem; color: var(--profile-label, #8b949e); }
    .guardian-import .guardian-msg.err { color: #f85149; }
    .guardian-import .guardian-msg.ok { color: #3fb950; }
    .entry-plain-mobile-only,
    .entry-link-mobile-only { display: none; }
    @media (min-width: 769px) {
      table.elenko-db-table { table-layout: fixed; }
      th.col-desktop-hidden, td.col-desktop-hidden { display: none !important; }
      th.col-disp-auto, td.col-disp-auto { width: auto; min-width: 2.5rem; }
      th.col-bodytext.col-disp-auto, td.col-bodytext.col-disp-auto { width: auto; max-width: none; }
    }
    @media (max-width: 768px) {
      table { font-size: 0.9rem; }
      th.col-mobile-hidden,
      td.col-mobile-hidden { display: none; }
      .entry-link-desktop-only { display: none; }
      .entry-plain-mobile-only { display: inline; }
      .entry-plain-desktop-only { display: none; }
      .entry-link-mobile-only { display: inline; }
      th.col-desktop-hidden, td.col-desktop-hidden { display: table-cell !important; }
    }
  </style>
  ${customCss ? `<style>${customCss}</style>` : ""}
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a>${canEdit ? (isAdmin ? `<a href="/profile/${encodeURIComponent(doc._id)}/edit">Edit profile</a>` : "") + `<a href="/profile/${encodeURIComponent(doc._id)}/entry/new" class="btn">Create entry</a>` : ""}</div>
  ${canEdit && infoImportFlowId ? `<form id="info-import-form" class="guardian-import"><label for="info-import-query" style="margin:0;color:var(--profile-label, #8b949e);">Query:</label><input type="text" id="info-import-query" placeholder="e.g. renewable energy"><button type="submit">${escapeHtml(infoImportButtonTitle)}</button><span id="info-import-msg" class="guardian-msg"></span></form>` : ""}
  <h1>${title}</h1>
  ${description ? `<p class="sub">${description}</p>` : ""}
  <form method="get" action="${profileBase}" class="search-bar">
    <input type="search" name="q" value="${escapeHtml(searchQuery)}" placeholder="Search entries…" aria-label="Search entries">
    <input type="hidden" name="page" value="1">
    <button type="submit" class="btn-search">Search</button>
    ${searchQuery ? `<a href="${profileBase}?clearSearch=1" class="btn-clear">Clear</a>` : ""}
  </form>
  <div class="pagination">
    ${hasPrev ? `<a href="${prevUrl}" class="btn-pag btn-pag-prev">← Previous</a>` : `<span class="btn-pag btn-pag-prev disabled">← Previous</span>`}
    <span class="page-num">Page ${escapeHtml(String(page))}${escapeHtml(pageOfTotal)}</span>
    ${hasNext ? `<a href="${nextUrl}" class="btn-pag btn-pag-next">Next →</a>` : `<span class="btn-pag btn-pag-next disabled">Next →</span>`}
  </div>
  <table class="elenko-db-table">
    <thead>${headerRow}</thead>
    <tbody>${dataRows.join("")}${emptyRow}
    </tbody>
  </table>
  ${canEdit && infoImportFlowId ? `<script>
    (function() {
      var form = document.getElementById('info-import-form');
      if (!form) return;
      var input = document.getElementById('info-import-query');
      var msg = document.getElementById('info-import-msg');
      var flowId = ${JSON.stringify(infoImportFlowId)};
      form.addEventListener('submit', async function(ev) {
        ev.preventDefault();
        var query = input && input.value ? input.value.trim() : '';
        if (!query) {
          if (msg) { msg.textContent = 'Please enter a query.'; msg.className = 'guardian-msg err'; }
          return;
        }
        var btn = form.querySelector('button[type="submit"]');
        if (btn) btn.disabled = true;
        if (msg) { msg.textContent = 'Import running...'; msg.className = 'guardian-msg'; }
        try {
          var r = await fetch('/api/profile/' + encodeURIComponent(${JSON.stringify(doc._id)}) + '/run-flow', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ flowId: flowId, query: query })
          });
          var data = await r.json();
          if (!r.ok) {
            if (msg) { msg.textContent = data.error || 'Import failed'; msg.className = 'guardian-msg err'; }
            if (btn) btn.disabled = false;
            return;
          }
          if (msg) { msg.textContent = (typeof data.created === 'number' ? ('Imported: ' + data.created + ' entries.') : 'Import done.'); msg.className = 'guardian-msg ok'; }
          setTimeout(function() { window.location.reload(); }, 700);
        } catch (err) {
          if (msg) { msg.textContent = (err && err.message) ? err.message : 'Request failed'; msg.className = 'guardian-msg err'; }
          if (btn) btn.disabled = false;
        }
      });
    })();
  </script>` : ""}
</body>
</html>`;
}

function renderDeletionsPage(batches, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const batchRows =
    batches.length > 0
      ? batches
          .map((b) => {
            const profileName = escapeHtml(b.profileName || "Profile");
            const entries = Array.isArray(b.entries) ? b.entries : [];
            const count = entries.length;
            const idList = entries.map((e) => escapeHtml(e.id)).join(", ");
            const executeUrl = "/api/deletions/" + encodeURIComponent(b._id) + "/execute";
            return `
    <div class="batch">
      <p class="batch-title"><strong>${profileName}</strong> — ${count} document(s) marked for deletion</p>
      <p class="batch-ids">${idList || "—"}</p>
      <button type="button" class="btn btn-danger batch-delete" data-url="${escapeHtml(executeUrl)}">Delete all</button>
    </div>`;
          })
          .join("")
      : `<p class="empty">No documents marked for deletion.</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Marked for deletion</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .batch { background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #21262d); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
    .batch-title { margin: 0 0 0.5rem 0; }
    .batch-ids { font-size: 0.875rem; color: var(--app-label, #8b949e); word-break: break-all; margin: 0 0 0.75rem 0; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-danger { background: #da3633; color: #fff; }
    .btn-danger:hover { background: #f85149; }
    .btn-danger:disabled { opacity: 0.6; cursor: not-allowed; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a></div>
  <h1>Marked for deletion</h1>
  <p class="sub">Documents marked when deleting a profile. Delete them permanently below.</p>
  ${batchRows}
  <div id="msg"></div>
  <script>
    document.querySelectorAll('.batch-delete').forEach(btn => {
      btn.onclick = async () => {
        const url = btn.getAttribute('data-url');
        btn.disabled = true;
        const msgEl = document.getElementById('msg');
        msgEl.textContent = '';
        msgEl.className = 'msg';
        try {
          const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
          const result = await r.json();
          if (!r.ok) { msgEl.textContent = result.error || 'Failed'; msgEl.className = 'msg err'; btn.disabled = false; return; }
          msgEl.textContent = 'Deleted.';
          msgEl.className = 'msg ok';
          setTimeout(() => window.location.reload(), 600);
        } catch (err) {
          msgEl.textContent = err.message || 'Request failed';
          msgEl.className = 'msg err';
          btn.disabled = false;
        }
      };
    });
  </script>
</body>
</html>`;
}

function renderEntryFormsListPage(forms, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const rows =
    forms.length > 0
      ? forms
          .map(
            (f) => `
        <tr>
          <td>${escapeHtml(f.name || f._id)}</td>
          <td class="row-actions"><a href="/entry-forms/${encodeURIComponent(f._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="copy-btn icon-action" data-id="${escapeHtml(f._id)}" aria-label="Copy" title="Copy">⧉</button><a href="/entry-forms/${encodeURIComponent(f._id)}/delete" class="delete-link icon-action" aria-label="Delete" title="Delete">✕</a></td>
        </tr>`
          )
          .join("")
      : `
        <tr>
          <td colspan="2" class="empty">No entry forms yet. Create one to customize single-entry view (colours and layout).</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Entry forms</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .row-actions { white-space: nowrap; }
    .row-actions .icon-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 2rem;
      min-height: 2rem;
      margin: 0 0.15rem;
      padding: 0.2rem 0.35rem;
      font-size: 1.15rem;
      line-height: 1;
      vertical-align: middle;
      text-decoration: none;
      border-radius: 4px;
    }
    .row-actions .icon-action:focus { outline: 2px solid var(--app-link, #58a6ff); outline-offset: 2px; }
    .edit-link { color: var(--app-link, #58a6ff); }
    .edit-link:hover { background: rgba(88, 166, 255, 0.12); }
    .copy-btn {
      border: none;
      background: none;
      color: var(--app-label, #8b949e);
      font: inherit;
      cursor: pointer;
    }
    .copy-btn:hover { color: var(--app-link, #58a6ff); background: rgba(88, 166, 255, 0.08); }
    .copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .delete-link { color: #f85149; }
    .delete-link:hover { color: #ff7b72; background: rgba(248, 81, 73, 0.12); }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a><a href="/entry-forms/create" class="btn">Create Single Entry form</a></div>
  <h1>Entry forms</h1>
  <p class="sub">Configure how a single database entry is displayed (colours and field layout). Assign a form to a profile on the profile edit page.</p>
  <table>
    <thead><tr><th>Name</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="copy-msg" class="copy-msg" style="display:none;margin-top:0.75rem;font-size:0.875rem;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('copy-msg');
      document.querySelectorAll('.copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          if (!id) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/entry-forms/' + encodeURIComponent(id) + '/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok && o.data && o.data.id) {
                window.location.href = '/entry-forms/' + encodeURIComponent(o.data.id) + '/edit';
                return;
              }
              if (msgEl) {
                msgEl.style.display = 'block';
                msgEl.style.color = '#f85149';
                msgEl.textContent = (o.data && o.data.error) ? o.data.error : 'Copy failed';
              }
            })
            .catch(function(e) {
              btn.disabled = false;
              if (msgEl) {
                msgEl.style.display = 'block';
                msgEl.style.color = '#f85149';
                msgEl.textContent = e.message || 'Copy failed';
              }
            });
        });
      });
    })();
  </script>
</body>
</html>`;
}

function renderDeleteEntryFormPage(doc, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const name = escapeHtml(doc.name || doc._id);
  const rev = escapeHtml(doc._rev || "");
  const id = doc._id;
  const deleteUrl = "/api/entry-forms/" + encodeURIComponent(id) + "/delete";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Delete entry form</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 32rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .warning { background: #3d1f1f; color: #f85149; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; margin-right: 0.5rem; margin-top: 0.5rem; }
    .btn-danger { background: #da3633; color: #fff; }
    .btn-danger:hover { background: #f85149; }
    .btn-secondary { background: #21262d; color: #e6edf3; }
    .btn-secondary:hover { background: #30363d; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
  </style>
</head>
<body>
  <div class="actions"><a href="/entry-forms">← Entry forms</a></div>
  <h1>Delete entry form</h1>
  <p class="sub">Really delete this entry form?</p>
  <p><strong>${name}</strong></p>
  <p class="warning">This will remove the entry form document. Profiles that reference it may need to be updated.</p>
  <form id="delete-form">
    <input type="hidden" id="rev" value="${rev}">
    <button type="submit" class="btn btn-danger">Yes, delete</button>
    <a href="/entry-forms" class="btn btn-secondary">Cancel</a>
  </form>
  <div id="msg"></div>
  <script>
    var form = document.getElementById('delete-form');
    var msgEl = document.getElementById('msg');
    form.onsubmit = async function(e) {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      var _rev = document.getElementById('rev').value;
      try {
        var r = await fetch(${JSON.stringify(deleteUrl)}, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ _rev })
        });
        var result = await r.json();
        if (!r.ok) { msgEl.textContent = result.error || 'Delete failed'; msgEl.className = 'msg err'; return; }
        window.location.href = result.redirect || '/entry-forms';
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderFlowsListPage(flows, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const truncate = (s, max) => (s && s.length > max ? s.slice(0, max) + "…" : s || "");
  const stepSummary = (steps) => {
    if (!Array.isArray(steps) || steps.length === 0) return "—";
    return steps.map((s) => s.target).join(" → ");
  };
  const rows =
    flows.length > 0
      ? flows
          .map(
            (f) => `
        <tr>
          <td><a href="/flows/${encodeURIComponent(f._id)}/edit">${escapeHtml(f.name || f._id)}</a></td>
          <td><code class="id-cell">${escapeHtml(f._id || "")}</code></td>
          <td>${escapeHtml(truncate(f.description || "", 50))}</td>
          <td>${escapeHtml(stepSummary(f.steps))}</td>
          <td class="row-actions"><a href="/flows/${encodeURIComponent(f._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="copy-btn icon-action flow-copy-btn" data-id="${escapeHtml(f._id)}" aria-label="Copy" title="Copy">⧉</button><button type="button" class="delete-btn icon-action delete-flow-btn" data-id="${escapeHtml(f._id)}" data-rev="${escapeHtml(f._rev || "")}" aria-label="Delete" title="Delete">✕</button></td>
        </tr>`
          )
          .join("")
      : `
        <tr>
          <td colspan="5" class="empty">No flows yet. Create one to chain steps (log → API → local DB) and attach it to an entry form.</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Flows</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 56rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .row-actions { white-space: nowrap; }
    .row-actions .icon-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 2rem;
      min-height: 2rem;
      margin: 0 0.15rem;
      padding: 0.2rem 0.35rem;
      font-size: 1.15rem;
      line-height: 1;
      vertical-align: middle;
      text-decoration: none;
      border-radius: 4px;
    }
    .row-actions .icon-action:focus { outline: 2px solid var(--app-link, #58a6ff); outline-offset: 2px; }
    .edit-link { color: var(--app-link, #58a6ff); }
    .edit-link:hover { background: rgba(88, 166, 255, 0.12); }
    .copy-btn {
      border: none;
      background: none;
      color: var(--app-label, #8b949e);
      font: inherit;
      cursor: pointer;
    }
    .copy-btn:hover { color: var(--app-link, #58a6ff); background: rgba(88, 166, 255, 0.08); }
    .copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .delete-btn {
      border: none;
      background: none;
      color: #f85149;
      font: inherit;
      cursor: pointer;
      padding: 0.2rem 0.35rem;
    }
    .delete-btn:hover { color: #ff7b72; background: rgba(248, 81, 73, 0.12); }
    .delete-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .id-cell { font-size: 0.85em; color: var(--app-label, #8b949e); word-break: break-all; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Start</a><a href="/flows/create" class="btn">Create Flow</a></div>
  <h1>Flows</h1>
  <p class="sub">Multi-step pipelines: log (passthrough), Call API, Send to Local Database. Steps run in order; each step receives the previous step&apos;s output. Use a Flow in an entry form by selecting it in the flow configuration.</p>
  <table>
    <thead><tr><th>Name</th><th>ID</th><th>Description</th><th>Steps</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="flow-list-msg" class="flow-list-msg" style="display:none;margin-top:0.75rem;font-size:0.875rem;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('flow-list-msg');
      function showErr(t) {
        if (!msgEl) return;
        msgEl.style.display = 'block';
        msgEl.style.color = '#f85149';
        msgEl.textContent = t || 'Request failed';
      }
      document.querySelectorAll('.flow-copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          if (!id) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/flows/' + encodeURIComponent(id) + '/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok && o.data && o.data.id) {
                window.location.href = '/flows/' + encodeURIComponent(o.data.id) + '/edit';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Copy failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Copy failed');
            });
        });
      });
      document.querySelectorAll('.delete-flow-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          var rev = btn.getAttribute('data-rev');
          if (!id || !rev) { showErr('Missing revision; refresh the page.'); return; }
          if (!confirm('Delete this flow? Profiles or forms that reference it may need to be updated.')) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/flows/' + encodeURIComponent(id) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev: rev })
          })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok) {
                window.location.href = o.data.redirect || '/flows';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Delete failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Delete failed');
            });
        });
      });
    })();
  </script>
</body>
</html>`;
}

function renderProfilesListPage(profiles, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const truncate = (s, max) => (s && s.length > max ? s.slice(0, max) + "…" : s || "");
  const rows =
    profiles.length > 0
      ? profiles
          .map((p) => {
            const createdDate = p.createdAt ? formatDateOnly(p.createdAt) : "—";
            return `
        <tr>
          <td><a href="/profile/${encodeURIComponent(p._id)}/edit">${escapeHtml(p.name || p._id)}</a></td>
          <td>${escapeHtml(truncate(p.description || "", 80))}</td>
          <td>${escapeHtml(createdDate)}</td>
          <td class="row-actions"><a href="/profile/${encodeURIComponent(p._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="copy-btn icon-action profile-copy-btn" data-id="${escapeHtml(p._id)}" aria-label="Copy" title="Copy">⧉</button><button type="button" class="delete-btn icon-action delete-profile-btn" data-id="${escapeHtml(p._id)}" data-rev="${escapeHtml(p._rev || "")}" aria-label="Delete" title="Delete">✕</button></td>
        </tr>`;
          })
          .join("")
      : `
        <tr>
          <td colspan="4" class="empty">No Elenko database profiles yet. <a href="/profile/create">Create one</a>.</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Elenko profiles</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 56rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .row-actions { white-space: nowrap; }
    .row-actions .icon-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 2rem;
      min-height: 2rem;
      margin: 0 0.15rem;
      padding: 0.2rem 0.35rem;
      font-size: 1.15rem;
      line-height: 1;
      vertical-align: middle;
      text-decoration: none;
      border-radius: 4px;
    }
    .row-actions .icon-action:focus { outline: 2px solid var(--app-link, #58a6ff); outline-offset: 2px; }
    .edit-link { color: var(--app-link, #58a6ff); }
    .edit-link:hover { background: rgba(88, 166, 255, 0.12); }
    .copy-btn {
      border: none;
      background: none;
      color: var(--app-label, #8b949e);
      font: inherit;
      cursor: pointer;
    }
    .copy-btn:hover { color: var(--app-link, #58a6ff); background: rgba(88, 166, 255, 0.08); }
    .copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .delete-btn {
      border: none;
      background: none;
      color: #f85149;
      font: inherit;
      cursor: pointer;
      padding: 0.2rem 0.35rem;
    }
    .delete-btn:hover { color: #ff7b72; background: rgba(248, 81, 73, 0.12); }
    .delete-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .empty a { color: var(--app-link, #58a6ff); }
    #profiles-list-msg { margin-top: 0.75rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Start</a><a href="/profile/create" class="btn">Create Elenko database</a></div>
  <h1>Elenko profiles</h1>
  <p class="sub">All database profiles. Name opens the profile edit page (not the entry list). Use ⧉ to duplicate a profile (entries are not copied).</p>
  <table>
    <thead><tr><th>Name</th><th>Description</th><th>Creation date</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="profiles-list-msg" style="display:none;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('profiles-list-msg');
      function showErr(t) {
        if (!msgEl) return;
        msgEl.style.display = 'block';
        msgEl.style.color = '#f85149';
        msgEl.textContent = t || 'Request failed';
      }
      document.querySelectorAll('.profile-copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          if (!id) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/profiles/' + encodeURIComponent(id) + '/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok && o.data && o.data.id) {
                window.location.href = '/profile/' + encodeURIComponent(o.data.id) + '/edit';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Copy failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Copy failed');
            });
        });
      });
      document.querySelectorAll('.delete-profile-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          var rev = btn.getAttribute('data-rev');
          if (!id || !rev) { showErr('Missing revision; refresh the page.'); return; }
          if (!confirm('Delete this Elenko profile? Entries will be removed or listed under Marked for deletion if you confirm there.')) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/profiles/' + encodeURIComponent(id) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev: rev })
          })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok) {
                var red = o.data && o.data.redirect;
                if (red === '/deletions') window.location.href = '/deletions';
                else window.location.href = '/profiles';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Delete failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Delete failed');
            });
        });
      });
    })();
  </script>
</body>
</html>`;
}

function renderEditFlowPage(doc, err, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : "";
  const descVal = doc && typeof doc.description === "string" ? escapeHtml(doc.description) : "";
  const steps = Array.isArray(doc && doc.steps) && doc.steps.length > 0 ? doc.steps : [{ target: "log", param: "", label: "Log" }];
  const revInput = doc && doc._rev ? `<input type="hidden" id="rev" value="${escapeHtml(doc._rev)}">` : "";
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit Flow" : "Create Flow";
  const submitLabel = isEdit ? "Save" : "Create";
  const stepsJsonSafe = JSON.stringify(steps).replace(/<\//g, "<\\/");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 48rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="number"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    select { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .flow-steps-table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    .flow-steps-table th, .flow-steps-table td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    .flow-steps-table th { color: var(--app-table-header-text, #8b949e); font-weight: 600; font-size: 0.875rem; }
    .flow-steps-table select { min-width: 10rem; margin: 0; }
    .flow-steps-table input { margin: 0; }
    .msg.err { background: #3d1f1f; color: #f85149; padding: 0.5rem; border-radius: 6px; margin: 1rem 0; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/flows">← Flows</a>
    <button type="submit" form="flow-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/flows" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>${title}</h1>
  <p class="sub">Steps run in order. Log = passthrough (data unchanged, written to flow log). API and Local DB use the Param column (API doc ID or profile ID).</p>
  <p class="sub" style="margin-top:0.5rem; padding:0.5rem; background:var(--app-table-bg, #161b22); border-radius:6px; border-left:3px solid var(--app-link, #58a6ff);"><strong>Persistence:</strong> The flow writes to the database only when it includes one of: <em>Send to Local DB</em>, <em>Update current document</em>, or <em>Create new document in this profile</em>. If none of these steps are present, the result is not saved (&quot;fire and forget&quot;). Adding or removing a Log step does not change this — logging is neutral.</p>
  ${errHtml}
  <form id="flow-form">
    ${revInput}
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="e.g. Mistral then save" value="${nameVal}">
    <label for="description">Description</label>
    <input type="text" id="description" name="description" placeholder="Optional" value="${descVal}">
    <label style="margin-top:1.5rem;">Steps</label>
    <table class="flow-steps-table">
      <thead><tr><th>#</th><th>Target</th><th>Label</th><th>Param (API id or Profile id)</th><th></th></tr></thead>
      <tbody id="flow-steps-tbody"></tbody>
    </table>
    <button type="button" id="add-step" class="btn btn-secondary" style="margin-top:0.5rem;">+ Add step</button>
  </form>
  <script type="application/json" id="initial-steps-json">${stepsJsonSafe}</script>
  <script>
    const tbody = document.getElementById('flow-steps-tbody');
    const addBtn = document.getElementById('add-step');
    const formEl = document.getElementById('flow-form');
    let initialSteps;
    try {
      var dataEl = document.getElementById('initial-steps-json');
      initialSteps = dataEl && dataEl.textContent ? JSON.parse(dataEl.textContent) : [{ target: 'log', param: '', label: 'Log' }];
    } catch (e) {
      initialSteps = [{ target: 'log', param: '', label: 'Log' }];
    }
    if (!Array.isArray(initialSteps) || initialSteps.length === 0) initialSteps = [{ target: 'log', param: '', label: 'Log' }];
    function addStepRow(step) {
      if (!tbody) return;
      const tr = document.createElement('tr');
      tr.className = 'flow-step-row';
      const target =
        (step && step.target === 'localDb')
          ? 'localDb'
          : (step && step.target === 'api')
          ? 'api'
          : (step && step.target === 'script')
          ? 'script'
          : (step && step.target === 'update')
          ? 'update'
          : (step && step.target === 'create')
          ? 'create'
          : 'log';
      const label = (step && step.label != null) ? String(step.label).replace(/"/g, '&quot;') : '';
      const param = (step && step.param != null) ? String(step.param).replace(/"/g, '&quot;') : '';
      const paramPlaceholder =
        target === 'script'
          ? 'JS Processing doc id or name'
          : target === 'api'
          ? 'API id or name'
          : target === 'localDb'
          ? 'Profile id or name'
          : target === 'update'
          ? 'Not used'
          : target === 'create'
          ? 'Not used'
          : '—';
      tr.innerHTML =
        '<td class="step-num"></td>' +
        '<td><select class="step-target">' +
        '<option value="log"' + (target === 'log' ? ' selected' : '') + '>Log (passthrough)</option>' +
        '<option value="api"' + (target === 'api' ? ' selected' : '') + '>Call API</option>' +
        '<option value="localDb"' + (target === 'localDb' ? ' selected' : '') + '>Send to Local DB</option>' +
        '<option value="script"' + (target === 'script' ? ' selected' : '') + '>Run script (JS Processing)</option>' +
        '<option value="update"' + (target === 'update' ? ' selected' : '') + '>Update current document</option>' +
        '<option value="create"' + (target === 'create' ? ' selected' : '') + '>Create new document in this profile</option>' +
        '</select></td>' +
        '<td><input type="text" class="step-label" placeholder="Step label" value="' + label + '"></td>' +
        '<td><input type="text" class="step-param" placeholder="' + paramPlaceholder + '" value="' + param + '"></td>' +
        '<td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      const removeBtn = tr.querySelector('.btn-remove');
      if (removeBtn) removeBtn.onclick = function() { tr.remove(); updateStepNums(); };
      const stepTarget = tr.querySelector('.step-target');
      const stepParam = tr.querySelector('.step-param');
      if (stepTarget && stepParam) {
        stepTarget.addEventListener('change', function() {
          if (this.value === 'script') {
            stepParam.placeholder = 'JS Processing doc id or name';
          } else if (this.value === 'api') {
            stepParam.placeholder = 'API id or name';
          } else if (this.value === 'localDb') {
            stepParam.placeholder = 'Profile id or name';
          } else if (this.value === 'update') {
            stepParam.placeholder = 'Not used';
          } else if (this.value === 'create') {
            stepParam.placeholder = 'Not used';
          } else {
            stepParam.placeholder = '—';
          }
        });
      }
      tbody.appendChild(tr);
      updateStepNums();
    }
    function updateStepNums() {
      tbody.querySelectorAll('.flow-step-row').forEach((tr, i) => {
        const td = tr.querySelector('.step-num');
        if (td) td.textContent = i + 1;
      });
    }
    (Array.isArray(initialSteps) && initialSteps.length ? initialSteps : [{ target: 'log', param: '', label: 'Log' }]).forEach(s => addStepRow(s));
    if (addBtn) addBtn.onclick = function() { addStepRow({ target: 'log', param: '', label: '' }); };
    if (formEl) formEl.onsubmit = async (e) => {
      e.preventDefault();
      const name = document.getElementById('name').value.trim();
      if (!name) { alert('Name is required.'); return; }
      const description = document.getElementById('description').value.trim();
      const steps = (tbody ? Array.from(tbody.querySelectorAll('.flow-step-row')) : []).map((tr, i) => ({
        target: (tr.querySelector('.step-target') && tr.querySelector('.step-target').value) || 'log',
        label: (tr.querySelector('.step-label') && tr.querySelector('.step-label').value.trim()) || '',
        param: (tr.querySelector('.step-param') && tr.querySelector('.step-param').value.trim()) || ''
      }));
      const url = ${isEdit ? JSON.stringify("/api/flows/" + encodeURIComponent(doc._id)) : '"/api/flows"'};
      const method = ${isEdit ? '"PUT"' : '"POST"'};
      const body = { name, description, steps };
      if (${isEdit ? "true" : "false"}) body._rev = document.getElementById('rev').value;
      try {
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await r.json();
        if (!r.ok) { alert(data.error || 'Failed'); return; }
        window.location.href = '/flows';
      } catch (err) {
        alert(err.message || 'Request failed');
      }
    };
  </script>
</body>
</html>`;
}

function renderJsProcessingListPage(list, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const truncate = (s, max) => (s && s.length > max ? s.slice(0, max) + "…" : s || "");
  const rows =
    list.length > 0
      ? list
          .map(
            (d) => `
        <tr>
          <td><a href="/js-processing/${encodeURIComponent(d._id)}/edit">${escapeHtml(d.name || d._id)}</a></td>
          <td><code class="id-cell">${escapeHtml(d._id || "")}</code></td>
          <td>${escapeHtml(truncate(d.description || "", 50))}</td>
          <td>${escapeHtml(String(d.timeout != null ? d.timeout : 5000))} ms</td>
          <td class="row-actions"><a href="/js-processing/${encodeURIComponent(d._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="copy-btn icon-action js-copy-btn" data-id="${escapeHtml(d._id)}" aria-label="Copy" title="Copy">⧉</button><button type="button" class="delete-btn icon-action delete-js-btn" data-id="${escapeHtml(d._id)}" data-rev="${escapeHtml(d._rev || "")}" aria-label="Delete" title="Delete">✕</button></td>
        </tr>`
          )
          .join("")
      : `
        <tr>
          <td colspan="5" class="empty">No JS Processing documents yet. Create one to run custom scripts in flows (admin saves set the integrity hash; non-admin can run the flow).</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – JS Processing</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 56rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .row-actions { white-space: nowrap; }
    .row-actions .icon-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 2rem;
      min-height: 2rem;
      margin: 0 0.15rem;
      padding: 0.2rem 0.35rem;
      font-size: 1.15rem;
      line-height: 1;
      vertical-align: middle;
      text-decoration: none;
      border-radius: 4px;
    }
    .row-actions .icon-action:focus { outline: 2px solid var(--app-link, #58a6ff); outline-offset: 2px; }
    .edit-link { color: var(--app-link, #58a6ff); }
    .edit-link:hover { background: rgba(88, 166, 255, 0.12); }
    .copy-btn {
      border: none;
      background: none;
      color: var(--app-label, #8b949e);
      font: inherit;
      cursor: pointer;
    }
    .copy-btn:hover { color: var(--app-link, #58a6ff); background: rgba(88, 166, 255, 0.08); }
    .copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .delete-btn {
      border: none;
      background: none;
      color: #f85149;
      font: inherit;
      cursor: pointer;
      padding: 0.2rem 0.35rem;
    }
    .delete-btn:hover { color: #ff7b72; background: rgba(248, 81, 73, 0.12); }
    .delete-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .id-cell { font-size: 0.85em; color: var(--app-label, #8b949e); word-break: break-all; }
    #js-list-msg { margin-top: 0.75rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Start</a><a href="/js-processing/create" class="btn">Create JS Processing</a></div>
  <h1>JS Processing</h1>
  <p class="sub">Scripts run in a sandbox (input/output only; no file or DB access). Only admins can create or edit; when saved, a hash protects the script so non-admin users can run flows that use it.</p>
  <table>
    <thead><tr><th>Name</th><th>ID</th><th>Description</th><th>Timeout</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="js-list-msg" style="display:none;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('js-list-msg');
      function showErr(t) {
        if (!msgEl) return;
        msgEl.style.display = 'block';
        msgEl.style.color = '#f85149';
        msgEl.textContent = t || 'Request failed';
      }
      document.querySelectorAll('.js-copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          if (!id) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/js-processing/' + encodeURIComponent(id) + '/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok && o.data && o.data.id) {
                window.location.href = '/js-processing/' + encodeURIComponent(o.data.id) + '/edit';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Copy failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Copy failed');
            });
        });
      });
      document.querySelectorAll('.delete-js-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          var rev = btn.getAttribute('data-rev');
          if (!id || !rev) { showErr('Missing revision; refresh the page.'); return; }
          if (!confirm('Delete this JS Processing document? Flows that reference it may need to be updated.')) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/js-processing/' + encodeURIComponent(id) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev: rev })
          })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok) {
                window.location.href = o.data.redirect || '/js-processing';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Delete failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Delete failed');
            });
        });
      });
    })();
  </script>
</body>
</html>`;
}

function renderEditJsProcessingPage(doc, err, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : "";
  const descVal = doc && typeof doc.description === "string" ? escapeHtml(doc.description) : "";
  const scriptVal = doc && typeof doc.script === "string" ? escapeHtml(doc.script) : "";
  const timeoutVal = doc && doc.timeout != null ? String(Math.min(Math.max(Number(doc.timeout), 100), 60000)) : "5000";
  const revInput = doc && doc._rev ? `<input type="hidden" id="rev" value="${escapeHtml(doc._rev)}">` : "";
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit JS Processing" : "Create JS Processing";
  const submitLabel = isEdit ? "Save" : "Create";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 48rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="number"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    textarea { width: 100%; min-height: 12rem; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-family: monospace; font-size: 0.9rem; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; }
    .msg.err { background: #3d1f1f; color: #f85149; padding: 0.5rem; border-radius: 6px; margin: 1rem 0; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/js-processing">← JS Processing</a>
    <button type="submit" form="js-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/js-processing" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>${title}</h1>
  <p class="sub">Script runs in a sandbox with <code>input</code> (read-only pipeline data) and <code>output</code> (object to write results; merged back into the pipeline). Return value is logged only. Timeout 100–60000 ms.</p>
  ${errHtml}
  <form id="js-form">
    ${revInput}
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="e.g. Normalize fields" value="${nameVal}">
    <label for="description">Description</label>
    <input type="text" id="description" name="description" placeholder="Optional" value="${descVal}">
    <label for="timeout">Timeout (ms)</label>
    <input type="number" id="timeout" name="timeout" min="100" max="60000" value="${timeoutVal}" placeholder="5000">
    <label for="script">Script <button type="button" class="btn btn-secondary" style="margin-left:0.5rem;padding:0.2rem 0.6rem;font-size:0.75rem;" onclick="window.open('/js-processing/help','js-processing-help','width=820,height=760');return false;">Help</button></label>
    <textarea id="script" name="script" placeholder="// input = pipeline data (read-only)\n// output = object to write results\noutput.result = input.someField;">${scriptVal}</textarea>
  </form>
  <script>
    var formEl = document.getElementById('js-form');
    if (formEl) formEl.onsubmit = async function(e) {
      e.preventDefault();
      var name = document.getElementById('name').value.trim();
      if (!name) { alert('Name is required.'); return; }
      var script = document.getElementById('script').value;
      var timeout = Math.min(Math.max(parseInt(document.getElementById('timeout').value, 10) || 5000, 100), 60000);
      var description = document.getElementById('description').value.trim();
      var url = ${isEdit ? JSON.stringify("/api/js-processing/" + encodeURIComponent(doc._id)) : '"/api/js-processing"'};
      var method = ${isEdit ? '"PUT"' : '"POST"'};
      var body = { name, description, script, timeout };
      if (${isEdit ? "true" : "false"}) body._rev = document.getElementById('rev').value;
      try {
        var r = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await r.json();
        if (!r.ok) { alert(data.error || 'Failed'); return; }
        window.location.href = '/js-processing';
      } catch (err) {
        alert(err.message || 'Request failed');
      }
    };
  </script>
</body>
</html>`;
}

function renderJsProcessingHelpPage(appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – JS Processing Help</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem 1.25rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); }
    h1 { font-size: 1.1rem; margin: 0 0 0.75rem 0; }
    h2 { font-size: 0.95rem; margin: 1rem 0 0.4rem 0; color: var(--app-label, #8b949e); }
    p { margin: 0.35rem 0; }
    ul { margin: 0.35rem 0 0.35rem 1.2rem; padding: 0; }
    li { margin: 0.2rem 0; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
    code { background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 4px; padding: 0.1rem 0.3rem; }
    pre { background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; padding: 0.6rem; overflow: auto; font-size: 0.85rem; line-height: 1.35; }
    .sub { color: var(--app-label, #8b949e); }
  </style>
</head>
<body>
  <h1>JS Processing Help</h1>
  <p class="sub">Scripts run in a sandbox. Use <code>input</code> to read pipeline data and <code>output</code> to return data.</p>

  <h2>input.fieldName</h2>
  <p>Read values from the current pipeline dataset:</p>
  <pre>// Example
var q = input.query || "";
var apiJson = input.guardianJson || "";</pre>

  <h2>output.fieldName</h2>
  <p>Write values back into the pipeline dataset (merged after script execution):</p>
  <pre>// Example
output.normalizedQuery = (input.query || "").trim().toLowerCase();
output.importCount = 0;</pre>

  <h2>output._writeLog(object)</h2>
  <p>Write structured log entries to the flow log as <code>flow.scriptLog</code> messages.</p>
  <pre>// Example
output._writeLog({ stage: "parse", ok: true, count: 12 });
output._writeLog({ level: "error", message: "Invalid JSON" });</pre>
  <ul>
    <li>Accepts JSON-compatible objects (strings/numbers/booleans/arrays/objects).</li>
    <li>Logs include profile and entry context automatically.</li>
  </ul>

  <h2>output._createMany</h2>
  <p>Create multiple new Elenko entries in the current profile.</p>
  <pre>// Example
output._createMany = [
  { title: "A", url: "https://example.org/a" },
  { title: "B", url: "https://example.org/b" }
];</pre>
  <ul>
    <li>Each object is mapped to profile fields by name.</li>
    <li>Unknown fields are ignored; missing profile fields become empty.</li>
  </ul>

  <h2>Combined example</h2>
  <pre>var rows = [];
try {
  var parsed = JSON.parse(input.guardianJson || "{}");
  var results = (((parsed || {}).response || {}).results || []);
  rows = results.map(function(r) {
    return { webTitle: r.webTitle || "", webUrl: r.webUrl || "" };
  });
  output._writeLog({ stage: "map", results: rows.length });
} catch (e) {
  output._writeLog({ level: "error", stage: "parse", message: String(e.message || e) });
}
output._createMany = rows;
output.importCount = rows.length;</pre>
</body>
</html>`;
}

function renderApisListPage(apis, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const truncate = (s, max) => (s && s.length > max ? s.slice(0, max) + "…" : s || "");
  const rows =
    apis.length > 0
      ? apis
          .map(
            (a) => `
        <tr>
          <td><a href="/apis/${encodeURIComponent(a._id)}/edit">${escapeHtml(a.name || a._id)}</a></td>
          <td><code class="id-cell">${escapeHtml(a._id || "")}</code></td>
          <td>${escapeHtml(truncate(a.description || "", 40))}</td>
          <td>${escapeHtml(a.method || "GET")}</td>
          <td>${escapeHtml(truncate(a.url || "", 50))}</td>
          <td class="row-actions"><a href="/apis/${encodeURIComponent(a._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="copy-btn icon-action api-copy-btn" data-id="${escapeHtml(a._id)}" aria-label="Copy" title="Copy">⧉</button><button type="button" class="delete-btn icon-action delete-api-btn" data-id="${escapeHtml(a._id)}" data-rev="${escapeHtml(a._rev || "")}" aria-label="Delete" title="Delete">✕</button></td>
        </tr>`
          )
          .join("")
      : `
        <tr>
          <td colspan="6" class="empty">No REST APIs yet. Create one to use the &quot;Call API&quot; flow target.</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – REST APIs</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 56rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .row-actions { white-space: nowrap; }
    .row-actions .icon-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 2rem;
      min-height: 2rem;
      margin: 0 0.15rem;
      padding: 0.2rem 0.35rem;
      font-size: 1.15rem;
      line-height: 1;
      vertical-align: middle;
      text-decoration: none;
      border-radius: 4px;
    }
    .row-actions .icon-action:focus { outline: 2px solid var(--app-link, #58a6ff); outline-offset: 2px; }
    .edit-link { color: var(--app-link, #58a6ff); }
    .edit-link:hover { background: rgba(88, 166, 255, 0.12); }
    .copy-btn {
      border: none;
      background: none;
      color: var(--app-label, #8b949e);
      font: inherit;
      cursor: pointer;
    }
    .copy-btn:hover { color: var(--app-link, #58a6ff); background: rgba(88, 166, 255, 0.08); }
    .copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .delete-btn {
      border: none;
      background: none;
      color: #f85149;
      font: inherit;
      cursor: pointer;
      padding: 0.2rem 0.35rem;
    }
    .delete-btn:hover { color: #ff7b72; background: rgba(248, 81, 73, 0.12); }
    .delete-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .id-cell { font-size: 0.85em; color: var(--app-label, #8b949e); word-break: break-all; }
    #api-list-msg { margin-top: 0.75rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Start</a><a href="/apis/create" class="btn">Create REST API</a></div>
  <h1>REST APIs</h1>
  <p class="sub">Configure REST API targets for the &quot;Call API&quot; flow. Use the API document ID or name in the entry form flow parameter.</p>
  <table>
    <thead><tr><th>Name</th><th>ID</th><th>Description</th><th>Method</th><th>URL</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="api-list-msg" style="display:none;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('api-list-msg');
      function showErr(t) {
        if (!msgEl) return;
        msgEl.style.display = 'block';
        msgEl.style.color = '#f85149';
        msgEl.textContent = t || 'Request failed';
      }
      document.querySelectorAll('.api-copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          if (!id) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/apis/' + encodeURIComponent(id) + '/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok && o.data && o.data.id) {
                window.location.href = '/apis/' + encodeURIComponent(o.data.id) + '/edit';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Copy failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Copy failed');
            });
        });
      });
      document.querySelectorAll('.delete-api-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          var rev = btn.getAttribute('data-rev');
          if (!id || !rev) { showErr('Missing revision; refresh the page.'); return; }
          if (!confirm('Delete this REST API? Flows or forms that reference it may need to be updated.')) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/apis/' + encodeURIComponent(id) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev: rev })
          })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok) {
                window.location.href = o.data.redirect || '/apis';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Delete failed');
            })
            .catch(function(e) {
              btn.disabled = false;
              showErr(e.message || 'Delete failed');
            });
        });
      });
    })();
  </script>
</body>
</html>`;
}

function renderEditApiPage(doc, err, returnTo, appUi, prefillApiKeyRef) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const id = doc && doc._id;
  const rev = doc && doc._rev;
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : "";
  const descVal = doc && typeof doc.description === "string" ? escapeHtml(doc.description) : "";
  const urlVal = doc && typeof doc.url === "string" ? escapeHtml(doc.url) : "";
  const methodVal = doc && doc.method === "POST" ? "POST" : doc && doc.method === "PUT" ? "PUT" : doc && doc.method === "PATCH" ? "PATCH" : "GET";
  const apiKeyRefRaw =
    doc && typeof doc.apiKeyRef === "string" && doc.apiKeyRef.trim()
      ? doc.apiKeyRef.trim()
      : (typeof prefillApiKeyRef === "string" && prefillApiKeyRef.trim() ? prefillApiKeyRef.trim() : "");
  const apiKeyRefVal = apiKeyRefRaw ? escapeHtml(apiKeyRefRaw) : "";
  const responseTargetVal = doc && doc.responseTarget === "create" ? "create" : doc && doc.responseTarget === "forward" ? "forward" : "update";
  const templateVal = doc && typeof doc.template === "string" ? escapeHtml(doc.template) : "";
  const responseFieldVal = doc && typeof doc.responseField === "string" ? escapeHtml(doc.responseField) : "";
  const responseStartVal = doc && typeof doc.responseStart === "string" ? escapeHtml(doc.responseStart) : "";
  const responseEndVal = doc && typeof doc.responseEnd === "string" ? escapeHtml(doc.responseEnd) : "";
  const returnToRaw = (typeof returnTo === "string" && returnTo.trim()) ? returnTo.trim() : "";
  const defaultNameForKey = nameVal ? encodeURIComponent(nameVal) : "";
  const keyEditHref = apiKeyRefRaw
    ? "/apis/keys/" + encodeURIComponent(apiKeyRefRaw) + "/edit" + (returnToRaw ? "?returnTo=" + encodeURIComponent(returnToRaw) : "")
    : "/apis/keys/create" + (returnToRaw ? "?returnTo=" + encodeURIComponent(returnToRaw) : "") + (defaultNameForKey ? "&defaultName=" + defaultNameForKey : "");
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit REST API" : "Create REST API";
  const submitLabel = isEdit ? "Save" : "Create";
  const revInput = rev ? `<input type="hidden" id="rev" value="${escapeHtml(rev)}">` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .actions { margin-bottom: 1rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    label { display: block; margin-top: 0.75rem; color: var(--app-label, #8b949e); }
    input, select, textarea { width: 100%; max-width: 28rem; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); }
    .btn { margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; border: none; }
    .btn-primary { background: #238636; color: #fff; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; display: inline-block; margin-left: 0.5rem; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    .msg { margin-top: 1rem; }
    .msg.err { color: #f85149; }
    .msg.ok { color: #3fb950; }
    .sub { color: var(--app-label, #8b949e); font-size: 0.9rem; margin-top: 0.25rem; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/apis">← REST APIs</a>
    <button type="submit" form="api-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/apis" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>${title}</h1>
  ${errHtml}
  <form id="api-form">
    ${revInput}
    <input type="hidden" id="apiId" value="${id ? escapeHtml(id) : ""}">
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="API label (or use _id in flow param)" value="${nameVal}">
    <label for="description">Description</label>
    <input type="text" id="description" name="description" placeholder="Optional" value="${descVal}">
    <label for="url">URL</label>
    <input type="text" id="url" name="url" placeholder="https://..." value="${urlVal}">
    <label for="method">Method</label>
    <select id="method" name="method">
      <option value="GET"${methodVal === "GET" ? " selected" : ""}>GET</option>
      <option value="POST"${methodVal === "POST" ? " selected" : ""}>POST</option>
      <option value="PUT"${methodVal === "PUT" ? " selected" : ""}>PUT</option>
      <option value="PATCH"${methodVal === "PATCH" ? " selected" : ""}>PATCH</option>
    </select>
    <label for="template">Template <span class="sub">(optional) API call with placeholders: use #fieldName# for Elenko document fields, e.g. {directory-query:'#customer#'}</span></label>
    <textarea id="template" name="template" placeholder='e.g. {"query":"#customer#"}' rows="4" style="width:100%;max-width:28rem;font-family:monospace;">${templateVal}</textarea>
    <label for="responseField">Response field <span class="sub">(optional) Elenko document field name where the raw API response body will be stored when updating the same entry)</span></label>
    <input type="text" id="responseField" name="responseField" placeholder="e.g. apiResponse" value="${responseFieldVal}">
    <label for="responseStart">Response start <span class="sub">(optional) Character sequence that marks the start of the useful text; everything before and including it is removed)</span></label>
    <input type="text" id="responseStart" name="responseStart" placeholder='e.g. "content":"' value="${responseStartVal}" style="font-family:monospace;">
    <label for="responseEnd">Response end <span class="sub">(optional) Character sequence that marks the end of the useful text; it and everything after it is removed)</span></label>
    <input type="text" id="responseEnd" name="responseEnd" placeholder='e.g. "}}]}' value="${responseEndVal}" style="font-family:monospace;">
    <label for="apiKeyRef">API key document ID <span class="sub">(set from API name below, or enter manually)</span></label>
    <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
      <input type="text" id="apiKeyRef" name="apiKeyRef" placeholder="key_..." value="${apiKeyRefVal}" style="max-width:20rem;">
      <a href="#" id="createEditKeyLink" class="btn btn-secondary" style="margin-top:0;">Create / Edit API key document</a>
    </div>
    <div id="apiKeyRefNotice" class="msg" style="margin-top:0.25rem;" aria-live="polite"></div>
    <label for="responseTarget">Response target</label>
    <select id="responseTarget" name="responseTarget">
      <option value="update"${responseTargetVal === "update" ? " selected" : ""}>Update same entry (lastApiResponse)</option>
      <option value="create"${responseTargetVal === "create" ? " selected" : ""}>Create new entry in same profile</option>
      <option value="forward"${responseTargetVal === "forward" ? " selected" : ""}>Forward to next flow step only</option>
    </select>
    <p class="sub" style="margin-top:0.25rem;">When updating the same entry, <code>lastApiResponse</code> on the document will contain the full API response (statusCode, body, timestamp, success, error).</p>
  </form>
  <div id="msg"></div>
  <script>
    function slugifyForKeyId(name) {
      var s = String(name == null ? '' : name).trim().toLowerCase();
      var slug = s.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'key';
      return 'key_' + (slug.slice(0, 80) || 'key');
    }
    var apiKeyRefManuallyEdited = false;
    function syncApiKeyRefFromName() {
      var nameEl = document.getElementById('name');
      var refEl = document.getElementById('apiKeyRef');
      if (nameEl && refEl) {
        if (apiKeyRefManuallyEdited) return;
        if ((refEl.value || '').trim()) return;
        var n = (nameEl.value || '').trim();
        refEl.value = n ? slugifyForKeyId(n) : '';
      }
    }
    var form = document.getElementById('api-form');
    var formId = document.getElementById('apiId').value;
    syncApiKeyRefFromName();
    var apiKeyRefEl = document.getElementById('apiKeyRef');
    if (apiKeyRefEl) {
      apiKeyRefEl.addEventListener('input', function() {
        apiKeyRefManuallyEdited = true;
      });
    }
    document.getElementById('name').addEventListener('input', syncApiKeyRefFromName);
    document.getElementById('name').addEventListener('blur', syncApiKeyRefFromName);
    var createEditKeyLink = document.getElementById('createEditKeyLink');
    if (createEditKeyLink) {
      createEditKeyLink.addEventListener('click', function(e) {
        e.preventDefault();
        var name = (document.getElementById('name').value || '').trim();
        var apiKeyRef = (document.getElementById('apiKeyRef').value || '').trim();
        var returnTo = window.location.pathname + window.location.search;
        var q = returnTo ? '?returnTo=' + encodeURIComponent(returnTo) : '';
        // Always open create/upsert page; this also handles missing key docs gracefully.
        if (apiKeyRef) q += (q ? '&' : '?') + 'apiKeyDocId=' + encodeURIComponent(apiKeyRef);
        if (name) q += (q ? '&' : '?') + 'defaultName=' + encodeURIComponent(name);
        window.location.href = '/apis/keys/create' + q;
      });
    }
    form.onsubmit = async function(e) {
      e.preventDefault();
      var msgEl = document.getElementById('msg');
      var name = (document.getElementById('name').value || '').trim();
      var description = (document.getElementById('description').value || '').trim();
      var url = (document.getElementById('url').value || '').trim();
      var method = document.getElementById('method').value || 'GET';
      var apiKeyRef = (document.getElementById('apiKeyRef').value || '').trim();
      var responseTarget = document.getElementById('responseTarget').value || 'update';
      var template = (document.getElementById('template').value || '').trim();
      var responseField = (document.getElementById('responseField').value || '').trim();
      var responseStart = (document.getElementById('responseStart').value || '');
      var responseEnd = (document.getElementById('responseEnd').value || '');
      var urlApi = formId ? '/api/apis/' + encodeURIComponent(formId) : '/api/apis';
      var methodHttp = formId ? 'PUT' : 'POST';
      var body = { name: name, description: description, url: url, method: method, template: template, responseField: responseField, responseStart: responseStart, responseEnd: responseEnd, apiKeyRef: apiKeyRef, responseTarget: responseTarget };
      try {
        var r = await fetch(urlApi, { method: methodHttp, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        msgEl.textContent = formId ? 'Saved.' : 'Created.';
        msgEl.className = 'msg ok';
        setTimeout(function() { window.location.href = '/apis'; }, formId ? 600 : 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderEditApiKeyPage(doc, err, returnTo, defaultName, appUi, defaultApiKeyDocId) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const id = doc && doc._id;
  const apiKeyDocIdVal = id ? id : (typeof defaultApiKeyDocId === "string" ? defaultApiKeyDocId.trim() : "");
  const rev = doc && doc._rev;
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : (typeof defaultName === "string" && defaultName ? escapeHtml(defaultName) : "");
  const keyPlaceholder = isEdit ? "Leave blank to keep current key" : "API key / secret";
  const returnToVal = typeof returnTo === "string" && returnTo.trim() ? escapeHtml(returnTo.trim()) : "";
  const returnToInput = returnToVal ? `<input type="hidden" name="returnTo" id="returnTo" value="${returnToVal}">` : "";
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit API key" : "Create / Update API key";
  const submitLabel = isEdit ? "Save" : "Create";
  const revInput = rev ? `<input type="hidden" id="rev" value="${escapeHtml(rev)}">` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .actions { margin-bottom: 1rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    label { display: block; margin-top: 0.75rem; color: var(--app-label, #8b949e); }
    input { width: 100%; max-width: 28rem; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); }
    .btn { margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; border: none; }
    .btn-primary { background: #238636; color: #fff; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; display: inline-block; margin-left: 0.5rem; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    .msg { margin-top: 1rem; }
    .msg.err { color: #f85149; }
    .msg.ok { color: #3fb950; }
    .sub { color: var(--app-label, #8b949e); font-size: 0.9rem; margin-top: 0.25rem; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/apis">← REST APIs</a>
    <button type="submit" form="api-key-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/apis" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>${title}</h1>
  <p class="sub">Stored in the config store. The document ID is derived from the name (e.g. &quot;My Service&quot; → key_my-service). Use this ID in the API form as &quot;API key document ID&quot;.</p>
  ${errHtml}
  <form id="api-key-form" autocomplete="off">
    ${revInput}
    ${returnToInput}
    <input type="hidden" id="keyId" value="${id ? escapeHtml(id) : ""}">
    <label for="apiKeyDocId">API key document ID</label>
    <input type="text" id="apiKeyDocId" value="${apiKeyDocIdVal ? escapeHtml(apiKeyDocIdVal) : ""}" readonly>
    <label for="name">Description</label>
    <input type="text" id="name" name="name" required placeholder="e.g. OpenWeather API key" value="${nameVal}">
    <label for="key">API key / secret</label>
    <input type="password" id="key" name="key" placeholder="${escapeHtml(keyPlaceholder)}" autocomplete="off">
  </form>
  <div id="msg"></div>
  <script>
    var form = document.getElementById('api-key-form');
    var keyId = document.getElementById('keyId').value;
    var apiKeyDocIdEl = document.getElementById('apiKeyDocId');
    var returnToEl = document.getElementById('returnTo');
    var returnToVal = returnToEl ? returnToEl.value : '';

    function syncApiKeyDocId() {
      // In edit mode, the document id is fixed; in create mode it is derived from the "Description"/name.
      // If an apiKeyDocId was provided (from the REST API's apiKeyRef), keep it.
      if (!apiKeyDocIdEl || keyId) return;
      if (apiKeyDocIdEl.value && String(apiKeyDocIdEl.value).trim()) return;
      var n = (document.getElementById('name').value || '').trim();
      apiKeyDocIdEl.value = n ? slugifyForKeyId(n) : '';
    }
    var nameEl = document.getElementById('name');
    if (nameEl) {
      nameEl.addEventListener('input', syncApiKeyDocId);
      nameEl.addEventListener('blur', syncApiKeyDocId);
    }
    syncApiKeyDocId();

    form.onsubmit = async function(e) {
      e.preventDefault();
      var msgEl = document.getElementById('msg');
      var name = (document.getElementById('name').value || '').trim();
      var key = (document.getElementById('key').value || '');
      var urlApi = keyId ? '/api/apis/keys/' + encodeURIComponent(keyId) : '/api/apis/keys';
      var methodHttp = keyId ? 'PUT' : 'POST';
      var body = { name: name };
      var apiKeyDocId = apiKeyDocIdEl ? String(apiKeyDocIdEl.value || '').trim() : '';
      if (apiKeyDocId) body.apiKeyDocId = apiKeyDocId;
      if (key) body.key = key;
      try {
        var r = await fetch(urlApi, { method: methodHttp, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        msgEl.textContent = keyId ? 'Saved.' : 'Created.';
        msgEl.className = 'msg ok';
        if (returnToVal && data.id) {
          var sep = returnToVal.indexOf('?') !== -1 ? '&' : '?';
          setTimeout(function() { window.location.href = returnToVal + sep + 'apiKeyRef=' + encodeURIComponent(data.id); }, 500);
        } else {
          setTimeout(function() { window.location.href = '/apis'; }, keyId ? 600 : 800);
        }
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderCreateEntryFormPage(err, flows, appUi) {
  return renderEntryFormPage(null, null, err, flows, appUi);
}

function renderEditEntryFormPage(doc, err, flows, appUi) {
  return renderEntryFormPage(doc, doc._rev, err, flows, appUi);
}

function renderEntryFormCssHelpPage(appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Entry form CSS reference</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 48rem; line-height: 1.5; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    h2 { font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; font-size: 1.1rem; }
    p { margin: 0.5rem 0 1rem 0; color: var(--app-label, #8b949e); }
    code { background: var(--app-table-header-bg, #21262d); padding: 0.15em 0.4em; border-radius: 4px; font-size: 0.9em; }
    pre { background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #21262d); border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.875rem; }
    table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1rem 0; }
    th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    .back { margin-bottom: 1rem; }
    .back a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .back a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="back"><a href="/entry-forms">← Entry forms</a></div>
  <h1>Entry form CSS reference</h1>
  <p>Custom CSS in an entry form is applied on the <strong>single-entry view</strong> (read-only) and the <strong>edit entry</strong> page. You can use the variables and selectors below to override or extend styles.</p>

  <h2>CSS custom properties (variables)</h2>
  <p>These are set by the form theme. Use <code>var(--name, fallback)</code> in your custom CSS.</p>
  <table>
    <thead><tr><th>Variable</th><th>Used for</th><th>Default</th></tr></thead>
    <tbody>
      <tr><td><code>--entry-bg</code></td><td>Page background</td><td>#0f1419</td></tr>
      <tr><td><code>--entry-text</code></td><td>Body text colour</td><td>#e6edf3</td></tr>
      <tr><td><code>--entry-label</code></td><td>Label text (field names, subtitle)</td><td>#8b949e</td></tr>
      <tr><td><code>--entry-link</code></td><td>Links (Back, Edit)</td><td>#58a6ff</td></tr>
      <tr><td><code>--entry-field-border</code></td><td>Field value border (view only)</td><td>#21262d</td></tr>
      <tr><td><code>--entry-field-bg</code></td><td>Field value background (view only)</td><td>#161b22</td></tr>
      <tr><td><code>--entry-field-bg-edit</code></td><td>Input background (edit page)</td><td>#161b22</td></tr>
      <tr><td><code>--entry-text-edit</code></td><td>Input text colour (edit page)</td><td>#e6edf3</td></tr>
    </tbody>
  </table>

  <h2>Example: use variables and label classes in custom CSS</h2>
  <pre>/* Slightly lighter field background on view */
.value { background: color-mix(in srgb, var(--entry-field-bg) 90%, white) !important; }

/* Different font sizes: field names vs static labels */
.field-label { font-size: 0.9rem; }
.static-label { font-size: 1.1rem; font-weight: 600; }</pre>

  <h2>Main selectors and classes</h2>
  <p>Structure you can target in your custom CSS.</p>
  <table>
    <thead><tr><th>Selector</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td><code>body</code></td><td>Page container</td></tr>
      <tr><td><code>.actions</code></td><td>Back / Edit links</td></tr>
      <tr><td><code>.sub</code></td><td>Subtitle (e.g. "Edit entry:")</td></tr>
      <tr><td><code>.entry-view-stack</code></td><td>Stack layout container</td></tr>
      <tr><td><code>.entry-view-grid</code></td><td>Grid layout container</td></tr>
      <tr><td><code>.entry-field-block</code></td><td>One field or label block (stack)</td></tr>
      <tr><td><code>.entry-field-block.entry-label-only</code></td><td>Static label block (no value)</td></tr>
      <tr><td><code>.entry-grid-cell</code></td><td>One field or label cell (grid)</td></tr>
      <tr><td><code>.entry-grid-cell.entry-label-only</code></td><td>Static label cell</td></tr>
      <tr><td><code>.label</code></td><td>All labels (field names and static text)</td></tr>
      <tr><td><code>.field-label</code></td><td>Field name only (use e.g. for font-size)</td></tr>
      <tr><td><code>.static-label</code></td><td>Static label text only (use e.g. for font-size)</td></tr>
      <tr><td><code>.value</code></td><td>Field value container (view) or input wrapper</td></tr>
      <tr><td><code>input.entry-field</code></td><td>Text inputs (edit page only)</td></tr>
      <tr><td><code>table</code>, <code>td.value</code></td><td>Table layout: table and value cell</td></tr>
      <tr><td><code>tr.entry-label-row</code></td><td>Table row for static label</td></tr>
      <tr><td><code>.empty</code></td><td>Empty state message</td></tr>
      <tr><td><code>.msg</code>, <code>.btn</code></td><td>Messages and buttons (edit page)</td></tr>
    </tbody>
  </table>
</body>
</html>`;
}

function renderEntryFormPage(doc, rev, err, flows, appUi) {
  const appTheme = normalizeAppTheme(appUi && appUi.theme);
  const appThemeVars = getAppThemeVars(appTheme);
  const flowsList = Array.isArray(flows) ? flows : [];
  const isEdit = !!doc;
  const name = doc ? escapeHtml(doc.name || "") : "";
  const theme = doc && doc.theme ? doc.theme : DEFAULT_ENTRY_VIEW_THEME;
  const themeBgHex = toHex6(theme.background || DEFAULT_ENTRY_VIEW_THEME.background);
  const themeTextHex = toHex6(theme.text || DEFAULT_ENTRY_VIEW_THEME.text);
  const themeLabelHex = toHex6(theme.label || DEFAULT_ENTRY_VIEW_THEME.label);
  const themeLinkHex = toHex6(theme.link || DEFAULT_ENTRY_VIEW_THEME.link);
  const themeFieldBorderHex = toHex6(theme.fieldBorder || DEFAULT_ENTRY_VIEW_THEME.fieldBorder);
  const themeFieldBgHex = toHex6(theme.fieldBackground || DEFAULT_ENTRY_VIEW_THEME.fieldBackground);
  const themeFieldBgEditHex = toHex6(theme.fieldBackgroundEdit != null ? theme.fieldBackgroundEdit : DEFAULT_ENTRY_VIEW_THEME.fieldBackgroundEdit);
  const themeTextEditHex = toHex6(theme.textEdit != null ? theme.textEdit : DEFAULT_ENTRY_VIEW_THEME.textEdit);
  const background = escapeHtml(themeBgHex);
  const text = escapeHtml(themeTextHex);
  const label = escapeHtml(themeLabelHex);
  const link = escapeHtml(themeLinkHex);
  const fieldBorder = escapeHtml(themeFieldBorderHex);
  const fieldBackground = escapeHtml(themeFieldBgHex);
  const fieldBackgroundEdit = escapeHtml(themeFieldBgEditHex);
  const textEdit = escapeHtml(themeTextEditHex);
  const layout = doc && (doc.layout === "grid" || doc.layout === "stack") ? doc.layout : "table";
  const customCss = doc ? escapeHtml(doc.customCss || "") : "";
  const flowConfigs = Array.isArray(doc && doc.flowConfigs) && doc.flowConfigs.length > 0
    ? doc.flowConfigs
    : [{ enabled: !!(doc && doc.flowButtonEnabled), target: (doc && doc.flowTarget === "api") ? "api" : (doc && doc.flowTarget === "localDb") ? "localDb" : "log", label: (doc && typeof doc.flowButtonLabel === "string" && doc.flowButtonLabel.trim()) ? doc.flowButtonLabel.trim() : "Send to Flow", param: (doc && typeof doc.flowButtonParam === "string") ? doc.flowButtonParam : "", flowId: "" }];
  const initialFlowConfigsJson = JSON.stringify(flowConfigs);
  const labelsArr = (doc && Array.isArray(doc.labels) ? doc.labels : []);
  const fieldLayout = (doc && Array.isArray(doc.fieldLayout) ? doc.fieldLayout : []);
  const revInput = rev ? `<input type="hidden" id="rev" value="${escapeHtml(rev)}">` : "";
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Single Entry form configuration" : "Create Single Entry form configuration";
  const submitLabel = isEdit ? "Save" : "Create";

  const labelsRows =
    labelsArr.length > 0
      ? labelsArr
          .map(
            (l) => `
        <tr class="labels-row">
          <td><input type="text" class="label-id" placeholder="e.g. sectionTitle" value="${escapeHtml(l.id || "")}"></td>
          <td><input type="text" class="label-text" placeholder="Fixed text shown on entry view" value="${escapeHtml(l.text || "")}"></td>
          <td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>
        </tr>`
          )
          .join("")
      : "";

  const fieldLayoutRows = fieldLayout.length > 0
    ? fieldLayout
        .map(
          (item, idx) => {
            const fieldOrLabel = item.fieldName || item.labelId || "";
            const xVal = item.x != null ? String(item.x) : "";
            const yVal = item.y != null ? String(item.y) : "";
            const hVal = item.height != null ? String(item.height) : "";
            const fieldTypeVal = item.fieldType === "markdown" ? "markdown" : item.fieldType === "url" ? "url" : "text";
            const typeSelect = item.fieldName
              ? `<select class="fl-type"><option value="text"${fieldTypeVal === "text" ? " selected" : ""}>Text</option><option value="markdown"${fieldTypeVal === "markdown" ? " selected" : ""}>Markdown</option><option value="url"${fieldTypeVal === "url" ? " selected" : ""}>URL</option></select>`
              : "<span class=\"sub\">—</span>";
            return `
        <tr class="field-layout-row">
          <td><input type="text" class="fl-field" placeholder="Field name or label id" value="${escapeHtml(fieldOrLabel)}"></td>
          <td><input type="number" class="fl-order" min="0" value="${item.order != null ? Number(item.order) : idx}"></td>
          <td>${typeSelect}</td>
          <td><input type="text" class="fl-width" placeholder="50%, 1fr, or 40ch" value="${escapeHtml(item.width || "100%")}"></td>
          <td><input type="number" class="fl-x" step="any" placeholder="—" value="${escapeHtml(xVal)}"></td>
          <td><input type="number" class="fl-y" step="any" placeholder="—" value="${escapeHtml(yVal)}"></td>
          <td><input type="number" class="fl-height" step="any" placeholder="—" value="${escapeHtml(hVal)}" min="0"></td>
          <td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>
        </tr>`;
          }
        )
        .join("")
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    ${appThemeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 48rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="number"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    select { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    textarea { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; }
    .btn-secondary:hover { background: #30363d; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .btn-remove:hover { color: #ff7b72; }
    .msg.err { background: #3d1f1f; color: #f85149; padding: 0.5rem; border-radius: 6px; margin: 1rem 0; }
    .field-layout-table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
    .field-layout-table td { padding: 0.25rem; }
    .field-layout-table input { width: 100%; }
    .el-theme-colours { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem; width: 100%; }
    .el-theme-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 2.5rem minmax(0, 1fr);
      align-items: center;
      gap: 0.5rem;
      width: 100%;
      min-width: 0;
    }
    .el-theme-row > label { display: block; margin: 0; font-size: 0.875rem; min-width: 0; word-break: break-word; }
    .el-theme-row > input[type="color"] {
      width: 2.5rem; height: 2.5rem; min-width: 2.5rem; min-height: 2.5rem; max-width: 2.5rem; max-height: 2.5rem;
      padding: 2px; margin: 0; cursor: pointer; border: 1px solid var(--app-table-border, #30363d); border-radius: 4px;
      background: var(--app-table-bg, #161b22); box-sizing: border-box; justify-self: center;
    }
    .el-theme-row > input[type="text"] {
      width: 100%; min-width: 0; margin: 0; padding: 0.5rem; background: var(--app-table-bg, #161b22);
      border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 0.875rem;
    }
    .flow-config-table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    .flow-config-table th, .flow-config-table td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    .flow-config-table th { color: var(--app-table-header-text, #8b949e); font-weight: 600; font-size: 0.875rem; }
    .flow-config-table tbody tr:last-child td { border-bottom: none; }
    .flow-config-table input[type="text"] { margin: 0; }
    .flow-config-table select { margin: 0; min-width: 10rem; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/entry-forms">← Entry forms</a>
    <button type="submit" form="entry-form-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/entry-forms" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>${title}</h1>
  <p class="sub">Used to style the single-entry (read-only) view: colours and field positions/sizes.</p>
  ${errHtml}
  <form id="entry-form-form">
    ${revInput}
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="e.g. Compact dark" value="${name}">
    <label>Theme (colours)</label>
    <p class="sub" style="margin-top:0.25rem;">Click the swatch to open the colour picker.</p>
    <div class="el-theme-colours">
      <div class="el-theme-row"><label for="theme-background-color">Background</label><input type="color" id="theme-background-color" value="${background}" aria-label="Background"><input type="text" id="theme-background" placeholder="#0f1419" value="${background}"></div>
      <div class="el-theme-row"><label for="theme-text-color">Text</label><input type="color" id="theme-text-color" value="${text}" aria-label="Text"><input type="text" id="theme-text" placeholder="#e6edf3" value="${text}"></div>
      <div class="el-theme-row"><label for="theme-label-color">Label</label><input type="color" id="theme-label-color" value="${label}" aria-label="Label"><input type="text" id="theme-label" placeholder="#8b949e" value="${label}"></div>
      <div class="el-theme-row"><label for="theme-link-color">Link</label><input type="color" id="theme-link-color" value="${link}" aria-label="Link"><input type="text" id="theme-link" placeholder="#58a6ff" value="${link}"></div>
      <div class="el-theme-row"><label for="theme-fieldBorder-color">Field border</label><input type="color" id="theme-fieldBorder-color" value="${fieldBorder}" aria-label="Field border"><input type="text" id="theme-fieldBorder" placeholder="#21262d" value="${fieldBorder}"></div>
      <div class="el-theme-row"><label for="theme-fieldBackground-color">Field background</label><input type="color" id="theme-fieldBackground-color" value="${fieldBackground}" aria-label="Field background"><input type="text" id="theme-fieldBackground" placeholder="#161b22" value="${fieldBackground}"></div>
      <div class="el-theme-row"><label for="theme-fieldBackgroundEdit-color">Field background (edit)</label><input type="color" id="theme-fieldBackgroundEdit-color" value="${fieldBackgroundEdit}" aria-label="Field background edit"><input type="text" id="theme-fieldBackgroundEdit" placeholder="#161b22" value="${fieldBackgroundEdit}"></div>
      <div class="el-theme-row"><label for="theme-textEdit-color">Text (edit)</label><input type="color" id="theme-textEdit-color" value="${textEdit}" aria-label="Text edit"><input type="text" id="theme-textEdit" placeholder="#e6edf3" value="${textEdit}"></div>
    </div>
    <label for="layout">Layout</label>
    <p class="sub" style="margin-top:0.25rem;">Table layout is the default and generates a two-column table. The first column contains the field names, the second the values. Grid layout places all fields in one row. Stack layout allows positioning the fields directly.</p>
    <select id="layout" name="layout">
      <option value="table" ${layout === "table" ? "selected" : ""}>Table</option>
      <option value="grid" ${layout === "grid" ? "selected" : ""}>Grid</option>
      <option value="stack" ${layout === "stack" ? "selected" : ""}>Stack (supports x/y field positioning)</option>
    </select>
    <label class="field-list-label">Static labels (optional)</label>
    <p class="sub" style="margin-top:0;">Define labels by id and text. Use the id in the field layout below to place a fixed text (e.g. section heading) at a position.</p>
    <table class="field-layout-table">
      <thead><tr><th>Name (id)</th><th>Text</th><th></th></tr></thead>
      <tbody id="labels-tbody">${labelsRows}
      </tbody>
    </table>
    <button type="button" class="btn btn-secondary" id="add-label" style="margin-top:0.5rem;">+ Add label</button>
    <label class="field-list-label" style="margin-top:1.5rem;">Field layout (optional: field name or label id, order, type, width, position)</label>
    <p class="sub" style="margin-top:0;">Use a profile field name or a label id from above. Type: Text (plain), Markdown (rendered in view mode), or URL (clickable link text in view mode). Leave empty to use profile field order. Width: e.g. 50%, 1fr, or 40ch. Only Stack supports X (ch), Y (em), and Height (em) for positioning; Grid uses width as column size only.</p>
    <table class="field-layout-table">
      <thead><tr><th>Field name or label id</th><th>Order</th><th>Type</th><th>Width</th><th>X (ch)</th><th>Y (em)</th><th>Height (em)</th><th></th></tr></thead>
      <tbody id="field-layout-tbody">${fieldLayoutRows}
      </tbody>
    </table>
    <button type="button" class="btn btn-secondary" id="add-field-layout" style="margin-top:0.5rem;">+ Add row</button>
    <label style="margin-top:1.5rem;">Flow buttons (single-entry view)</label>
    <p class="sub" style="margin-top:0;">Each row adds a button on the single-entry view that sends the entry dataset to the Flow facility. First column enables the button.</p>
    <table class="flow-config-table" style="margin-top:0.5rem;">
      <thead>
        <tr>
          <th style="width:4rem;">Enabled</th>
          <th style="min-width:10rem;">Flow</th>
          <th style="min-width:10rem;">Target</th>
          <th style="min-width:10rem;">Button title</th>
          <th style="min-width:10rem;">Additional parameter</th>
          <th style="width:5rem;"></th>
        </tr>
      </thead>
      <tbody id="flow-config-tbody"></tbody>
    </table>
    <button type="button" class="btn btn-secondary" id="add-flow-config" style="margin-top:0.5rem;">+ Add flow button</button>
    <label for="customCss">Custom CSS (entry view and edit)</label>
    <p class="sub" style="margin-top:0;">Optional CSS applied to single-entry view and edit entry page. <a href="/entry-forms/css-help" target="_blank" rel="noopener noreferrer">CSS parameters reference</a></p>
    <textarea id="customCss" name="customCss" placeholder="Optional CSS">${customCss}</textarea>
  </form>
  <div id="msg"></div>
  <script>
    const form = document.getElementById('entry-form-form');
    const labelsTbody = document.getElementById('labels-tbody');
    const tbody = document.getElementById('field-layout-tbody');
    const addLabelBtn = document.getElementById('add-label');
    const addBtn = document.getElementById('add-field-layout');
    const msgEl = document.getElementById('msg');
    const formId = ${isEdit ? JSON.stringify(doc._id) : "null"};

    const flowConfigTbody = document.getElementById('flow-config-tbody');
    const addFlowConfigBtn = document.getElementById('add-flow-config');
    const initialFlowConfigs = ${initialFlowConfigsJson};
    const flowsList = ${JSON.stringify(flowsList)};
    function addFlowConfigRow(cfg) {
      const tr = document.createElement('tr');
      tr.className = 'flow-config-row';
      const enabled = !!cfg.enabled;
      const flowId = (cfg && cfg.flowId != null) ? String(cfg.flowId) : '';
      const isSingleStep = !flowId;
      const target = (cfg.target === 'localDb' || cfg.target === 'api') ? cfg.target : 'log';
      const label = (cfg && cfg.label != null) ? String(cfg.label).replace(/"/g, '&quot;') : '';
      const param = (cfg && cfg.param != null) ? String(cfg.param).replace(/"/g, '&quot;') : '';
      let flowOpts = '<option value="">Single step</option>';
      flowsList.forEach(function(f) {
        const id = (f._id || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
        const name = (f.name || f._id || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        flowOpts += '<option value="' + id + '"' + (f._id === flowId ? ' selected' : '') + '>' + name + '</option>';
      });
      const targetOptsSingle = '<option value="log"' + (target === 'log' ? ' selected' : '') + '>Log file</option><option value="localDb"' + (target === 'localDb' ? ' selected' : '') + '>Send to Local Database</option><option value="api"' + (target === 'api' ? ' selected' : '') + '>Call API</option>';
      const targetOptsNa = '<option value="">n/a</option>';
      const targetOpts = isSingleStep ? targetOptsSingle : targetOptsNa;
      tr.innerHTML = '<td><input type="checkbox" class="flow-cfg-enabled" ' + (enabled ? 'checked' : '') + '></td><td><select class="flow-cfg-flow">' + flowOpts + '</select></td><td><select class="flow-cfg-target">' + targetOpts + '</select></td><td><input type="text" class="flow-cfg-label" placeholder="Send to Flow" value="' + label + '"></td><td><input type="text" class="flow-cfg-param" placeholder="Profile ID or API id" value="' + param + '"></td><td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      const flowSel = tr.querySelector('.flow-cfg-flow');
      const targetSel = tr.querySelector('.flow-cfg-target');
      function refreshTargetSelect() {
        const fid = (flowSel && flowSel.value) || '';
        if (fid) {
          targetSel.innerHTML = '<option value="">n/a</option>';
          targetSel.value = '';
        } else {
          const cur = (targetSel.value === 'localDb' || targetSel.value === 'api') ? targetSel.value : 'log';
          targetSel.innerHTML = '<option value="log"' + (cur === 'log' ? ' selected' : '') + '>Log file</option><option value="localDb"' + (cur === 'localDb' ? ' selected' : '') + '>Send to Local Database</option><option value="api"' + (cur === 'api' ? ' selected' : '') + '>Call API</option>';
          targetSel.value = cur;
        }
      }
      if (flowSel) flowSel.addEventListener('change', refreshTargetSelect);
      tr.querySelector('.btn-remove').onclick = () => tr.remove();
      flowConfigTbody.appendChild(tr);
    }
    (Array.isArray(initialFlowConfigs) && initialFlowConfigs.length ? initialFlowConfigs : [{ enabled: false, target: 'log', label: '', param: '', flowId: '' }]).forEach(c => addFlowConfigRow(c));
    if (addFlowConfigBtn) addFlowConfigBtn.onclick = () => addFlowConfigRow({ enabled: false, target: 'log', label: '', param: '', flowId: '' });

    function addLabelRow(id, text) {
      const tr = document.createElement('tr');
      tr.className = 'labels-row';
      tr.innerHTML = '<td><input type="text" class="label-id" placeholder="e.g. sectionTitle" value="' + (id || '').replace(/"/g, '&quot;') + '"></td><td><input type="text" class="label-text" placeholder="Fixed text shown on entry view" value="' + (text || '').replace(/"/g, '&quot;') + '"></td><td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      tr.querySelector('.btn-remove').onclick = () => tr.remove();
      labelsTbody.appendChild(tr);
    }
    addLabelBtn.onclick = () => addLabelRow('', '');

    function addRow(fieldName, order, width, x, y, height, fieldType) {
      const tr = document.createElement('tr');
      tr.className = 'field-layout-row';
      const n = tbody.querySelectorAll('.field-layout-row').length;
      const xv = (x != null && x !== '') ? String(x) : '';
      const yv = (y != null && y !== '') ? String(y) : '';
      const hv = (height != null && height !== '') ? String(height) : '';
      const typeVal = (fieldType === 'markdown') ? 'markdown' : (fieldType === 'url' ? 'url' : 'text');
      tr.innerHTML = '<td><input type="text" class="fl-field" placeholder="Field name or label id" value="' + (fieldName || '').replace(/"/g, '&quot;') + '"></td><td><input type="number" class="fl-order" min="0" value="' + (order != null ? order : n) + '"></td><td><select class="fl-type"><option value="text"' + (typeVal === 'text' ? ' selected' : '') + '>Text</option><option value="markdown"' + (typeVal === 'markdown' ? ' selected' : '') + '>Markdown</option><option value="url"' + (typeVal === 'url' ? ' selected' : '') + '>URL</option></select></td><td><input type="text" class="fl-width" placeholder="50%, 1fr, or 40ch" value="' + (width || '100%').replace(/"/g, '&quot;') + '"></td><td><input type="number" class="fl-x" step="any" placeholder="—"></td><td><input type="number" class="fl-y" step="any" placeholder="—"></td><td><input type="number" class="fl-height" step="any" placeholder="—" min="0"></td><td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      tr.querySelector('.fl-x').value = xv;
      tr.querySelector('.fl-y').value = yv;
      tr.querySelector('.fl-height').value = hv;
      const removeBtn = tr.querySelector('.btn-remove');
      if (removeBtn) {
        removeBtn.onclick = () => tr.remove();
      }
      tbody.appendChild(tr);
    }
    // Wire remove handlers for any initial field layout rows rendered from the server
    Array.from(tbody.querySelectorAll('.field-layout-row .btn-remove')).forEach((btn) => {
      btn.onclick = () => {
        const row = btn.closest('.field-layout-row');
        if (row) row.remove();
      };
    });
    addBtn.onclick = () => addRow('', tbody.querySelectorAll('.field-layout-row').length, '100%', '', '', '', 'text');

    function toHex6Sync(val) {
      const m = (val || '').trim().match(/^#?([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/);
      if (!m) return null;
      let s = m[1];
      if (s.length === 3) s = s[0] + s[0] + s[1] + s[1] + s[2] + s[2];
      return '#' + s;
    }
    const entryThemeKeys = ['background', 'text', 'label', 'link', 'fieldBorder', 'fieldBackground', 'fieldBackgroundEdit', 'textEdit'];
    entryThemeKeys.forEach(key => {
      const colorEl = document.getElementById('theme-' + key + '-color');
      const textEl = document.getElementById('theme-' + key);
      if (colorEl && textEl) {
        colorEl.addEventListener('input', () => { textEl.value = colorEl.value; });
        textEl.addEventListener('input', () => {
          const hex = toHex6Sync(textEl.value);
          if (hex) colorEl.value = hex;
        });
      }
    });

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = '';
      const name = document.getElementById('name').value.trim();
      if (!name) { msgEl.textContent = 'Name is required.'; msgEl.className = 'msg err'; return; }
      const theme = {
        background: document.getElementById('theme-background').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.background.replace(/'/g, "\\'")}',
        text: document.getElementById('theme-text').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.text.replace(/'/g, "\\'")}',
        label: document.getElementById('theme-label').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.label.replace(/'/g, "\\'")}',
        link: document.getElementById('theme-link').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.link.replace(/'/g, "\\'")}',
        fieldBorder: document.getElementById('theme-fieldBorder').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.fieldBorder.replace(/'/g, "\\'")}',
        fieldBackground: document.getElementById('theme-fieldBackground').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.fieldBackground.replace(/'/g, "\\'")}',
        fieldBackgroundEdit: document.getElementById('theme-fieldBackgroundEdit').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.fieldBackgroundEdit.replace(/'/g, "\\'")}',
        textEdit: document.getElementById('theme-textEdit').value.trim() || '${DEFAULT_ENTRY_VIEW_THEME.textEdit.replace(/'/g, "\\'")}'
      };
      const layout = document.getElementById('layout').value;
      const customCss = document.getElementById('customCss').value;
      const labels = Array.from(labelsTbody.querySelectorAll('.labels-row')).map((tr) => {
        const id = (tr.querySelector('.label-id') && tr.querySelector('.label-id').value.trim()) || '';
        const text = (tr.querySelector('.label-text') && tr.querySelector('.label-text').value.trim()) || '';
        return { id, text };
      }).filter((l) => l.id);
      const labelIds = new Set(labels.map((l) => l.id));
      const rows = tbody.querySelectorAll('.field-layout-row');
      const parseNumInput = (el) => { const v = el && el.value; const n = Number(v); return (v !== '' && Number.isFinite(n)) ? n : undefined; };
      const fieldLayout = Array.from(rows).map((tr, i) => {
        const firstCol = (tr.querySelector('.fl-field') && tr.querySelector('.fl-field').value.trim()) || '';
        if (!firstCol) return null;
        const item = {
          order: parseInt(tr.querySelector('.fl-order') && tr.querySelector('.fl-order').value, 10) || i,
          width: (tr.querySelector('.fl-width') && tr.querySelector('.fl-width').value.trim()) || '100%'
        };
        const x = parseNumInput(tr.querySelector('.fl-x'));
        const y = parseNumInput(tr.querySelector('.fl-y'));
        const h = parseNumInput(tr.querySelector('.fl-height'));
        if (x != null) item.x = x;
        if (y != null) item.y = y;
        if (h != null) item.height = h;
        if (labelIds.has(firstCol)) item.labelId = firstCol; else {
          item.fieldName = firstCol;
          const typeEl = tr.querySelector('.fl-type');
          item.fieldType = (typeEl && (typeEl.value === 'markdown' || typeEl.value === 'url')) ? typeEl.value : 'text';
        }
        return item;
      }).filter(Boolean);
      const flowConfigs = Array.from(flowConfigTbody.querySelectorAll('.flow-config-row')).map((tr) => {
        const enabled = tr.querySelector('.flow-cfg-enabled') && tr.querySelector('.flow-cfg-enabled').checked;
        const flowId = (tr.querySelector('.flow-cfg-flow') && tr.querySelector('.flow-cfg-flow').value) || '';
        const target = (tr.querySelector('.flow-cfg-target') && tr.querySelector('.flow-cfg-target').value) || '';
        const label = (tr.querySelector('.flow-cfg-label') && tr.querySelector('.flow-cfg-label').value.trim()) || 'Send to Flow';
        const param = (tr.querySelector('.flow-cfg-param') && tr.querySelector('.flow-cfg-param').value.trim()) || '';
        return { enabled, flowId, target, label, param };
      });
      const flowConfigErr = flowConfigs.find(function(c) {
        return !c.flowId && (c.target === '' || (c.target !== 'log' && c.target !== 'localDb' && c.target !== 'api'));
      });
      if (flowConfigErr) {
        msgEl.textContent = 'When using Single step, please select a Target (Log file, Send to Local Database, or Call API) for each flow button.';
        msgEl.className = 'msg err';
        return;
      }
      const url = formId ? '/api/entry-forms/' + encodeURIComponent(formId) : '/api/entry-forms';
      const method = formId ? 'PUT' : 'POST';
      const body = { name, labels, theme, layout, fieldLayout, customCss, flowConfigs };
      if (formId) body._rev = document.getElementById('rev').value;
      try {
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        msgEl.textContent = formId ? 'Saved.' : 'Created.';
        msgEl.className = 'msg ok';
        setTimeout(function() { window.location.href = '/entry-forms'; }, formId ? 600 : 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderDeleteProfilePage(doc) {
  const name = escapeHtml(doc.name || doc._id);
  const rev = escapeHtml(doc._rev || "");
  const id = doc._id;
  const deleteUrl = "/api/profiles/" + encodeURIComponent(id) + "/delete";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Delete profile</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 32rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .warning { background: #3d1f1f; color: #f85149; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; margin-right: 0.5rem; margin-top: 0.5rem; }
    .btn-danger { background: #da3633; color: #fff; }
    .btn-danger:hover { background: #f85149; }
    .btn-secondary { background: #21262d; color: #e6edf3; }
    .btn-secondary:hover { background: #30363d; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a></div>
  <h1>Delete profile</h1>
  <p class="sub">Really delete this profile?</p>
  <p><strong>${name}</strong></p>
  <p class="warning">This will remove the profile document. All linked entries will be marked for deletion; you can remove them permanently from the "Marked for deletion" page.</p>
  <form id="delete-form">
    <input type="hidden" id="rev" value="${rev}">
    <button type="submit" class="btn btn-danger">Yes, delete</button>
    <a href="/" class="btn btn-secondary">Cancel</a>
  </form>
  <div id="msg"></div>
  <script>
    const form = document.getElementById('delete-form');
    const msgEl = document.getElementById('msg');

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const _rev = document.getElementById('rev').value;
      try {
        const r = await fetch(${JSON.stringify(deleteUrl)}, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ _rev })
        });
        const result = await r.json();
        if (!r.ok) { msgEl.textContent = result.error || 'Delete failed'; msgEl.className = 'msg err'; return; }
        window.location.href = result.redirect || '/';
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderAllDocumentsPage(docs, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const profileMap = {};
  for (const d of docs) {
    if (d.type === "elenko_profile") {
      const firstFieldName = Array.isArray(d.fieldNames) && d.fieldNames[0] ? d.fieldNames[0] : null;
      profileMap[d._id] = { name: d.name || d._id, firstFieldName };
    }
  }

  const rows =
    docs.length > 0
      ? docs
          .map((d) => {
            const id = escapeHtml(d._id);
            const rev = escapeHtml(d._rev || "");
            const type = escapeHtml(d.type || "—");
            let summary;
            if (d.type === "elenko_profile") {
              summary = escapeHtml(d.name || "—");
            } else if (d.type === "elenko_pending_deletions") {
              summary = (d.profileName ? escapeHtml(d.profileName) + " · " : "") + (Array.isArray(d.entries) ? d.entries.length + " entries" : "batch");
            } else if (d.type === "elenko_record" && d.profileId) {
              const profile = profileMap[d.profileId];
              const profileName = profile ? (profile.name || d.profileId) : d.profileId;
              summary = escapeHtml(profileName) + " <span class=\"profile-id-hint\" title=\"Profile ID on this entry\">(ID: " + escapeHtml(d.profileId) + ")</span>";
            } else if (d.type === "elenko_entry_form") {
              summary = escapeHtml(d.name || "—");
            } else {
              summary = d.profileId ? "profile: " + escapeHtml(d.profileId) : "—";
            }
            return `
        <tr>
          <td><input type="checkbox" class="doc-delete-cb" data-id="${id}" data-rev="${rev}" aria-label="Delete"></td>
          <td><code>${id}</code></td>
          <td>${type}</td>
          <td>${summary}</td>
        </tr>`;
          })
          .join("")
      : `<tr><td colspan="4" class="empty">No application documents in the database.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – All documents</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    code { font-size: 0.9em; background: var(--app-table-bg, #21262d); color: var(--app-label, #8b949e); padding: 0.2em 0.4em; border-radius: 4px; word-break: break-all; }
    .btn { display: inline-block; background: #da3633; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; margin-bottom: 1rem; }
    .btn:hover { background: #f85149; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
    .profile-id-hint { font-size: 0.85em; color: var(--app-label, #8b949e); font-weight: normal; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a></div>
  <h1>All documents</h1>
  <p class="sub">CouchDB documents created by the application (profiles, entries, pending-deletion batches).</p>
  <p><label for="doc-summary-search" style="margin-right:0.5rem;">Search Summary:</label><input type="search" id="doc-summary-search" placeholder="Filter by summary…" style="padding:0.5rem 0.75rem;background:var(--app-table-bg, #161b22);border:1px solid var(--app-table-border, #30363d);border-radius:6px;color:var(--app-text, #e6edf3);font-size:1rem;min-width:16rem;"></p>
  <p><button type="button" class="btn" id="delete-marked-btn">Delete marked entries</button></p>
  <table>
    <thead>
      <tr>
        <th style="width:2.5rem">Delete</th>
        <th>Document ID</th>
        <th>Type</th>
        <th>Summary</th>
      </tr>
    </thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="msg"></div>
  <script>
    const deleteBtn = document.getElementById('delete-marked-btn');
    const msgEl = document.getElementById('msg');
    const searchInput = document.getElementById('doc-summary-search');
    const tbody = document.querySelector('table tbody');
    if (searchInput && tbody) {
      searchInput.addEventListener('input', () => {
        const q = (searchInput.value || '').trim().toLowerCase();
        const rows = tbody.querySelectorAll('tr');
        rows.forEach(tr => {
          if (tr.classList.contains('empty')) { tr.style.display = q ? 'none' : ''; return; }
          const summaryCell = tr.cells[3];
          const text = summaryCell ? (summaryCell.textContent || '').toLowerCase() : '';
          tr.style.display = !q || text.indexOf(q) !== -1 ? '' : 'none';
        });
      });
    }

    deleteBtn.onclick = async () => {
      const checked = document.querySelectorAll('.doc-delete-cb:checked');
      if (checked.length === 0) { msgEl.textContent = 'Select at least one document.'; msgEl.className = 'msg err'; return; }
      const items = Array.from(checked).map(cb => ({ id: cb.getAttribute('data-id'), rev: cb.getAttribute('data-rev') }));
      deleteBtn.disabled = true;
      msgEl.textContent = '';
      msgEl.className = 'msg';
      try {
        const r = await fetch('/api/documents/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ items })
        });
        const result = await r.json();
        if (!r.ok) { msgEl.textContent = result.error || 'Delete failed'; msgEl.className = 'msg err'; deleteBtn.disabled = false; return; }
        msgEl.textContent = 'Deleted ' + (result.deleted || 0) + ' document(s).';
        msgEl.className = 'msg ok';
        setTimeout(() => window.location.reload(), 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
        deleteBtn.disabled = false;
      }
    };
  </script>
</body>
</html>`;
}

function renderStartPage(profiles, role, appUi) {
  const isAdmin = role === "admin";
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const logoUrl = appUi && appUi.logoUrl ? appUi.logoUrl : "";
  const logoWidth = appUi && appUi.logoWidth ? appUi.logoWidth : 0;
  const logoHeight = appUi && appUi.logoHeight ? appUi.logoHeight : 0;
  const logoHtml = logoUrl
    ? `<div class="logo-wrap" style="margin-bottom:1rem;"><img src="${escapeHtml(logoUrl)}" style="max-width:100%;${logoWidth ? `width:${logoWidth}px;` : ""}${logoHeight ? `height:${logoHeight}px;` : ""}" alt="Elenko logo"></div>`
    : "";
  const titleHtml = logoUrl ? "" : "<h1>Elenko</h1>";
  const themeVars = `
    :root {
      --app-bg: ${escapeHtml(theme.background)};
      --app-text: ${escapeHtml(theme.text)};
      --app-label: ${escapeHtml(theme.label)};
      --app-link: ${escapeHtml(theme.link)};
      --app-table-bg: ${escapeHtml(theme.tableBg)};
      --app-table-header-bg: ${escapeHtml(theme.tableHeaderBg)};
      --app-table-header-text: ${escapeHtml(theme.tableHeaderText)};
      --app-table-border: ${escapeHtml(theme.tableBorder)};
    }`;
  const rows = profiles.length
    ? profiles
        .map((p) => {
          const createdDate = p.createdAt ? formatDateOnly(p.createdAt) : "—";
          return `
        <tr>
          <td><a href="/profile/${encodeURIComponent(p._id)}">${escapeHtml(p.name || p._id)}</a></td>
          <td>${escapeHtml(p.description || "—")}</td>
          <td class="col-mobile-hidden">${escapeHtml(createdDate)}</td>
        </tr>`;
        })
        .join("")
    : `
        <tr>
          <td colspan="3" class="empty">No Elenko database profiles yet.${isAdmin ? ' Add documents with <code>type: "elenko_profile"</code> in CouchDB.' : ""}</td>
        </tr>`;

    const actionsAdmin = '<a href="/profile/create" class="btn">Create Elenko database</a>';
  const actionsUser = "";
  const userAdminOptions = '<option value="" disabled selected>Admin</option><option value="/account/change-password">Change password</option>' + (isAdmin ? '<option value="/account/couchdb-password">CouchDB password</option><option value="/account/users">Manage users</option><option value="/account/users/create">Create user</option>' : '');
  const specialOptions = '<option value="" disabled selected>Special</option><option value="/app-config">Application design / theme</option><option value="/config-export-import">Export / Import configuration</option><option value="/data-export-import">Export / Import data</option><option value="/profiles">Elenko profiles</option><option value="/entry-forms">Single Entry forms</option><option value="/documents">All documents</option><option value="/deletions">Marked for deletion</option>';
  const actionsCommon = '<a href="/logout" class="btn-logout">Log out</a>';
  const thead = '<tr><th>Name</th><th>Description</th><th class="col-mobile-hidden">Creation date</th></tr>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <title>Elenko</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    a { color: var(--app-link, #58a6ff); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code { font-size: 0.9em; background: var(--app-table-bg, #21262d); color: var(--app-label, #8b949e); padding: 0.2em 0.4em; border-radius: 4px; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; margin-bottom: 0; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    a.btn:not(.btn-secondary), .nav-bar a.btn:not(.btn-secondary) { color: #fff; }
    a.btn:hover:not(.btn-secondary), .nav-bar a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    .btn-logout { display: inline-block; margin-left: 0.5rem; padding: 0.35rem 0.75rem; background: #0d1117; color: #fff; border: 1px solid #30363d; border-radius: 6px; font-size: 0.9rem; text-decoration: none; vertical-align: middle; }
    .btn-logout:hover { background: #21262d; color: #fff; text-decoration: none; }
    .nav-bar { display: flex; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem; }
    .edit-link { color: var(--app-link, #58a6ff); }
    .delete-link { color: #f85149; margin-left: 0.5rem; }
    .delete-link:hover { color: #ff7b72; }
    .nav-select { margin-left: 0; padding: 0.35rem 0.5rem; background: #21262d; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 0.9rem; cursor: pointer; vertical-align: middle; }
    .nav-select:hover { border-color: #58a6ff; }
    .nav-select:focus { outline: none; border-color: #58a6ff; }
    .col-mobile-hidden { display: table-cell; }
    @media (max-width: 768px) {
      .col-mobile-hidden { display: none; }
      .nav-bar { gap: 0.25rem; margin-bottom: 0.75rem; }
      .btn { padding: 0.35rem 0.75rem; font-size: 0.875rem; }
      .btn-logout { padding: 0.25rem 0.55rem; font-size: 0.82rem; }
      .nav-select { padding: 0.15rem 0.22rem; font-size: 0.7rem; width: 4.7rem; max-width: 4.7rem; min-width: 4.7rem; }
      .nav-select-admin { width: 4.8rem; max-width: 4.8rem; min-width: 4.8rem; }
      .nav-select-flow { width: 4.4rem; max-width: 4.4rem; min-width: 4.4rem; }
      .nav-select-special { width: 4.4rem; max-width: 4.4rem; min-width: 4.4rem; }
    }
  </style>
</head>
<body>
  ${logoHtml}
  ${titleHtml}
  <p class="nav-bar">
    ${isAdmin ? actionsAdmin : actionsUser}
    ${actionsCommon}
    <select id="nav-user-admin" class="nav-select nav-select-admin" aria-label="Administration">${userAdminOptions}</select>
    ${isAdmin ? '<select id="nav-flow-processing" class="nav-select nav-select-flow" aria-label="Flow"><option value="" disabled selected>Flow</option><option value="/flows">Flows</option><option value="/apis">REST APIs</option><option value="/js-processing">JS Processing</option></select>' : ''}
    ${isAdmin ? `<select id="nav-special" class="nav-select nav-select-special" aria-label="Special functions">${specialOptions}</select>` : ""}
  </p>
  <table>
    <thead>${thead}</thead>
    <tbody>${rows}
    </tbody>
  </table>
  <script>
    document.getElementById('nav-user-admin').addEventListener('change', function() {
      var v = this.value;
      if (v) { window.location.href = v; }
    });
    var navFlowProcessing = document.getElementById('nav-flow-processing');
    if (navFlowProcessing) navFlowProcessing.addEventListener('change', function() {
      var v = this.value;
      if (v) { window.location.href = v; }
    });
    var navSpecial = document.getElementById('nav-special');
    if (navSpecial) navSpecial.addEventListener('change', function() {
      var v = this.value;
      if (v) { window.location.href = v; }
    });
  </script>
</body>
</html>`;
}

function toHex6(hex) {
  if (!hex || typeof hex !== "string") return "#000000";
  const m = hex.trim().match(/^#?([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/);
  if (!m) return "#000000";
  let s = m[1];
  if (s.length === 3) s = s[0] + s[0] + s[1] + s[1] + s[2] + s[2];
  return "#" + s;
}

function renderEditProfilePage(doc, forms = [], appUi) {
  const appTheme = normalizeAppTheme(appUi && appUi.theme);
  const appThemeVars = getAppThemeVars(appTheme);
  const name = escapeHtml(doc.name || "");
  const description = escapeHtml(doc.description || "");
  const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const fieldDefaultSources = Array.isArray(doc.fieldDefaultSources) ? doc.fieldDefaultSources : [];
  const initialDefaultSources = fieldNames.map((_, i) => (fieldDefaultSources[i] !== undefined && DEFAULT_VALUE_SOURCES.includes(fieldDefaultSources[i]) ? fieldDefaultSources[i] : ""));
  const initialFieldDisplay = normalizeFieldDisplay(fieldNames, doc.fieldDisplay);
  const rev = escapeHtml(doc._rev || "");
  const customCss = doc.customCss || "";
  const listFields = Array.isArray(doc.listFields)
    ? doc.listFields.filter((f) => typeof f === "string" && f.trim()).map((f) => f.trim())
    : [];
  const entryFormIds = Array.isArray(doc.entryFormIds)
    ? doc.entryFormIds.filter((id) => typeof id === "string" && id.trim()).map((id) => id.trim())
    : [];
  const theme = normalizeProfileTheme(doc.theme);
  const themeBg = toHex6(theme.background);
  const themeText = toHex6(theme.text);
  const themeLabel = toHex6(theme.label);
  const themeLink = toHex6(theme.link);
  const themeTableBg = toHex6(theme.tableBg);
  const themeTableHeaderBg = toHex6(theme.tableHeaderBg);
  const themeTableHeaderText = toHex6(theme.tableHeaderText);
  const themeTableBorder = toHex6(theme.tableBorder);
  const allEntryForms = Array.isArray(forms)
    ? forms.map((f) => ({ id: f._id, name: f.name || f._id }))
    : [];
  const initialEntryFormIds =
    entryFormIds.length > 0
      ? entryFormIds
      : (typeof doc.entryFormId === "string" && doc.entryFormId.trim()
          ? [doc.entryFormId.trim()]
          : []);
  const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
  const sortDirectionValue = doc.sortDirection === "desc" ? "desc" : "asc";
  const mobileSingleEntryFormId =
    typeof doc.mobileSingleEntryFormId === "string" && doc.mobileSingleEntryFormId.trim()
      ? doc.mobileSingleEntryFormId.trim()
      : "";
  const infoImportFlowId =
    typeof doc.infoImportFlowId === "string" && doc.infoImportFlowId.trim()
      ? doc.infoImportFlowId.trim()
      : (typeof doc.guardianFlowId === "string" && doc.guardianFlowId.trim() ? doc.guardianFlowId.trim() : "");
  const infoImportButtonTitle =
    typeof doc.infoImportButtonTitle === "string" && doc.infoImportButtonTitle.trim()
      ? doc.infoImportButtonTitle.trim()
      : "Import from Guardian";
  function sortKeySelect(name, id, selected) {
    const fieldOpts = fieldNames.map((fn) => `<option value="${escapeHtml(fn)}"${selected === fn ? " selected" : ""}>${escapeHtml(fn)}</option>`).join("");
    return `<select id="${id}" name="${name}"><option value="">— None —</option>${fieldOpts}<option value="createdAt"${selected === "createdAt" ? " selected" : ""}>Creation date</option><option value="updatedAt"${selected === "updatedAt" ? " selected" : ""}>Update date</option></select>`;
  }
  function listFieldSelect(name, id, selected) {
    const fieldOpts = fieldNames
      .map((fn) => `<option value="${escapeHtml(fn)}"${selected === fn ? " selected" : ""}>${escapeHtml(fn)}</option>`)
      .join("");
    return `<select id="${id}" name="${name}"><option value="">— None —</option>${fieldOpts}</select>`;
  }
  const sortKeySelect1 = sortKeySelect("sortKeyField1", "sortKeyField1", sortKeyFields[0]);
  const sortKeySelect2 = sortKeySelect("sortKeyField2", "sortKeyField2", sortKeyFields[1]);
  const sortKeySelect3 = sortKeySelect("sortKeyField3", "sortKeyField3", sortKeyFields[2]);
  const listFieldSelect1 = listFieldSelect("listField1", "listField1", listFields[0]);
  const listFieldSelect2 = listFieldSelect("listField2", "listField2", listFields[1]);
  const listFieldSelect3 = listFieldSelect("listField3", "listField3", listFields[2]);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Edit profile</title>
  <style>
    ${appThemeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 58rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input[type="text"]:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    textarea { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    textarea:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    select { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    select:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .field-row { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center; flex-wrap: wrap; }
    .field-row input[name="fieldNames"] { flex: 1; min-width: 10rem; }
    .field-row select[name="fieldDefaultSources"] { flex: 0 0 auto; width: auto; min-width: 10rem; max-width: 14rem; }
    .field-row select[name="fieldDisplay"] { flex: 0 0 6.75rem; min-width: 6.75rem; max-width: 7.5rem; font-size: 0.875rem; }
    .field-list-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.25rem; font-size: 0.875rem; color: #8b949e; flex-wrap: wrap; }
    .field-list-header .col-name { flex: 1; min-width: 10rem; }
    .field-list-header .col-prefill { flex: 0 0 auto; width: auto; min-width: 10rem; max-width: 14rem; }
    .field-list-header .col-display { flex: 0 0 6.75rem; min-width: 6.75rem; font-size: 0.8rem; }
    .field-list-header .col-action { flex: 0 0 auto; min-width: 5rem; }
    .field-list { margin: 1rem 0; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; }
    .btn-secondary:hover { background: #30363d; }
    .btn-danger { background: #da3633; color: #fff; }
    .btn-danger:hover { background: #f85149; }
    .btn-danger:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .btn-remove:hover { color: #ff7b72; }
    .field-row .btn-remove { font-size: 1.15rem; line-height: 1; min-width: 2rem; padding: 0.2rem 0.4rem; }
    .flow-config-table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    .flow-config-table th, .flow-config-table td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    .flow-config-table th { color: var(--app-table-header-text, #8b949e); font-weight: 600; font-size: 0.875rem; }
    .flow-config-table tbody tr:last-child td { border-bottom: none; }
    .flow-config-table input[type="text"] { margin: 0; }
    .flow-config-table select { margin: 0; min-width: 10rem; }
    /* Theme colours: one full-width row per colour — label | swatch | hex (CSS Grid; not 2-column layout). */
    .el-theme-colours { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem; width: 100%; }
    .el-theme-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 2.5rem minmax(0, 1fr);
      align-items: center;
      gap: 0.5rem;
      width: 100%;
      min-width: 0;
    }
    .el-theme-row > label {
      display: block;
      margin: 0;
      font-size: 0.875rem;
      min-width: 0;
      word-break: break-word;
    }
    .el-theme-row > input[type="color"] {
      width: 2.5rem;
      height: 2.5rem;
      min-width: 2.5rem;
      min-height: 2.5rem;
      max-width: 2.5rem;
      max-height: 2.5rem;
      padding: 2px;
      margin: 0;
      cursor: pointer;
      border: 1px solid var(--app-table-border, #30363d);
      border-radius: 4px;
      background: var(--app-table-bg, #161b22);
      box-sizing: border-box;
      justify-self: center;
    }
    .el-theme-row > input[type="text"] {
      width: 100%;
      min-width: 0;
      margin: 0;
      padding: 0.5rem;
      background: var(--app-table-bg, #161b22);
      border: 1px solid var(--app-table-border, #30363d);
      border-radius: 6px;
      color: var(--app-text, #e6edf3);
      font-size: 0.875rem;
    }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/">← Profiles</a>
    <button type="submit" form="edit-form" class="btn btn-primary" style="margin-left:1rem;">Save</button>
    <button type="button" class="btn btn-danger" id="delete-profile-btn" style="margin-left:0.5rem;">Delete profile</button>
    <a href="/" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>Elenko database profile</h1>
  <p class="sub">Edit Elenko database profile</p>
  <p class="sub" style="margin-bottom:0.5rem;"><strong>Profile ID:</strong> <code id="profile-id-value">${escapeHtml(doc._id)}</code> <button type="button" class="btn btn-secondary" id="copy-profile-id" style="padding:0.25rem 0.5rem;font-size:0.8rem;">Copy</button></p>
  <form id="edit-form">
    <input type="hidden" id="rev" name="_rev" value="${rev}">
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="Profile name" value="${name}">
    <label for="description">Description</label>
    <textarea id="description" name="description" placeholder="Optional description">${description}</textarea>
    <label class="field-list-label">Field names</label>
    <p class="sub" style="margin-top:0.25rem;">Optional default value is used when creating a new entry (form is prefilled; you can change it before saving). <strong>Display</strong> sets desktop list column width: <em>Auto</em> shares leftover space; <em>Hide</em> hides the column on desktop (still visible on mobile if selected in the mobile list below); percentage widths are scaled so they sum to 100% together.</p>
    <div class="field-list" id="field-list">
      <div class="field-list-header"><span class="col-name">Field name</span><span class="col-prefill">Prefill value</span><span class="col-display">Display</span><span class="col-action"></span></div>
    </div>
    <button type="button" class="btn btn-secondary" id="add-field">+ Add field</button>
    <label>Theme (colours)</label>
    <p class="sub" style="margin-top:0.25rem;">Colours for the full database (list) view: background, table, links, etc. Click the swatch to open the colour picker.</p>
    <div class="el-theme-colours">
      <div class="el-theme-row"><label for="theme-background">Background</label><input type="color" id="theme-background" value="${escapeHtml(themeBg)}" aria-label="Background colour"><input type="text" id="theme-background-hex" value="${escapeHtml(themeBg)}" placeholder="#0f1419"></div>
      <div class="el-theme-row"><label for="theme-text">Text</label><input type="color" id="theme-text" value="${escapeHtml(themeText)}" aria-label="Text colour"><input type="text" id="theme-text-hex" value="${escapeHtml(themeText)}" placeholder="#e6edf3"></div>
      <div class="el-theme-row"><label for="theme-label">Label</label><input type="color" id="theme-label" value="${escapeHtml(themeLabel)}" aria-label="Label colour"><input type="text" id="theme-label-hex" value="${escapeHtml(themeLabel)}" placeholder="#8b949e"></div>
      <div class="el-theme-row"><label for="theme-link">Link</label><input type="color" id="theme-link" value="${escapeHtml(themeLink)}" aria-label="Link colour"><input type="text" id="theme-link-hex" value="${escapeHtml(themeLink)}" placeholder="#58a6ff"></div>
      <div class="el-theme-row"><label for="theme-tableBg">Table background</label><input type="color" id="theme-tableBg" value="${escapeHtml(themeTableBg)}" aria-label="Table background"><input type="text" id="theme-tableBg-hex" value="${escapeHtml(themeTableBg)}" placeholder="#161b22"></div>
      <div class="el-theme-row"><label for="theme-tableHeaderBg">Table header bg</label><input type="color" id="theme-tableHeaderBg" value="${escapeHtml(themeTableHeaderBg)}" aria-label="Table header background"><input type="text" id="theme-tableHeaderBg-hex" value="${escapeHtml(themeTableHeaderBg)}" placeholder="#21262d"></div>
      <div class="el-theme-row"><label for="theme-tableHeaderText">Table header text</label><input type="color" id="theme-tableHeaderText" value="${escapeHtml(themeTableHeaderText)}" aria-label="Table header text"><input type="text" id="theme-tableHeaderText-hex" value="${escapeHtml(themeTableHeaderText)}" placeholder="#8b949e"></div>
      <div class="el-theme-row"><label for="theme-tableBorder">Table border</label><input type="color" id="theme-tableBorder" value="${escapeHtml(themeTableBorder)}" aria-label="Table border"><input type="text" id="theme-tableBorder-hex" value="${escapeHtml(themeTableBorder)}" placeholder="#21262d"></div>
    </div>
    <label for="customCss">Custom CSS</label>
    <textarea id="customCss" name="customCss" placeholder="Optional CSS applied to the full database (list) view only">${customCss}</textarea>
    <label for="customCssFile">Load CSS from file</label>
    <input type="file" id="customCssFile" accept=".css,text/css">
    <label class="field-list-label" style="margin-top:1.5rem;">Entry view forms</label>
    <p class="sub" style="margin-top:0.25rem;">First form is the default. Entries can switch between these forms in edit mode.</p>
    <div class="field-list" id="entry-forms-list"></div>
    <button type="button" class="btn btn-secondary" id="add-entry-form">+ Add existing form</button>
    <button type="button" class="btn btn-secondary" id="clone-entry-form" style="margin-left:0.5rem;">+ New form from default</button>
    <p class="sub" style="margin-top:0.25rem;">Use the <a href="/entry-forms">Single Entry forms</a> page or the link opened after cloning to adjust layout and colours.</p>
    <label for="mobileSingleEntryFormId" style="margin-top:1.5rem;">Mobile Single Entry Form</label>
    <p class="sub" style="margin-top:0.25rem;">Optional. When set and the app is opened from a mobile device, the single-entry view will use this form instead of the normal default. On desktop, the normal form selection applies.</p>
    <select id="mobileSingleEntryFormId" name="mobileSingleEntryFormId">
      <option value="">— None —</option>
      ${allEntryForms
        .map((f) => `<option value="${escapeHtml(f.id)}"${
          mobileSingleEntryFormId === f.id ? " selected" : ""
        }>${escapeHtml(f.name)}</option>`)
        .join("")}
    </select>
    <label for="infoImportFlowId" style="margin-top:1.5rem;">Information Import flow ID</label>
    <p class="sub" style="margin-top:0.25rem;">Optional. When set, the profile page shows an import query field and button that runs this flow. The entered query is sent in the dataset as <code>query</code>, so you can reference it in API templates with placeholders like <code>#query#</code>.</p>
    <input type="text" id="infoImportFlowId" name="infoImportFlowId" placeholder="Flow ID or name" value="${escapeHtml(infoImportFlowId)}">
    <label for="infoImportButtonTitle" style="margin-top:0.75rem;">Information Import button title</label>
    <p class="sub" style="margin-top:0.25rem;">Text shown on the import button in the database view.</p>
    <input type="text" id="infoImportButtonTitle" name="infoImportButtonTitle" placeholder="e.g. Import from Guardian" value="${escapeHtml(infoImportButtonTitle)}">
    <label style="margin-top:1.5rem;">Visible fields in Mobile entry list (up to 3)</label>
    <p class="sub" style="margin-top:0.25rem;">On narrow screens (mobile), only these columns stay visible in the entries table. If empty, the first fields are used.</p>
    <div style="display:flex;flex-wrap:wrap;gap:0.75rem 1rem;align-items:center;margin-top:0.5rem;">
      <div><label for="listField1" style="margin:0;font-size:0.875rem;">1</label><br>${listFieldSelect1}</div>
      <div><label for="listField2" style="margin:0;font-size:0.875rem;">2</label><br>${listFieldSelect2}</div>
      <div><label for="listField3" style="margin:0;font-size:0.875rem;">3</label><br>${listFieldSelect3}</div>
    </div>
    <label style="margin-top:1.5rem;">Sort key fields (up to 3)</label>
    <p class="sub" style="margin-top:0.25rem;">Entry list is sorted by these fields in order (CouchDB index). Use profile fields or Creation/Update date.</p>
    <div style="display:flex;flex-wrap:wrap;gap:0.75rem 1rem;align-items:center;margin-top:0.5rem;">
      <div><label for="sortKeyField1" style="margin:0;font-size:0.875rem;">1</label><br>${sortKeySelect1}</div>
      <div><label for="sortKeyField2" style="margin:0;font-size:0.875rem;">2</label><br>${sortKeySelect2}</div>
      <div><label for="sortKeyField3" style="margin:0;font-size:0.875rem;">3</label><br>${sortKeySelect3}</div>
    </div>
    <label for="sortDirection" style="margin-top:0.75rem;">Sort direction</label>
    <select id="sortDirection" name="sortDirection">
      <option value="asc"${sortDirectionValue === "asc" ? " selected" : ""}>Ascending</option>
      <option value="desc"${sortDirectionValue === "desc" ? " selected" : ""}>Descending</option>
    </select>
    <p style="margin-top:0.5rem;"><button type="button" class="btn btn-secondary" id="rebuild-sort-keys-btn">Rebuild sort keys for existing entries</button> <span id="rebuild-msg"></span></p>
    <label style="margin-top:1.5rem;">Recover entries</label>
    <p class="sub" style="margin-top:0.25rem;">If entries show in All documents but not on this profile, they may have a different profile ID (e.g. after a restore). In <a href="/documents">All documents</a>, open an entry row and copy the ID in parentheses from the Summary column. Paste it below and click Reassign to attach those entries to this profile.</p>
    <div style="display:flex;gap:0.5rem;align-items:center;margin-top:0.5rem;flex-wrap:wrap;">
      <input type="text" id="previous-profile-id" placeholder="Paste previous profile ID" style="max-width:20rem;padding:0.5rem;background:var(--app-table-bg, #161b22);border:1px solid var(--app-table-border, #30363d);border-radius:6px;color:var(--app-text, #e6edf3);">
      <button type="button" class="btn btn-secondary" id="reassign-entries-btn">Reassign entries to this profile</button>
      <span id="reassign-msg"></span>
    </div>
  </form>
  <div id="msg"></div>
  <script>
    const fieldList = document.getElementById('field-list');
    const addBtn = document.getElementById('add-field');
    const form = document.getElementById('edit-form');
    const msgEl = document.getElementById('msg');
    const profileId = ${JSON.stringify(doc._id)};
    const deleteBtn = document.getElementById('delete-profile-btn');
    if (deleteBtn) {
      deleteBtn.onclick = async () => {
        if (!confirm('Really delete this profile? This cannot be undone.')) return;
        deleteBtn.disabled = true;
        msgEl.textContent = '';
        msgEl.className = 'msg err';
        try {
          const _rev = document.getElementById('rev').value;
          const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev })
          });
          const result = await r.json();
          if (!r.ok) {
            msgEl.textContent = result.error || 'Delete failed';
            msgEl.className = 'msg err';
            deleteBtn.disabled = false;
            return;
          }
          window.location.href = result.redirect || '/';
        } catch (err) {
          msgEl.textContent = err.message || 'Request failed';
          msgEl.className = 'msg err';
          deleteBtn.disabled = false;
        }
      };
    }
    const initialFields = ${JSON.stringify(fieldNames)};
    const initialDefaultSources = ${JSON.stringify(initialDefaultSources)};
    const initialFieldDisplay = ${JSON.stringify(initialFieldDisplay)};
    const displayOptions = [
      { value: 'auto', label: 'Auto' },
      { value: 'hide', label: 'Hide' },
      { value: '10%', label: '10%' },
      { value: '20%', label: '20%' },
      { value: '30%', label: '30%' },
      { value: '40%', label: '40%' },
      { value: '50%', label: '50%' }
    ];

    const defaultSourceOptions = [
      { value: '', label: 'None' },
      { value: 'createdAt', label: 'Creation date' },
      { value: 'updatedAt', label: 'Update date' },
      { value: 'currentUser', label: 'Current user' }
    ];

    function addFieldRow(value, defaultSource, displayVal) {
      const row = document.createElement('div');
      row.className = 'field-row';
      const esc = (v) => (v || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const selectOpts = defaultSourceOptions.map(function(opt) {
        return '<option value="' + esc(opt.value) + '"' + (defaultSource === opt.value ? ' selected' : '') + '>' + esc(opt.label) + '</option>';
      }).join('');
      const disp = displayVal && typeof displayVal === 'string' ? displayVal : 'auto';
      const dispOpts = displayOptions.map(function(opt) {
        return '<option value="' + esc(opt.value) + '"' + (disp === opt.value ? ' selected' : '') + '>' + esc(opt.label) + '</option>';
      }).join('');
      row.innerHTML = '<input type="text" name="fieldNames" placeholder="Field name" value="' + esc(value) + '"><select name="fieldDefaultSources" title="Default for new entries">' + selectOpts + '</select><select name="fieldDisplay" title="Desktop list column width">' + dispOpts + '</select><button type="button" class="btn btn-remove" aria-label="Remove" title="Remove">✕</button>';
      row.querySelector('.btn-remove').onclick = () => row.remove();
      fieldList.appendChild(row);
    }

    addBtn.onclick = () => addFieldRow('', '', 'auto');
    (initialFields.length ? initialFields : ['', '']).forEach((v, i) => addFieldRow(v, initialDefaultSources[i] || '', (initialFieldDisplay && initialFieldDisplay[i]) ? initialFieldDisplay[i] : 'auto'));

    const cssFileInput = document.getElementById('customCssFile');
    const cssTextarea = document.getElementById('customCss');
    if (cssFileInput && cssTextarea) {
      cssFileInput.addEventListener('change', () => {
        const file = cssFileInput.files && cssFileInput.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          cssTextarea.value = reader.result || '';
        };
        reader.readAsText(file);
      });
    }

    const entryFormsList = document.getElementById('entry-forms-list');
    const addEntryFormBtn = document.getElementById('add-entry-form');
    const cloneEntryFormBtn = document.getElementById('clone-entry-form');
    const allEntryForms = ${JSON.stringify(allEntryForms)};
    const initialEntryFormIds = ${JSON.stringify(initialEntryFormIds)};

    function addEntryFormRow(selectedId) {
      const row = document.createElement('div');
      row.className = 'field-row';
      const select = document.createElement('select');
      select.name = 'entryFormIds';
      const placeholderOpt = document.createElement('option');
      placeholderOpt.value = '';
      placeholderOpt.textContent = '— Choose form —';
      select.appendChild(placeholderOpt);
      allEntryForms.forEach((f) => {
        const opt = document.createElement('option');
        opt.value = f.id;
        opt.textContent = f.name || f.id;
        if (selectedId && selectedId === f.id) opt.selected = true;
        select.appendChild(opt);
      });
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn btn-remove';
      removeBtn.textContent = 'Remove';
      removeBtn.onclick = () => row.remove();
      row.appendChild(select);
      row.appendChild(removeBtn);
      entryFormsList.appendChild(row);
    }

    (initialEntryFormIds.length ? initialEntryFormIds : []).forEach((id) => addEntryFormRow(id));
    if (!entryFormsList.children.length) {
      addEntryFormRow('');
    }

    if (addEntryFormBtn) {
      addEntryFormBtn.onclick = () => addEntryFormRow('');
    }

    if (cloneEntryFormBtn) {
      cloneEntryFormBtn.onclick = async () => {
        const defaultSelect = entryFormsList.querySelector('select[name="entryFormIds"]');
        if (!defaultSelect || !defaultSelect.value) {
          alert('Please choose a default entry form (first row) before cloning.');
          return;
        }
        const newName = (prompt('New entry form name:') || '').trim();
        if (!newName) return;
        cloneEntryFormBtn.disabled = true;
        try {
          const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/entry-forms/clone-default', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: newName })
          });
          const data = await r.json();
          if (!r.ok) {
            alert(data.error || 'Failed to create form.');
            return;
          }
          const newId = data.id;
          allEntryForms.push({ id: newId, name: newName });
          addEntryFormRow(newId);
          window.open('/entry-forms/' + encodeURIComponent(newId) + '/edit', '_blank');
        } catch (e) {
          alert(e.message || 'Request failed');
        } finally {
          cloneEntryFormBtn.disabled = false;
        }
      };
    }
    const rebuildBtn = document.getElementById('rebuild-sort-keys-btn');
    const rebuildMsg = document.getElementById('rebuild-msg');
    if (rebuildBtn && rebuildMsg) {
      rebuildBtn.onclick = async () => {
        rebuildMsg.textContent = '';
        rebuildBtn.disabled = true;
        try {
          const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/rebuild-sort-keys', { method: 'POST' });
          const data = await r.json();
          if (r.ok) { rebuildMsg.textContent = 'Rebuilt ' + (data.updated || 0) + ' entries.'; rebuildMsg.style.color = '#3fb950'; }
          else { rebuildMsg.textContent = data.error || 'Failed'; rebuildMsg.style.color = '#f85149'; }
        } catch (e) { rebuildMsg.textContent = e.message || 'Request failed'; rebuildMsg.style.color = '#f85149'; }
        rebuildBtn.disabled = false;
      };
    }
    const copyProfileIdBtn = document.getElementById('copy-profile-id');
    if (copyProfileIdBtn) {
      copyProfileIdBtn.onclick = () => {
        const el = document.getElementById('profile-id-value');
        if (el) { navigator.clipboard.writeText(el.textContent).then(() => { copyProfileIdBtn.textContent = 'Copied'; setTimeout(() => { copyProfileIdBtn.textContent = 'Copy'; }, 1500); }); }
      };
    }
    const reassignBtn = document.getElementById('reassign-entries-btn');
    const reassignMsg = document.getElementById('reassign-msg');
    const previousProfileIdInput = document.getElementById('previous-profile-id');
    if (reassignBtn && reassignMsg && previousProfileIdInput) {
      reassignBtn.onclick = async () => {
        const prevId = previousProfileIdInput.value.trim();
        if (!prevId) { reassignMsg.textContent = 'Enter the previous profile ID.'; reassignMsg.style.color = '#f85149'; return; }
        reassignMsg.textContent = '';
        reassignBtn.disabled = true;
        try {
          const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/reassign-entries', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ previousProfileId: prevId }) });
          const data = await r.json();
          if (r.ok) { reassignMsg.textContent = 'Reassigned ' + (data.reassigned || 0) + ' entries.'; reassignMsg.style.color = '#3fb950'; if ((data.reassigned || 0) > 0) setTimeout(() => window.location.href = '/profile/' + encodeURIComponent(profileId), 1500); }
          else { reassignMsg.textContent = data.error || 'Failed'; reassignMsg.style.color = '#f85149'; }
        } catch (e) { reassignMsg.textContent = e.message || 'Request failed'; reassignMsg.style.color = '#f85149'; }
        reassignBtn.disabled = false;
      };
    }

    function toHex6Sync(val) {
      const m = (val || '').trim().match(/^#?([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/);
      if (!m) return null;
      let s = m[1];
      if (s.length === 3) s = s[0] + s[0] + s[1] + s[1] + s[2] + s[2];
      return '#' + s;
    }
    const themeKeys = ['background', 'text', 'label', 'link', 'tableBg', 'tableHeaderBg', 'tableHeaderText', 'tableBorder'];
    themeKeys.forEach(key => {
      const colorEl = document.getElementById('theme-' + key);
      const hexEl = document.getElementById('theme-' + key + '-hex');
      if (colorEl && hexEl) {
        colorEl.addEventListener('input', () => { hexEl.value = colorEl.value; });
        hexEl.addEventListener('input', () => {
          const hex = toHex6Sync(hexEl.value);
          if (hex) colorEl.value = hex;
        });
      }
    });

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const name = document.getElementById('name').value.trim();
      const description = document.getElementById('description').value.trim();
      const customCss = document.getElementById('customCss').value;
      const _rev = document.getElementById('rev').value;
      const fieldRows = Array.from(document.getElementById('field-list').querySelectorAll('.field-row'));
      const fieldNames = [];
      const fieldDefaultSources = [];
      const fieldDisplay = [];
      fieldRows.forEach((row) => {
        const input = row.querySelector('input[name="fieldNames"]');
        const select = row.querySelector('select[name="fieldDefaultSources"]');
        const dispSel = row.querySelector('select[name="fieldDisplay"]');
        const name = input ? input.value.trim() : '';
        if (name) {
          fieldNames.push(name);
          fieldDefaultSources.push(select ? select.value : '');
          fieldDisplay.push(dispSel ? dispSel.value : 'auto');
        }
      });
      const entryFormIds = Array.from(document.querySelectorAll('select[name="entryFormIds"]'))
        .map((s) => s.value.trim())
        .filter(Boolean);
      const theme = {
        background: toHex6Sync(document.getElementById('theme-background-hex')?.value) || document.getElementById('theme-background')?.value || '#0f1419',
        text: toHex6Sync(document.getElementById('theme-text-hex')?.value) || document.getElementById('theme-text')?.value || '#e6edf3',
        label: toHex6Sync(document.getElementById('theme-label-hex')?.value) || document.getElementById('theme-label')?.value || '#8b949e',
        link: toHex6Sync(document.getElementById('theme-link-hex')?.value) || document.getElementById('theme-link')?.value || '#58a6ff',
        tableBg: toHex6Sync(document.getElementById('theme-tableBg-hex')?.value) || document.getElementById('theme-tableBg')?.value || '#161b22',
        tableHeaderBg: toHex6Sync(document.getElementById('theme-tableHeaderBg-hex')?.value) || document.getElementById('theme-tableHeaderBg')?.value || '#21262d',
        tableHeaderText: toHex6Sync(document.getElementById('theme-tableHeaderText-hex')?.value) || document.getElementById('theme-tableHeaderText')?.value || '#8b949e',
        tableBorder: toHex6Sync(document.getElementById('theme-tableBorder-hex')?.value) || document.getElementById('theme-tableBorder')?.value || '#21262d'
      };
      try {
        const r = await fetch('/api/profiles/' + encodeURIComponent(profileId), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            _rev,
            name,
            description,
            customCss,
            fieldNames,
            fieldDefaultSources,
            fieldDisplay,
            entryFormId: entryFormIds[0] || '',
            entryFormIds,
            theme,
            listFields: [
              document.getElementById('listField1') ? document.getElementById('listField1').value : '',
              document.getElementById('listField2') ? document.getElementById('listField2').value : '',
              document.getElementById('listField3') ? document.getElementById('listField3').value : ''
            ].filter(Boolean),
            mobileSingleEntryFormId: (document.getElementById('mobileSingleEntryFormId') && document.getElementById('mobileSingleEntryFormId').value) || '',
            sortKeyFields: [
              document.getElementById('sortKeyField1').value,
              document.getElementById('sortKeyField2').value,
              document.getElementById('sortKeyField3').value
            ].filter(Boolean),
            sortDirection: document.getElementById('sortDirection').value,
            infoImportFlowId: (document.getElementById('infoImportFlowId') && document.getElementById('infoImportFlowId').value.trim()) || '',
            infoImportButtonTitle: (document.getElementById('infoImportButtonTitle') && document.getElementById('infoImportButtonTitle').value.trim()) || ''
          })
        });
        const data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        document.getElementById('rev').value = data.rev;
        msgEl.textContent = 'Profile saved.';
        msgEl.className = 'msg ok';
        setTimeout(() => { window.location.href = '/'; }, 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderCreateProfilePage(appUi) {
  const appTheme = normalizeAppTheme(appUi && appUi.theme);
  const appThemeVars = getAppThemeVars(appTheme);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Create profile</title>
  <style>
    ${appThemeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input[type="text"]:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    textarea { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    textarea:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .field-row { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center; flex-wrap: wrap; }
    .field-row input { flex: 1; min-width: 8rem; }
    .field-row select[name="fieldDisplay"] { flex: 0 0 6.75rem; min-width: 6.75rem; font-size: 0.875rem; }
    .field-list-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.25rem; font-size: 0.875rem; color: #8b949e; flex-wrap: wrap; }
    .field-list-header .col-name { flex: 1; min-width: 8rem; }
    .field-list-header .col-display { flex: 0 0 6.75rem; min-width: 6.75rem; font-size: 0.8rem; }
    .field-list { margin: 1rem 0; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; }
    .btn-secondary:hover { background: #30363d; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .btn-remove:hover { color: #ff7b72; }
    .field-row .btn-remove { font-size: 1.15rem; line-height: 1; min-width: 2rem; padding: 0.2rem 0.4rem; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
</head>
<body>
  <h1>Elenko database profile</h1>
  <p class="sub">Create Elenko database profile</p>
  <form id="create-form">
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="Profile name">
    <label for="description">Description</label>
    <textarea id="description" name="description" placeholder="Optional description"></textarea>
    <label for="customCss">Custom CSS</label>
    <textarea id="customCss" name="customCss" placeholder="Optional CSS applied to the full database (list) view only"></textarea>
    <label for="customCssFile">Load CSS from file</label>
    <input type="file" id="customCssFile" accept=".css,text/css">
    <label class="field-list-label">Field names</label>
    <p class="sub" style="margin-top:0.25rem;"><strong>Display</strong> sets desktop list column width (Auto, Hide, or percentages scaled to 100% together).</p>
    <div class="field-list" id="field-list">
      <div class="field-list-header"><span class="col-name">Field name</span><span class="col-display">Display</span><span class="col-action"></span></div>
    </div>
    <button type="button" class="btn btn-secondary" id="add-field">+ Add field</button>
    <hr>
    <h2 style="margin-top:1.5rem;">Create from import</h2>
    <p class="sub">Load profile definition and data from a configuration in the <code>/io</code> directory.</p>
    <label for="importConfigFile">Config file name in /io</label>
    <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;margin-bottom:0.5rem;">
      <input type="text" id="importConfigFile" placeholder="e.g. compositions.eld" style="flex:1;min-width:12rem;">
      <label for="importFileSelect" style="margin:0;color:#8b949e;">Select file:</label>
      <select id="importFileSelect" class="import-select" style="background:var(--app-table-bg, #161b22);border:1px solid var(--app-table-border, #30363d);border-radius:6px;color:var(--app-text, #e6edf3);padding:0.5rem;font-size:1rem;min-width:10rem;">
        <option value="">— Select file —</option>
      </select>
    </div>
    <button type="button" class="btn btn-secondary" id="import-btn" style="margin-top:0.5rem;">Create from import</button>
    <div>
      <button type="submit" class="btn btn-primary">Create profile</button>
      <a href="/" class="btn btn-secondary" style="margin-left: 0.5rem;">Cancel</a>
    </div>
  </form>
  <div id="msg"></div>
  <script>
    const fieldList = document.getElementById('field-list');
    const addBtn = document.getElementById('add-field');
    const form = document.getElementById('create-form');
    const msgEl = document.getElementById('msg');

    const displayOptions = [
      { value: 'auto', label: 'Auto' },
      { value: 'hide', label: 'Hide' },
      { value: '10%', label: '10%' },
      { value: '20%', label: '20%' },
      { value: '30%', label: '30%' },
      { value: '40%', label: '40%' },
      { value: '50%', label: '50%' }
    ];
    function addFieldRow(value, displayVal) {
      const row = document.createElement('div');
      row.className = 'field-row';
      const esc = (v) => (v || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
      const disp = displayVal && typeof displayVal === 'string' ? displayVal : 'auto';
      const dispOpts = displayOptions.map(function(opt) {
        return '<option value="' + esc(opt.value) + '"' + (disp === opt.value ? ' selected' : '') + '>' + esc(opt.label) + '</option>';
      }).join('');
      row.innerHTML = '<input type="text" name="fieldNames" placeholder="Field name" value="' + (value || '').replace(/"/g, '&quot;') + '"><select name="fieldDisplay" title="Desktop list column width">' + dispOpts + '</select><button type="button" class="btn btn-remove" aria-label="Remove" title="Remove">✕</button>';
      row.querySelector('.btn-remove').onclick = () => row.remove();
      fieldList.appendChild(row);
    }

    addBtn.onclick = () => addFieldRow('', 'auto');
    addFieldRow('', 'auto'); addFieldRow('', 'auto');

    const cssFileInput = document.getElementById('customCssFile');
    const cssTextarea = document.getElementById('customCss');
    if (cssFileInput && cssTextarea) {
      cssFileInput.addEventListener('change', () => {
        const file = cssFileInput.files && cssFileInput.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          cssTextarea.value = reader.result || '';
        };
        reader.readAsText(file);
      });
    }

    const importBtn = document.getElementById('import-btn');
    const importInput = document.getElementById('importConfigFile');
    const importSelect = document.getElementById('importFileSelect');
    if (importSelect && importInput) {
      (async () => {
        try {
          const r = await fetch('/api/io-config-files');
          const data = await r.ok ? await r.json() : { files: [] };
          (data.files || []).forEach(function(name) {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            importSelect.appendChild(opt);
          });
        } catch (e) {}
      })();
      importSelect.addEventListener('change', function() {
        if (this.value) importInput.value = this.value;
      });
    }
    if (importBtn && importInput) {
      importBtn.addEventListener('click', async () => {
        msgEl.textContent = '';
        msgEl.className = 'msg';
        const cfg = importInput.value.trim();
        if (!cfg) {
          msgEl.textContent = 'Please enter a config file name (e.g. compositions.eld).';
          msgEl.className = 'msg err';
          return;
        }
        try {
          const r = await fetch('/api/import-profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ configFile: cfg })
          });
          const data = await r.json();
          if (!r.ok) {
            msgEl.textContent = data.error || 'Import failed';
            msgEl.className = 'msg err';
            return;
          }
          if (data.profileId) {
            window.location.href = '/profile/' + encodeURIComponent(data.profileId);
          } else {
            msgEl.textContent = 'Import completed, but no profile id returned.';
            msgEl.className = 'msg err';
          }
        } catch (err) {
          msgEl.textContent = err.message || 'Import request failed';
          msgEl.className = 'msg err';
        }
      });
    }

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const name = document.getElementById('name').value.trim();
      const description = document.getElementById('description').value.trim();
      const customCss = document.getElementById('customCss').value;
      const fieldRows = Array.from(document.getElementById('field-list').querySelectorAll('.field-row'));
      const fieldNames = [];
      const fieldDisplay = [];
      fieldRows.forEach((row) => {
        const input = row.querySelector('input[name="fieldNames"]');
        const dispSel = row.querySelector('select[name="fieldDisplay"]');
        const fn = input ? input.value.trim() : '';
        if (fn) {
          fieldNames.push(fn);
          fieldDisplay.push(dispSel ? dispSel.value : 'auto');
        }
      });
      try {
        const r = await fetch('/api/profiles', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, description, customCss, fieldNames, fieldDisplay })
        });
        const data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        msgEl.textContent = 'Profile created.';
        msgEl.className = 'msg ok';
        setTimeout(() => { window.location.href = '/'; }, 1000);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
}

function renderLoginPage(errorMessage, appUi) {
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const logoUrl = appUi && appUi.logoUrl ? appUi.logoUrl : "";
  const logoWidth = appUi && appUi.logoWidth ? appUi.logoWidth : 0;
  const logoHeight = appUi && appUi.logoHeight ? appUi.logoHeight : 0;
  const loginTextAboveRaw = appUi && typeof appUi.loginTextAbove === "string" ? appUi.loginTextAbove.trim() : "";
  const loginTextBelowRaw = appUi && typeof appUi.loginTextBelow === "string" ? appUi.loginTextBelow.trim() : "";
  const loginTextAboveHtml = loginTextAboveRaw ? marked.parse(loginTextAboveRaw) : "";
  const loginTextBelowHtml = loginTextBelowRaw ? marked.parse(loginTextBelowRaw) : "";
  const themeVars = `
    :root {
      --app-bg: ${escapeHtml(theme.background)};
      --app-text: ${escapeHtml(theme.text)};
      --app-label: ${escapeHtml(theme.label)};
      --app-link: ${escapeHtml(theme.link)};
      --app-table-bg: ${escapeHtml(theme.tableBg)};
      --app-table-border: ${escapeHtml(theme.tableBorder)};
    }`;
  const logoHtml = logoUrl
    ? `<div class="logo-wrap" style="margin-bottom:1rem;">
         <img src="${escapeHtml(logoUrl)}"
              style="max-width:100%;${logoWidth ? `width:${logoWidth}px;` : ""}${logoHeight ? `height:${logoHeight}px;` : ""}"
              alt="Elenko logo">
       </div>`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Login</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .login-box { max-width: 20rem; width: 100%; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    .login-err { color: #f85149; margin-top: 1rem; }
    .login-markdown { line-height: 1.5; margin: 1rem 0; }
    .login-markdown p { margin: 0 0 0.5rem 0; }
    .login-markdown p:last-child { margin-bottom: 0; }
    .login-markdown ul, .login-markdown ol { margin: 0 0 0.5rem 0; padding-left: 1.5rem; }
    .login-markdown a { color: var(--app-link, #58a6ff); }
  </style>
</head>
<body>
  <div class="login-box">
    ${logoHtml}
    ${logoUrl ? "" : "<h1>Elenko</h1>"}
    <p class="sub">Log in to continue</p>
    ${loginTextAboveHtml ? `<div class="login-markdown">${loginTextAboveHtml}</div>` : ""}
    ${err}
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <button type="submit" class="btn">Log in</button>
    </form>
    ${loginTextBelowHtml ? `<div class="login-markdown">${loginTextBelowHtml}</div>` : ""}
  </div>
</body>
</html>`;
}

function renderChangePasswordPage(errorMessage, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Change password</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 24rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="password"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    .btn-secondary { display: inline-block; margin-top: 0.5rem; background: #21262d; color: #e6edf3; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; }
    .btn-secondary:hover { background: #30363d; }
    .login-err { color: #f85149; margin-top: 1rem; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="sub">Change password</p>
  ${err}
  <form method="post" action="/account/change-password">
    <label for="currentPassword">Current password</label>
    <input type="password" id="currentPassword" name="currentPassword" required autofocus>
    <label for="newPassword">New password</label>
    <input type="password" id="newPassword" name="newPassword" required>
    <label for="confirmPassword">Confirm new password</label>
    <input type="password" id="confirmPassword" name="confirmPassword" required>
    <button type="submit" class="btn">Change password</button>
  </form>
  <a href="/" class="btn-secondary">Cancel</a>
</body>
</html>`;
}

function renderCouchDbPasswordPage(appUi, errorMessage, successMessage, formAction, isSetupFlow) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const err = errorMessage ? `<p class="msg err">${escapeHtml(errorMessage)}</p>` : "";
  const ok = successMessage ? `<p class="msg ok">${escapeHtml(successMessage)}</p>` : "";
  const action = formAction || "/account/couchdb-password";
  const sub = isSetupFlow
    ? "You are connected with the default password. Set a new password below; it will be saved to CouchDB and to the bootstrap file so the app can connect after restart."
    : "Change the password for the CouchDB <code>admin</code> user. The new password is written to CouchDB, then verified by reconnecting. The encrypted bootstrap file and Application config are updated so the app can connect after restart.";
  const cancelHref = isSetupFlow ? "/setup" : "/";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – CouchDB password</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 28rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="password"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    .btn-secondary { display: inline-block; margin-top: 0.5rem; background: #21262d; color: #e6edf3; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; }
    .btn-secondary:hover { background: #30363d; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2e1a; color: #7ee787; }
  </style>
</head>
<body>
  <div class="actions" style="margin-bottom:1rem;"><a href="${escapeHtml(cancelHref)}" class="btn-secondary">← ${isSetupFlow ? "Setup" : "Profiles"}</a></div>
  <h1>CouchDB password</h1>
  <p class="sub">${sub}</p>
  ${err}
  ${ok}
  <form method="post" action="${escapeHtml(action)}">
    <label for="currentPassword">Current CouchDB password</label>
    <input type="password" id="currentPassword" name="currentPassword" required autofocus autocomplete="current-password"${isSetupFlow ? ' placeholder="admin"' : ""}>
    <label for="newPassword">New password</label>
    <input type="password" id="newPassword" name="newPassword" required autocomplete="new-password">
    <label for="confirmPassword">Confirm new password</label>
    <input type="password" id="confirmPassword" name="confirmPassword" required autocomplete="new-password">
    <button type="submit" class="btn">Change CouchDB password</button>
  </form>
  <a href="${escapeHtml(cancelHref)}" class="btn-secondary">Cancel</a>
</body>
</html>`;
}

function renderEditAppConfigPage(appUi, err) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const bg = toHex6(theme.background);
  const text = toHex6(theme.text);
  const label = toHex6(theme.label);
  const link = toHex6(theme.link);
  const tableBg = toHex6(theme.tableBg);
  const tableHeaderBg = toHex6(theme.tableHeaderBg);
  const tableHeaderText = toHex6(theme.tableHeaderText);
  const tableBorder = toHex6(theme.tableBorder);
  const logoUrl = appUi && typeof appUi.logoUrl === "string" ? appUi.logoUrl : "";
  const logoWidth = appUi && appUi.logoWidth ? String(appUi.logoWidth) : "";
  const logoHeight = appUi && appUi.logoHeight ? String(appUi.logoHeight) : "";
  const loginTextAbove = (appUi && typeof appUi.loginTextAbove === "string") ? appUi.loginTextAbove : "";
  const loginTextBelow = (appUi && typeof appUi.loginTextBelow === "string") ? appUi.loginTextBelow : "";
  const id = appUi && appUi._id ? String(appUi._id) : "";
  const rev = appUi && appUi._rev ? String(appUi._rev) : "";
  const msgErr = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Application design</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 40rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="text"], input[type="number"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input[type="text"]:focus, input[type="number"]:focus { outline: none; border-color: #58a6ff; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: var(--app-bg, #0f1419); color: #e6edf3; text-decoration: none; margin-left: 0.5rem; border: 1px solid var(--app-table-border, #30363d); }
    .btn-secondary:hover { background: #161b22; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    .el-theme-colours { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem; width: 100%; }
    .el-theme-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 2.5rem minmax(0, 1fr);
      align-items: center;
      gap: 0.5rem;
      width: 100%;
      min-width: 0;
    }
    .el-theme-row > label { display: block; margin: 0; font-size: 0.875rem; min-width: 0; word-break: break-word; }
    .el-theme-row > input[type="color"] {
      width: 2.5rem; height: 2.5rem; min-width: 2.5rem; min-height: 2.5rem; max-width: 2.5rem; max-height: 2.5rem;
      padding: 2px; margin: 0; cursor: pointer; border: 1px solid #30363d; border-radius: 4px; background: #161b22; box-sizing: border-box; justify-self: center;
    }
    .el-theme-row > input[type="text"] {
      width: 100%; min-width: 0; margin: 0; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 0.875rem;
    }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .logo-preview { margin-top: 0.75rem; }
    .logo-preview img { max-width: 100%; border-radius: 4px; border: 1px solid #30363d; background: #161b22; padding: 0.5rem; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/" class="btn-secondary" style="display:inline-block;padding:0.5rem 1rem 0.5rem 1rem;">← Profiles</a>
    <button type="submit" form="app-config-form" class="btn btn-primary" style="margin-left:1rem;">Save</button>
    <button type="button" id="set-default-theme-btn" class="btn btn-secondary" style="margin-left:0.5rem;">Set to default</button>
    <a href="/" class="btn btn-secondary">Cancel</a>
  </div>
  <h1>Application design</h1>
  <p class="sub">Global colours and logo/header image used on the login page, start page, and configuration pages. Defaults match the current dark theme.</p>
  ${msgErr}
  <form id="app-config-form">
    ${id ? `<input type="hidden" id="appConfigId" name="_id" value="${escapeHtml(id)}">` : ""}
    ${rev ? `<input type="hidden" id="appConfigRev" name="_rev" value="${escapeHtml(rev)}">` : ""}
    <label>Theme (colours)</label>
    <p class="sub" style="margin-top:0.25rem;">Click the swatch to pick a colour, or edit the hex value.</p>
    <div class="el-theme-colours">
      <div class="el-theme-row"><label for="theme-background">Background</label><input type="color" id="theme-background" value="${escapeHtml(bg)}"><input type="text" id="theme-background-hex" value="${escapeHtml(bg)}" placeholder="#0f1419"></div>
      <div class="el-theme-row"><label for="theme-text">Text</label><input type="color" id="theme-text" value="${escapeHtml(text)}"><input type="text" id="theme-text-hex" value="${escapeHtml(text)}" placeholder="#e6edf3"></div>
      <div class="el-theme-row"><label for="theme-label">Label</label><input type="color" id="theme-label" value="${escapeHtml(label)}"><input type="text" id="theme-label-hex" value="${escapeHtml(label)}" placeholder="#8b949e"></div>
      <div class="el-theme-row"><label for="theme-link">Link</label><input type="color" id="theme-link" value="${escapeHtml(link)}"><input type="text" id="theme-link-hex" value="${escapeHtml(link)}" placeholder="#58a6ff"></div>
      <div class="el-theme-row"><label for="theme-tableBg">Table background</label><input type="color" id="theme-tableBg" value="${escapeHtml(tableBg)}"><input type="text" id="theme-tableBg-hex" value="${escapeHtml(tableBg)}" placeholder="#161b22"></div>
      <div class="el-theme-row"><label for="theme-tableHeaderBg">Table header bg</label><input type="color" id="theme-tableHeaderBg" value="${escapeHtml(tableHeaderBg)}"><input type="text" id="theme-tableHeaderBg-hex" value="${escapeHtml(tableHeaderBg)}" placeholder="#21262d"></div>
      <div class="el-theme-row"><label for="theme-tableHeaderText">Table header text</label><input type="color" id="theme-tableHeaderText" value="${escapeHtml(tableHeaderText)}"><input type="text" id="theme-tableHeaderText-hex" value="${escapeHtml(tableHeaderText)}" placeholder="#8b949e"></div>
      <div class="el-theme-row"><label for="theme-tableBorder">Table border</label><input type="color" id="theme-tableBorder" value="${escapeHtml(tableBorder)}"><input type="text" id="theme-tableBorder-hex" value="${escapeHtml(tableBorder)}" placeholder="#21262d"></div>
    </div>
    <label for="logoUrl">Logo / header image URL</label>
    <input type="text" id="logoUrl" name="logoUrl" placeholder="/logo.png or https://…" value="${escapeHtml(logoUrl)}">
    <p class="sub" style="margin-top:0.25rem;">Optional. URL or path. For a file in the <code>public/</code> directory (e.g. in Docker), omit <code>/public/</code> and use the path from the site root, e.g. <code>/logo.png</code>.</p>
    <div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-top:0.5rem;">
      <div style="flex:0 0 8rem;">
        <label for="logoWidth">Logo width (px)</label>
        <input type="number" id="logoWidth" name="logoWidth" min="0" step="1" placeholder="0 = auto" value="${escapeHtml(logoWidth)}">
      </div>
      <div style="flex:0 0 8rem;">
        <label for="logoHeight">Logo height (px)</label>
        <input type="number" id="logoHeight" name="logoHeight" min="0" step="1" placeholder="0 = auto" value="${escapeHtml(logoHeight)}">
      </div>
    </div>
    ${
      logoUrl
        ? `<div class="logo-preview">
      <p class="sub" style="margin-top:0.5rem;">Preview:</p>
      <img src="${escapeHtml(logoUrl)}" alt="Application logo preview"
           style="${logoWidth ? `width:${escapeHtml(logoWidth)}px;` : ""}${logoHeight ? `height:${escapeHtml(logoHeight)}px;` : ""}">
    </div>`
        : ""
    }
    <label for="loginTextAbove">Login page text (above form)</label>
    <textarea id="loginTextAbove" name="loginTextAbove" rows="3" placeholder="Optional. Shown below the logo, above the login fields. Markdown supported." style="width:100%;padding:0.5rem;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:1rem;font-family:inherit;resize:vertical;">${escapeHtml(loginTextAbove)}</textarea>
    <p class="sub" style="margin-top:0.25rem;">Rendered as Markdown on the login page.</p>
    <label for="loginTextBelow" style="margin-top:1rem;">Login page text (below form)</label>
    <textarea id="loginTextBelow" name="loginTextBelow" rows="3" placeholder="Optional. Shown below the login button. Markdown supported." style="width:100%;padding:0.5rem;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:1rem;font-family:inherit;resize:vertical;">${escapeHtml(loginTextBelow)}</textarea>
    <p class="sub" style="margin-top:0.25rem;">Rendered as Markdown on the login page.</p>
  </form>
  <div id="msg" class="msg" style="display:none;"></div>
  <script>
    (function() {
      function bindColorPair(colorId, textId) {
        var c = document.getElementById(colorId);
        var t = document.getElementById(textId);
        if (!c || !t) return;
        c.addEventListener('input', function() {
          t.value = c.value;
        });
        t.addEventListener('input', function() {
          var v = t.value.trim();
          if (!v) return;
          if (!v.startsWith('#')) v = '#' + v;
          t.value = v;
          c.value = v;
        });
      }
      bindColorPair('theme-background', 'theme-background-hex');
      bindColorPair('theme-text', 'theme-text-hex');
      bindColorPair('theme-label', 'theme-label-hex');
      bindColorPair('theme-link', 'theme-link-hex');
      bindColorPair('theme-tableBg', 'theme-tableBg-hex');
      bindColorPair('theme-tableHeaderBg', 'theme-tableHeaderBg-hex');
      bindColorPair('theme-tableHeaderText', 'theme-tableHeaderText-hex');
      bindColorPair('theme-tableBorder', 'theme-tableBorder-hex');

      var defaultTheme = {
        background: '#0f1419',
        text: '#e6edf3',
        label: '#8b949e',
        link: '#58a6ff',
        tableBg: '#161b22',
        tableHeaderBg: '#21262d',
        tableHeaderText: '#8b949e',
        tableBorder: '#21262d'
      };
      var setDefaultBtn = document.getElementById('set-default-theme-btn');
      if (setDefaultBtn) {
        setDefaultBtn.onclick = function() {
          ['background', 'text', 'label', 'link', 'tableBg', 'tableHeaderBg', 'tableHeaderText', 'tableBorder'].forEach(function(key) {
            var colorEl = document.getElementById('theme-' + key);
            var hexEl = document.getElementById('theme-' + key + '-hex');
            var val = defaultTheme[key];
            if (colorEl) colorEl.value = val;
            if (hexEl) hexEl.value = val;
          });
          var logoUrlEl = document.getElementById('logoUrl');
          var logoWidthEl = document.getElementById('logoWidth');
          var logoHeightEl = document.getElementById('logoHeight');
          if (logoUrlEl) logoUrlEl.value = '';
          if (logoWidthEl) logoWidthEl.value = '0';
          if (logoHeightEl) logoHeightEl.value = '0';
          var loginTextAboveEl = document.getElementById('loginTextAbove');
          var loginTextBelowEl = document.getElementById('loginTextBelow');
          if (loginTextAboveEl) loginTextAboveEl.value = '';
          if (loginTextBelowEl) loginTextBelowEl.value = '';
        };
      }

      var form = document.getElementById('app-config-form');
      var msgEl = document.getElementById('msg');
      if (!form || !msgEl) return;
      form.onsubmit = async function(e) {
        e.preventDefault();
        msgEl.style.display = 'none';
        msgEl.textContent = '';
        msgEl.className = 'msg';
        var theme = {
          background: document.getElementById('theme-background-hex').value.trim() || '${escapeHtml(bg)}',
          text: document.getElementById('theme-text-hex').value.trim() || '${escapeHtml(text)}',
          label: document.getElementById('theme-label-hex').value.trim() || '${escapeHtml(label)}',
          link: document.getElementById('theme-link-hex').value.trim() || '${escapeHtml(link)}',
          tableBg: document.getElementById('theme-tableBg-hex').value.trim() || '${escapeHtml(tableBg)}',
          tableHeaderBg: document.getElementById('theme-tableHeaderBg-hex').value.trim() || '${escapeHtml(tableHeaderBg)}',
          tableHeaderText: document.getElementById('theme-tableHeaderText-hex').value.trim() || '${escapeHtml(tableHeaderText)}',
          tableBorder: document.getElementById('theme-tableBorder-hex').value.trim() || '${escapeHtml(tableBorder)}'
        };
        var loginTextAboveEl = document.getElementById('loginTextAbove');
        var loginTextBelowEl = document.getElementById('loginTextBelow');
        var payload = {
          theme,
          logoUrl: document.getElementById('logoUrl').value.trim(),
          logoWidth: document.getElementById('logoWidth').value,
          logoHeight: document.getElementById('logoHeight').value,
          loginTextAbove: loginTextAboveEl ? loginTextAboveEl.value.trim() : '',
          loginTextBelow: loginTextBelowEl ? loginTextBelowEl.value.trim() : ''
        };
        var idEl = document.getElementById('appConfigId');
        var revEl = document.getElementById('appConfigRev');
        if (idEl && idEl.value) payload._id = idEl.value;
        if (revEl && revEl.value) payload._rev = revEl.value;
        try {
          var r = await fetch('/api/app-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          var data = await r.json();
          if (!r.ok) {
            msgEl.textContent = data.error || 'Save failed';
            msgEl.className = 'msg err';
            msgEl.style.display = 'block';
            return;
          }
          msgEl.textContent = 'Saved. Reload pages to see the new design.';
          msgEl.className = 'msg';
          msgEl.style.display = 'block';
          if (data.id) {
            if (!idEl) {
              idEl = document.createElement('input');
              idEl.type = 'hidden';
              idEl.id = 'appConfigId';
              idEl.name = '_id';
              form.appendChild(idEl);
            }
            idEl.value = data.id;
          }
          if (data.rev) {
            if (!revEl) {
              revEl = document.createElement('input');
              revEl.type = 'hidden';
              revEl.id = 'appConfigRev';
              revEl.name = '_rev';
              form.appendChild(revEl);
            }
            revEl.value = data.rev;
          }
        } catch (err) {
          msgEl.textContent = err.message || 'Request failed';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
        }
      };
    })();
  </script>
</body>
</html>`;
}

function renderDataExportImportPage(profiles, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const profileOptions = profiles.length
    ? '<option value="">— Select database —</option>' + profiles.map((p) => `<option value="${escapeHtml(p._id)}">${escapeHtml(p.name || p._id)}</option>`).join("")
    : '<option value="">No databases</option>';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Export / Import data</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 36rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="radio"] { margin-right: 0.5rem; }
    input[type="file"] { margin-top: 0.35rem; color: var(--app-label, #8b949e); font-size: 0.9rem; max-width: 100%; }
    input[type="checkbox"] { margin-right: 0.5rem; vertical-align: middle; }
    .checkbox-row { margin-top: 0.75rem; }
    .checkbox-row label { display: flex; align-items: flex-start; gap: 0.35rem; margin-top: 0; cursor: pointer; }
    .checkbox-row label span { color: var(--app-text, #e6edf3); font-weight: normal; }
    select { padding: 0.35rem 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; min-width: 12rem; width: 100%; max-width: 24rem; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions .back-nav {
      display: inline-block;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      background: var(--app-bg, #0f1419);
      color: var(--app-link, #58a6ff);
      border: 1px solid transparent;
    }
    .actions .back-nav:hover { text-decoration: underline; background: var(--app-bg, #0f1419); color: var(--app-link, #58a6ff); }
    .section { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--app-table-border, #30363d); }
    .radio-group { margin-top: 0.5rem; }
    .radio-group label { display: inline; margin-top: 0; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/" class="back-nav">← Profiles</a>
  </div>
  <h1>Export / Import data</h1>
  <p class="sub">Export entry data from an Elenko database or import rows from a semicolon-separated CSV file into one.</p>

  <div class="radio-group">
    <label><input type="radio" name="dataMode" value="export" checked> Export</label>
    <label style="margin-left:1rem;"><input type="radio" name="dataMode" value="import"> Import</label>
  </div>

  <div class="section">
    <label for="data-profile">Elenko database</label>
    <select id="data-profile" aria-describedby="data-profile-hint">${profileOptions}</select>
    <p class="sub" id="data-profile-hint" style="margin-top:0.5rem;">Profile whose entries will be exported or the target for an import.</p>
  </div>

  <div id="export-data-section" class="section">
    <button type="button" id="export-data-btn" class="btn btn-primary" disabled title="Not available yet">Export data</button>
    <p class="sub" style="margin-top:0.75rem;">Export to file will be added in a later step.</p>
  </div>

  <div id="import-data-section" class="section" style="display:none;">
    <label for="import-csv-file">CSV file (semicolon-separated)</label>
    <input type="file" id="import-csv-file" accept=".csv,text/csv,text/plain">
    <p class="sub" style="margin-top:0.35rem;">Separator is <code>;</code>. Optional quotes around values; use <code>""</code> for a literal quote inside a field.</p>
    <div class="checkbox-row">
      <label>
        <input type="checkbox" id="import-header-match" checked>
        <span>Check for matching field names in the first row</span>
      </label>
    </div>
    <p class="sub" style="margin-top:0.35rem;">When checked, the first row lists column titles; they are matched to profile field names (case-insensitive). When unchecked, columns are read in profile field order (first column → first field, etc.).</p>
    <button type="button" id="import-data-btn" class="btn btn-primary" style="margin-top:1rem;">Import data</button>
  </div>

  <div id="data-import-msg" class="sub" style="display:none; margin-top:1rem; white-space:pre-wrap;"></div>

  <script>
    (function() {
      var exportSection = document.getElementById('export-data-section');
      var importSection = document.getElementById('import-data-section');
      var msgEl = document.getElementById('data-import-msg');
      var importBtn = document.getElementById('import-data-btn');
      var fileInput = document.getElementById('import-csv-file');
      var profileSel = document.getElementById('data-profile');
      var headerChk = document.getElementById('import-header-match');

      function setMode(isImport) {
        if (exportSection) exportSection.style.display = isImport ? 'none' : 'block';
        if (importSection) importSection.style.display = isImport ? 'block' : 'none';
        if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
      }
      document.querySelectorAll('input[name="dataMode"]').forEach(function(r) {
        r.addEventListener('change', function() {
          setMode(r.value === 'import');
        });
      });

      if (importBtn) {
        importBtn.addEventListener('click', function() {
          var pid = profileSel && profileSel.value ? profileSel.value.trim() : '';
          if (!pid) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Select an Elenko database first.';
            }
            return;
          }
          var file = fileInput && fileInput.files && fileInput.files[0];
          if (!file) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Choose a CSV file.';
            }
            return;
          }
          importBtn.disabled = true;
          if (msgEl) { msgEl.style.display = 'block'; msgEl.style.color = 'var(--app-label, #8b949e)'; msgEl.textContent = 'Reading file…'; }
          var reader = new FileReader();
          reader.onload = function() {
            var text = reader.result != null ? String(reader.result) : '';
            function runImport(confirmUnmatched) {
              fetch('/api/profiles/' + encodeURIComponent(pid) + '/import-data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  csvText: text,
                  firstRowHeaders: !!(headerChk && headerChk.checked),
                  confirmUnmatchedHeaders: !!confirmUnmatched
                })
              })
                .then(function(r) {
                  return r.text().then(function(t) {
                    var d = null;
                    try {
                      d = t && t.length ? JSON.parse(t) : null;
                    } catch (parseErr) {
                      return {
                        ok: false,
                        data: {
                          error:
                            'Server response was not JSON (HTTP ' +
                            r.status +
                            '). ' +
                            (parseErr && parseErr.message ? parseErr.message : '') +
                            (t && t.length ? ' — starts with: ' + t.slice(0, 120).replace(/\\s+/g, ' ') : ''),
                        },
                      };
                    }
                    return { ok: r.ok, data: d };
                  });
                })
                .then(function(o) {
                  if (o.ok && o.data && o.data.needUnmatchedHeadersConfirm && !confirmUnmatched) {
                    var un = o.data.unmatchedHeaders || [];
                    var msg =
                      'These CSV column title(s) do not match any profile field. Values in those columns will not be imported:\\n\\n' +
                      un.map(function(u) { return '\\u2022 ' + u; }).join('\\n') +
                      '\\n\\nContinue with import anyway?';
                    if (window.confirm(msg)) {
                      runImport(true);
                    } else {
                      importBtn.disabled = false;
                      if (msgEl) {
                        msgEl.style.display = 'block';
                        msgEl.style.color = 'var(--app-label, #8b949e)';
                        msgEl.textContent = 'Import cancelled.';
                      }
                    }
                    return;
                  }
                  importBtn.disabled = false;
                  if (!msgEl) return;
                  msgEl.style.display = 'block';
                  if (o.ok && o.data && o.data.ok) {
                    msgEl.style.color = '#7ee787';
                    var lines = ['Imported ' + (o.data.imported || 0) + ' row(s).'];
                    if (o.data.failed) lines.push('Failed: ' + o.data.failed + ' row(s).');
                    if (o.data.rowErrors && o.data.rowErrors.length) {
                      lines.push('');
                      o.data.rowErrors.forEach(function(err) {
                        lines.push('Line ' + err.row + ': ' + err.message);
                      });
                    }
                    msgEl.textContent = lines.join(String.fromCharCode(10));
                  } else {
                    msgEl.style.color = '#f85149';
                    msgEl.textContent = (o.data && o.data.error) ? o.data.error : 'Import failed';
                  }
                })
                .catch(function(e) {
                  importBtn.disabled = false;
                  if (msgEl) {
                    msgEl.style.display = 'block';
                    msgEl.style.color = '#f85149';
                    msgEl.textContent = e.message || 'Request failed';
                  }
                });
            }
            runImport(false);
          };
          reader.onerror = function() {
            importBtn.disabled = false;
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Could not read the file.';
            }
          };
          reader.readAsText(file, 'UTF-8');
        });
      }
    })();
  </script>
</body>
</html>`;
}

function renderConfigExportImportPage(profiles, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const profileOptions = profiles.length
    ? '<option value="">— Select database —</option>' + profiles.map((p) => `<option value="${escapeHtml(p._id)}">${escapeHtml(p.name || p._id)}</option>`).join("")
    : '<option value="">No databases</option>';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Export / Import configuration</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 36rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="radio"] { margin-right: 0.5rem; }
    select { padding: 0.35rem 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; min-width: 12rem; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; }
    .btn-primary:hover { background: #2ea043; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions .back-nav {
      display: inline-block;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      background: var(--app-bg, #0f1419);
      color: var(--app-link, #58a6ff);
      border: 1px solid transparent;
    }
    .actions .back-nav:hover { text-decoration: underline; background: var(--app-bg, #0f1419); color: var(--app-link, #58a6ff); }
    .section { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--app-table-border, #30363d); }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2e1a; color: #7ee787; }
    #import-file { margin-top: 0.5rem; }
    .radio-group { margin-top: 0.5rem; }
    .radio-group label { display: inline; margin-top: 0; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/" class="back-nav">← Profiles</a>
  </div>
  <h1>Export / Import configuration</h1>
  <p class="sub">Export configuration to a JSON file or import from a previously exported file. User data, API keys, and passwords are never exported.</p>

  <div class="radio-group">
    <label><input type="radio" name="mode" value="export" checked> Export</label>
    <label style="margin-left:1rem;"><input type="radio" name="mode" value="import"> Import</label>
  </div>

  <div id="export-section">
    <div class="section">
      <label for="export-scope">Scope</label>
      <select id="export-scope">
        <option value="profile">One Elenko database</option>
        <option value="all">All configuration documents</option>
      </select>
      <p class="sub" style="margin-top:0.25rem;">"One Elenko database" exports the selected profile and its linked entry forms and flows (and APIs / JS Processing used by those flows). "All" also includes the Application design document.</p>
    </div>
    <div class="section" id="export-profile-wrap">
      <label for="export-profile">Elenko database</label>
      <select id="export-profile">${profileOptions}</select>
    </div>
    <div class="section">
      <button type="button" id="export-btn" class="btn btn-primary">Download export file</button>
    </div>
  </div>

  <div id="import-section" style="display:none;">
    <div class="section">
      <label for="import-file">Export file (JSON)</label>
      <input type="file" id="import-file" accept=".json,application/json">
      <p class="sub" style="margin-top:0.25rem;">Select a file that was exported from this page. Existing configuration will be overwritten.</p>
    </div>
    <div class="section">
      <label><input type="checkbox" id="import-backup" checked> Backup original configuration</label>
      <p class="sub" style="margin-top:0.25rem;">Before importing, save current configuration to <code>public/backups/</code> with a timestamped filename.</p>
    </div>
    <div class="section">
      <button type="button" id="import-btn" class="btn btn-primary">Import</button>
    </div>
  </div>

  <div id="restore-section" class="section" style="margin-top:2rem; padding-top:1.5rem; border-top:1px solid var(--app-table-border, #30363d);">
    <h2 style="font-size:1.1rem; font-weight:600; margin-bottom:0.5rem;">Restore old configurations</h2>
    <p class="sub" style="margin-bottom:0.75rem;">Select a backup from <code>public/backups/</code> to restore. Existing configuration will be overwritten.</p>
    <label for="restore-select">Backup file</label>
    <select id="restore-select" style="min-width:20rem;">
      <option value="">— Load list —</option>
    </select>
    <button type="button" id="restore-btn" class="btn btn-primary" style="margin-left:0.5rem;">Restore</button>
  </div>

  <div id="msg" class="msg" style="display:none;"></div>

  <script>
    (function() {
      var modeExport = document.querySelector('input[name="mode"][value="export"]');
      var modeImport = document.querySelector('input[name="mode"][value="import"]');
      var exportSection = document.getElementById('export-section');
      var importSection = document.getElementById('import-section');
      var exportScope = document.getElementById('export-scope');
      var exportProfileWrap = document.getElementById('export-profile-wrap');
      var exportProfile = document.getElementById('export-profile');
      var exportBtn = document.getElementById('export-btn');
      var importFile = document.getElementById('import-file');
      var importBackup = document.getElementById('import-backup');
      var importBtn = document.getElementById('import-btn');
      var restoreSelect = document.getElementById('restore-select');
      var restoreBtn = document.getElementById('restore-btn');
      var msgEl = document.getElementById('msg');

      function summarizeExportCounts(payload) {
        var summary = { profiles: 0, entryForms: 0, flows: 0, apis: 0, jsProcessing: 0, appConfig: 0 };
        var docs = payload && payload.documents ? payload.documents : {};
        var dbDocs = Array.isArray(docs.db) ? docs.db : [];
        var cfgDocs = Array.isArray(docs.configDb) ? docs.configDb : [];
        dbDocs.forEach(function(doc) {
          if (!doc || typeof doc !== 'object') return;
          if (doc.type === 'elenko_profile') summary.profiles += 1;
          if (doc.type === 'elenko_entry_form') summary.entryForms += 1;
        });
        cfgDocs.forEach(function(doc) {
          if (!doc || typeof doc !== 'object') return;
          if (doc.type === 'elenko_flow') summary.flows += 1;
          if (doc.type === 'elenko_api') summary.apis += 1;
          if (doc.type === 'elenko_js_processing') summary.jsProcessing += 1;
          if (doc.type === 'elenko_app_config') summary.appConfig += 1;
        });
        return summary;
      }

      function setMode() {
        var isExport = modeExport && modeExport.checked;
        exportSection.style.display = isExport ? 'block' : 'none';
        importSection.style.display = isExport ? 'none' : 'block';
        exportProfileWrap.style.display = (exportScope && exportScope.value === 'profile') ? 'block' : 'none';
        msgEl.style.display = 'none';
      }
      function setProfileVisibility() {
        exportProfileWrap.style.display = (exportScope && exportScope.value === 'profile') ? 'block' : 'none';
      }
      if (modeExport) modeExport.addEventListener('change', setMode);
      if (modeImport) modeImport.addEventListener('change', setMode);
      if (exportScope) exportScope.addEventListener('change', setProfileVisibility);

      if (exportBtn) exportBtn.addEventListener('click', async function() {
        msgEl.style.display = 'none';
        var scope = exportScope && exportScope.value === 'all' ? 'all' : 'profile';
        var profileId = scope === 'profile' && exportProfile ? exportProfile.value : null;
        if (scope === 'profile' && !profileId) {
          msgEl.textContent = 'Select an Elenko database to export.';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
          return;
        }
        try {
          var r = await fetch('/api/config-export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope: scope, profileId: profileId })
          });
          var data = await r.json();
          if (!r.ok) {
            msgEl.textContent = data.error || 'Export failed';
            msgEl.className = 'msg err';
            msgEl.style.display = 'block';
            return;
          }
          var blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'elenko-config-export-' + (data.data.scope === 'all' ? 'all' : (data.data.profileId || 'profile')) + '-' + (data.data.exportedAt || '').slice(0, 10) + '.json';
          a.click();
          URL.revokeObjectURL(a.href);
          var c = summarizeExportCounts(data.data);
          var parts = [
            'profiles: ' + c.profiles,
            'forms: ' + c.entryForms,
            'flows: ' + c.flows,
            'APIs: ' + c.apis,
            'JS Processing: ' + c.jsProcessing
          ];
          if (c.appConfig > 0) parts.push('app config: ' + c.appConfig);
          msgEl.textContent = 'Export downloaded. Included ' + parts.join(', ') + '.';
          msgEl.className = 'msg ok';
          msgEl.style.display = 'block';
        } catch (err) {
          msgEl.textContent = err.message || 'Export failed';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
        }
      });

      if (importBtn) importBtn.addEventListener('click', async function() {
        msgEl.style.display = 'none';
        var file = importFile && importFile.files[0];
        if (!file) {
          msgEl.textContent = 'Select an export file to import.';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
          return;
        }
        try {
          if (importBackup && importBackup.checked) {
            var backupR = await fetch('/api/config-backup', { method: 'POST' });
            var backupData = await backupR.json();
            if (!backupR.ok) {
              msgEl.textContent = 'Backup failed: ' + (backupData.error || backupR.statusText);
              msgEl.className = 'msg err';
              msgEl.style.display = 'block';
              return;
            }
          }
          var text = await new Promise(function(resolve, reject) {
            var reader = new FileReader();
            reader.onload = function() { resolve(reader.result); };
            reader.onerror = reject;
            reader.readAsText(file);
          });
          var data = JSON.parse(text);
          var r = await fetch('/api/config-import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: data })
          });
          var result = await r.json();
          if (!r.ok) {
            msgEl.textContent = result.error || 'Import failed';
            msgEl.className = 'msg err';
            msgEl.style.display = 'block';
            return;
          }
          if (result.errors && result.errors.length) {
            msgEl.textContent = 'Imported ' + result.importedDb + ' main doc(s), ' + result.importedConfig + ' config doc(s). Some errors: ' + result.errors.slice(0, 3).map(function(e) { return e.id + ': ' + e.message; }).join('; ');
            msgEl.className = 'msg err';
          } else {
            msgEl.textContent = 'Imported ' + result.importedDb + ' main document(s), ' + result.importedConfig + ' config document(s).';
            msgEl.className = 'msg ok';
          }
          msgEl.style.display = 'block';
          importFile.value = '';
          if (restoreSelect) loadRestoreList();
        } catch (err) {
          msgEl.textContent = (err.message || 'Import failed') + (err.message && err.message.indexOf('JSON') !== -1 ? ' Make sure the file is a valid export JSON.' : '');
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
        }
      });

      function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }
      function loadRestoreList() {
        if (!restoreSelect) return;
        restoreSelect.innerHTML = '<option value="">Loading…</option>';
        fetch('/api/config-backups')
          .then(function(r) { return r.json(); })
          .then(function(data) {
            var list = data.backups || [];
            restoreSelect.innerHTML = list.length ? list.map(function(b) { return '<option value="' + esc(b.url) + '">' + esc(b.name) + '</option>'; }).join('') : '<option value="">No backups</option>';
          })
          .catch(function() {
            restoreSelect.innerHTML = '<option value="">Failed to load</option>';
          });
      }
      if (restoreSelect) restoreSelect.addEventListener('focus', loadRestoreList);
      if (restoreBtn) restoreBtn.addEventListener('click', async function() {
        var url = restoreSelect && restoreSelect.value;
        if (!url) {
          msgEl.textContent = 'Select a backup to restore.';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
          return;
        }
        msgEl.style.display = 'none';
        try {
          var r = await fetch(url);
          if (!r.ok) throw new Error('Failed to load backup');
          var data = await r.json();
          var impR = await fetch('/api/config-import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: data })
          });
          var result = await impR.json();
          if (!impR.ok) {
            msgEl.textContent = result.error || 'Restore failed';
            msgEl.className = 'msg err';
            msgEl.style.display = 'block';
            return;
          }
          if (result.errors && result.errors.length) {
            msgEl.textContent = 'Restored ' + result.importedDb + ' main doc(s), ' + result.importedConfig + ' config doc(s). Some errors: ' + result.errors.slice(0, 3).map(function(e) { return e.id + ': ' + e.message; }).join('; ');
            msgEl.className = 'msg err';
          } else {
            msgEl.textContent = 'Restored ' + result.importedDb + ' main document(s), ' + result.importedConfig + ' config document(s). Reload the page to see changes.';
            msgEl.className = 'msg ok';
          }
          msgEl.style.display = 'block';
        } catch (err) {
          msgEl.textContent = err.message || 'Restore failed';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
        }
      });
    })();
  </script>
</body>
</html>`;
}

function renderManageUsersPage(users, currentUsername, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const rows =
    users.length > 0
      ? users
          .map((u) => {
            const id = escapeHtml(u._id);
            const rev = escapeHtml(u._rev || "");
            const username = escapeHtml(u.username || "—");
            const role = (u.role === "admin" || u.role === "reader" ? u.role : "editor");
            const isSelf = u.username === currentUsername;
            const roleOptions = ["admin", "editor", "reader"].map((r) => `<option value="${escapeHtml(r)}"${r === role ? " selected" : ""}>${escapeHtml(r)}</option>`).join("");
            return `
        <tr data-id="${id}" data-rev="${rev}" data-username="${escapeHtml(u.username || "")}">
          <td><strong>${username}</strong></td>
          <td><select class="user-role-select" aria-label="Role">${roleOptions}</select></td>
          <td><input type="password" class="user-new-password" placeholder="New password" autocomplete="new-password" style="max-width:12rem;"> <button type="button" class="btn-set-password">Set password</button></td>
          <td>${isSelf ? '<span class="muted">(you)</span>' : `<button type="button" class="btn-delete-user">Delete</button>`}</td>
        </tr>`;
          })
          .join("")
      : `<tr><td colspan="4" class="empty">No users yet. <a href="/account/users/create">Create user</a></td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Manage users</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; max-width: 56rem; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .empty a { color: var(--app-link, #58a6ff); }
    .muted { color: var(--app-label, #8b949e); font-size: 0.9em; }
    select { padding: 0.35rem 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); }
    input[type="password"] { padding: 0.35rem 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); }
    .btn-set-password, .btn-delete-user { padding: 0.35rem 0.75rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-set-password { background: #238636; color: #fff; }
    .btn-set-password:hover { background: #2ea043; }
    .btn-delete-user { background: #da3633; color: #fff; }
    .btn-delete-user:hover { background: #f85149; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
    a { color: var(--app-link, #58a6ff); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-left: 0.5rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    a.btn:not(.btn-secondary) { color: #fff; }
    a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
  </style>
</head>
<body>
  <div><a href="/">← Profiles</a> <a href="/account/users/create" class="btn">Create user</a></div>
  <h1>Manage users</h1>
  <p class="sub">Change role, set password, or delete users.</p>
  <table>
    <thead>
      <tr>
        <th>Username</th>
        <th>Role</th>
        <th>Set password</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="msg"></div>
  <script>
    const msgEl = document.getElementById('msg');
    function showMsg(text, isErr) { msgEl.textContent = text; msgEl.className = 'msg ' + (isErr ? 'err' : 'ok'); }

    document.querySelectorAll('.user-role-select').forEach(sel => {
      sel.addEventListener('change', async function() {
        const row = this.closest('tr');
        if (!row || row.querySelector('.empty')) return;
        const id = row.getAttribute('data-id');
        const role = this.value;
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role }) });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Update failed', true); return; }
          showMsg('Role updated.');
        } catch (e) { showMsg(e.message || 'Request failed', true); }
      });
    });

    document.querySelectorAll('.btn-set-password').forEach(btn => {
      btn.addEventListener('click', async function() {
        const row = this.closest('tr');
        if (!row || row.querySelector('.empty')) return;
        const id = row.getAttribute('data-id');
        const input = row.querySelector('.user-new-password');
        const newPassword = (input && input.value || '').trim();
        if (!newPassword) { showMsg('Enter a new password.', true); return; }
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ newPassword }) });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Update failed', true); return; }
          showMsg('Password set.'); if (input) input.value = '';
        } catch (e) { showMsg(e.message || 'Request failed', true); }
      });
    });

    document.querySelectorAll('.btn-delete-user').forEach(btn => {
      btn.addEventListener('click', async function() {
        const row = this.closest('tr');
        if (!row || row.querySelector('.empty')) return;
        if (!confirm('Delete this user? This cannot be undone.')) return;
        const id = row.getAttribute('data-id');
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id), { method: 'DELETE' });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Delete failed', true); return; }
          showMsg('User deleted.'); row.remove();
        } catch (e) { showMsg(e.message || 'Request failed', true); }
      });
    });
  </script>
</body>
</html>`;
}

function renderCreateUserPage(errorMessage, created, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  const createdMsg = created ? '<p class="msg ok">User created.</p>' : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Create user</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 24rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    select { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    .btn-secondary { display: inline-block; margin-top: 0.5rem; background: #21262d; color: #e6edf3; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; }
    .btn-secondary:hover { background: #30363d; }
    .login-err { color: #f85149; margin-top: 1rem; }
    .msg.ok { color: #3fb950; margin-top: 1rem; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="sub">Create new user</p>
  ${createdMsg}
  ${err}
  <form method="post" action="/account/users/create">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    <label for="role">Role</label>
    <select id="role" name="role">
      <option value="editor">editor</option>
      <option value="reader">reader</option>
      <option value="admin">admin</option>
    </select>
    <button type="submit" class="btn">Create user</button>
  </form>
  <a href="/" class="btn-secondary">Back to start</a>
</body>
</html>`;
}

function renderLoginRequiredPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Login required</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .box { max-width: 24rem; text-align: center; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .err { color: #f85149; margin: 1rem 0; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Elenko</h1>
    <p class="err">You must log in to access this application.</p>
    <p><a href="/login">Go to login page</a></p>
  </div>
</body>
</html>`;
}

function renderForbiddenPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Forbidden</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .box { max-width: 24rem; text-align: center; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .err { color: #f85149; margin: 1rem 0; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Elenko</h1>
    <p class="err">You do not have permission to access this page.</p>
    <p><a href="/">Back to start</a></p>
  </div>
</body>
</html>`;
}

function renderSetupRequiredPage(errMessage) {
  const err = errMessage ? `<p class="err">${escapeHtml(errMessage)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Configuration required</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .box { max-width: 28rem; width: 100%; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin: 1rem 0; }
    .err { color: #f85149; margin: 1rem 0; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="password"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Elenko</h1>
    <p class="sub">The CouchDB bootstrap file is missing. The application cannot connect to the database until an administrator configures it.</p>
    <p class="sub">If you are an administrator, use the form below to set the CouchDB password (user <code>admin</code>). This will create the bootstrap file and allow the application to start.</p>
    ${err}
    <form method="post" action="/setup">
      <label for="couchdbPassword">CouchDB password (admin user)</label>
      <input type="password" id="couchdbPassword" name="couchdbPassword" required autofocus placeholder="Enter CouchDB admin password">
      <button type="submit" class="btn">Create bootstrap and connect</button>
    </form>
  </div>
</body>
</html>`;
}

function renderErrorPage(message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <title>Elenko – Error</title>
  <style>
    body { font-family: system-ui, sans-serif; padding: 2rem; background: #0f1419; color: #e6edf3; }
    .err { color: #f85149; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="err">Error: ${escapeHtml(message)}</p>
</body>
</html>`;
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function slugifyForApiKeyId(name) {
  const s = String(name == null ? "" : name).trim().toLowerCase();
  const slug = s.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "key";
  return "key_" + (slug.slice(0, 80) || "key");
}

/** Log JSON body parse failures (e.g. strict mode, invalid token at position 1) and return JSON for /api/*. */
app.use((err, req, res, next) => {
  if (err && err.status === 400 && err.type === "entity.parse.failed") {
    const raw = typeof err.body === "string" ? err.body : "";
    const first = raw.length > 0 ? raw[0] : "";
    console.error("[express.json] entity.parse.failed", {
      message: err.message,
      method: req.method,
      path: req.path,
      originalUrl: req.originalUrl,
      contentType: req.get("content-type"),
      contentLength: req.get("content-length"),
      rawLength: raw.length,
      firstCodeUnit: first ? first.charCodeAt(0) : null,
      firstCharHint:
        first === "<"
          ? "starts with '<' (often HTML or XML, not JSON)"
          : first === "" || !first
            ? "empty body string after read"
            : "see message",
      rawPreview: raw.slice(0, 1200).replace(/\r/g, "\\r").replace(/\n/g, "\\n"),
      stack: err.stack,
    });
    if (wantsJsonApiResponse(req)) {
      return res.status(400).json({
        error: "Invalid JSON in request body",
        detail: err.message,
      });
    }
  }
  next(err);
});

async function main() {
  await initCouch();
  startApiWorker();
  startFlowWorker();
  console.log(
    "Flow logging configured for",
    process.env.FLOW_LOG_FILE || path.join(__dirname, "logs", "flow.log")
  );
  const server = app.listen(PORT, "0.0.0.0", () => {
    const browserUrl = `http://127.0.0.1:${PORT}`;
    const altUrl = `http://localhost:${PORT}`;
    const openInBrowserMsg = `Open in browser: ${browserUrl} or ${altUrl}`;
    console.log(`Elenko server listening on http://0.0.0.0:${PORT}`);
    console.log(openInBrowserMsg);
    sendFlowMessage("system.start", {
      pid: process.pid,
      port: PORT,
      message: openInBrowserMsg,
      browserUrl,
      altUrl,
    });
  });
  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Port ${PORT} is already in use. Stop the other process or set PORT to a different number.`);
    } else {
      console.error("Server listen error:", err);
    }
    process.exit(1);
  });
}

main().catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
