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
const multer = require("multer");
const sharp = require("sharp");

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
/** Max elenko_records deleted in one flow "purge old" step (safety cap). */
const PURGE_OLD_MAX_DELETE = 500;
const FLOW_REFRESH_DEFAULT_TIMEOUT_MS = 15000;
const FLOW_REFRESH_POLL_INTERVAL_MS = 5000;
const PURGE_OLD_MS_PER_DAY = 24 * 60 * 60 * 1000;
const ENTRIES_PAGE_SIZE = 25;
const ENTRIES_PAGE_SIZE_MIN = 5;
const ENTRIES_PAGE_SIZE_MAX = 200;
const SORT_KEY_SPECIAL = ["createdAt", "updatedAt"];
const SORT_KEY_FIELDS_MAX = 3;
const PRIMARY_KEY_FIELDS_MAX = 3;
const DB_CODE_LEN = 8;
const PRIMARY_KEY_SEGMENT_LEN_MIN = 1;
const PRIMARY_KEY_SEGMENT_LEN_MAX = 512;
const DEFAULT_VALUE_SOURCES = ["", "createdAt", "updatedAt", "currentUser"];

/** Inline entry images: CouchDB attachments (see POST/GET .../attachments). */
const MAX_ENTRY_IMAGE_BYTES = Number(process.env.MAX_ENTRY_IMAGE_BYTES) || 2 * 1024 * 1024;
const MAX_IMAGE_DISPLAY_EDGE = Number(process.env.MAX_IMAGE_DISPLAY_EDGE) || 1600;
/** Upper bound for layout-derived upload resize (px); avoids huge server work from a typo like 99999px width. */
const MAX_IMAGE_UPLOAD_EDGE_CAP = Number(process.env.MAX_IMAGE_UPLOAD_EDGE_CAP) || 8192;
const ALLOWED_ENTRY_IMAGE_MIMES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);

const entryImageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_ENTRY_IMAGE_BYTES },
});

const MAX_KEYFILE_BYTES = 4096;
const keyFileUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_KEYFILE_BYTES },
});

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

/** Stored parallel to fieldNames: "text" (default), "file", or "repeat" (scalar rows JSON per field). */
function normalizeFieldKinds(fieldNames, raw) {
  const len = Array.isArray(fieldNames) ? fieldNames.length : 0;
  const arr = Array.isArray(raw) ? raw : [];
  const result = [];
  for (let i = 0; i < len; i++) {
    const v = arr[i];
    const s = typeof v === "string" ? v.trim().toLowerCase() : "";
    if (s === "file") result.push("file");
    else if (s === "repeat") result.push("repeat");
    else result.push("text");
  }
  return result;
}

function isProfileRepeatField(profileDoc, fieldName) {
  if (!profileDoc || !fieldName || typeof fieldName !== "string") return false;
  const fn = fieldName.trim();
  if (!fn) return false;
  const names = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const idx = names.indexOf(fn);
  if (idx < 0) return false;
  const kinds = normalizeFieldKinds(names, profileDoc.fieldKinds);
  return kinds[idx] === "repeat";
}

function isProfileFileField(profileDoc, fieldName) {
  if (!profileDoc || !fieldName || typeof fieldName !== "string") return false;
  const fn = fieldName.trim();
  if (!fn) return false;
  const names = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const idx = names.indexOf(fn);
  if (idx < 0) return false;
  const kinds = normalizeFieldKinds(names, profileDoc.fieldKinds);
  return kinds[idx] === "file";
}

/** Profile file fields plus Single Entry form Image fields — both use CouchDB attachments on the entry. */
function getAttachmentBackedFieldNames(profileDoc, formDoc) {
  const set = getImageFieldNamesFromFormLayout(formDoc);
  const names = Array.isArray(profileDoc && profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const kinds = normalizeFieldKinds(names, profileDoc && profileDoc.fieldKinds);
  for (let i = 0; i < names.length; i++) {
    if (kinds[i] === "file") set.add(names[i]);
  }
  return set;
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

function getSessionUsername(req) {
  if (!req || !req.session || req.session.user == null) return "";
  return String(req.session.user).trim();
}

/** Who created/last updated an entry (CouchDB username). Empty when no HTTP session (e.g. some flow steps). */
function setEntryAuditOnCreate(record, req) {
  const u = getSessionUsername(req);
  record.createdBy = u;
  record.updatedBy = u;
}

function setEntryAuditOnUpdate(record, req) {
  const u = getSessionUsername(req);
  if (u) record.updatedBy = u;
}

/** Set on records created via "Create entry" until the first successful save; allows cancel to delete the draft server-side. */
const ELENKO_DISCARD_ON_CANCEL = "elenko_discard_on_cancel";

/**
 * Same as POST /api/profiles/:id/entries: builds and inserts a new elenko_record.
 * @param {object} values - field values from JSON body; use {} for an empty draft (e.g. "new entry" redirect).
 * @param {{ discardOnCancel?: boolean }} [options]
 * @returns {{ ok: true, id: string, rev: string } | { ok: false, error: string, status: number }}
 */
async function insertNewEntryDocument(db, profileDoc, req, values, options) {
  const opts = options && typeof options === "object" ? options : {};
  const profileId = profileDoc._id;
  const fieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const record = { type: "elenko_record", profileId };
  for (const fn of fieldNames) {
    record[fn] = values[fn] != null ? String(values[fn]).trim() : "";
  }
  const now = new Date().toISOString();
  record.createdAt = now;
  record.updatedAt = now;
  setEntryAuditOnCreate(record, req);
  const sources = Array.isArray(profileDoc.fieldDefaultSources) ? profileDoc.fieldDefaultSources : [];
  for (let i = 0; i < fieldNames.length; i++) {
    const src = sources[i];
    if (src === "createdAt" || src === "updatedAt" || src === "currentUser") {
      record[fieldNames[i]] = resolveDefaultValue(src, req);
    }
  }
  let pdoc = profileDoc;
  pdoc = await ensureProfileDbCode8(db, pdoc);
  const sortKeyFields = Array.isArray(pdoc.sortKeyFields) ? pdoc.sortKeyFields : [];
  record.sortKey = buildSortKey(record, sortKeyFields);
  const requestedEntryFormId = typeof values.entryFormId === "string" ? values.entryFormId.trim() : "";
  const profileFormIds = getProfileEntryFormIds(pdoc);
  if (requestedEntryFormId && profileFormIds.includes(requestedEntryFormId)) {
    record.entryFormId = requestedEntryFormId;
  } else if (profileFormIds.length > 0) {
    record.entryFormId = profileFormIds[0];
  }
  try {
    applyPrimaryKeyToRecord(record, pdoc);
  } catch (e) {
    return { ok: false, error: e.message || "Primary key could not be computed.", status: 400 };
  }
  const encAccess = await resolveProfileEncryptionAccess(req, pdoc);
  if (isProfilePersonalEncryptionEnabled(pdoc) && !encAccess.ok) {
    return {
      ok: false,
      error: encAccess.error,
      status: encAccess.hidden ? 404 : encAccess.status || 403,
    };
  }
  const pkForLookup =
    encAccess.profileKey && record.primaryKey
      ? computePrimaryKeyToken(encAccess.profileKey, record.primaryKey)
      : record.primaryKey;
  if (pkForLookup) {
    const conflict = await findPrimaryKeyConflict(db, pkForLookup, "");
    if (conflict) {
      return {
        ok: false,
        error: "Duplicate primary key: another entry already uses this composite key.",
        status: 409,
      };
    }
  }
  if (encAccess.profileKey) {
    encryptRecordFieldsForStorage(record, pdoc, encAccess.profileKey, null);
  }
  if (opts.discardOnCancel) {
    record[ELENKO_DISCARD_ON_CANCEL] = true;
  }
  const result = await db.insert(record);
  clearProfileListCache(profileId);
  sendFlowMessage("entry.created", { id: result.id, profileId, fields: fieldNames });
  return { ok: true, id: result.id, rev: result.rev };
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

function normalizeEntryFieldType(raw) {
  const s = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (s === "markdown") return "markdown";
  if (s === "url") return "url";
  if (s === "image") return "image";
  if (s === "chart") return "chart";
  if (s === "repeat") return "repeat";
  return "text";
}

function normalizeRepeatSubFieldType(raw) {
  const s = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (s === "markdown" || s === "url") return s;
  return "text";
}

function normalizeRepeatColumn(item) {
  if (!item || typeof item !== "object") return null;
  const key = typeof item.key === "string" ? item.key.trim() : "";
  if (!key || !/^[\w.-]+$/.test(key)) return null;
  const label = typeof item.label === "string" && item.label.trim() ? item.label.trim() : key;
  return { key, label, fieldType: normalizeRepeatSubFieldType(item.fieldType) };
}

function normalizeRepeatColumns(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.map(normalizeRepeatColumn).filter(Boolean);
}

function normalizeRepeatMode(raw) {
  return raw === "stack" ? "stack" : "table";
}

const DEFAULT_REPEAT_COLUMNS_QA = [
  { key: "question", label: "Question", fieldType: "text" },
  { key: "answer", label: "Answer", fieldType: "text" },
];

function defaultRepeatColumnsForField(fieldName) {
  void fieldName;
  return DEFAULT_REPEAT_COLUMNS_QA.map((c) => ({ ...c }));
}

/** Per-profile-field repeat storage: { version: 1, rows: ["scalar", ...] } */
function parseProfileRepeatScalarValue(stored) {
  const storedStr = stored == null ? "" : String(stored);
  if (storedStr.trim() === "") {
    return { ok: true, rows: [] };
  }
  if (isEncryptedFieldValue(storedStr)) {
    return { ok: false, error: "Repeat field value is encrypted.", rows: [] };
  }
  let parsed;
  try {
    parsed = JSON.parse(storedStr);
  } catch (_) {
    return { ok: true, rows: [storedStr] };
  }
  if (typeof parsed === "string") {
    return { ok: true, rows: [parsed] };
  }
  if (Array.isArray(parsed)) {
    return { ok: true, rows: parsed.map((r) => (r != null ? String(r) : "")) };
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.rows)) {
    return {
      ok: true,
      rows: parsed.rows.map((r) => {
        if (r != null && typeof r === "object") {
          const vals = Object.values(r).filter((v) => v != null && String(v).trim() !== "");
          return vals.length > 0 ? String(vals[0]) : "";
        }
        return r != null ? String(r) : "";
      }),
    };
  }
  return { ok: true, rows: [storedStr] };
}

function serializeProfileRepeatScalarValue(rows) {
  const list = Array.isArray(rows) ? rows.map((r) => (r != null ? String(r) : "")) : [];
  return JSON.stringify({ version: 1, rows: list });
}

function getProfileRepeatFieldNames(profileDoc) {
  const names = Array.isArray(profileDoc && profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const kinds = normalizeFieldKinds(names, profileDoc && profileDoc.fieldKinds);
  return names.filter((fn, idx) => kinds[idx] === "repeat");
}

/** Repeat fields from profile kinds, or inferred from stored repeat JSON on the entry. */
function profileDialogRepeatFieldNames(profileDoc, record) {
  const fromKinds = getProfileRepeatFieldNames(profileDoc);
  if (fromKinds.length > 0) return fromKinds;
  const names = Array.isArray(profileDoc && profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const inferred = names.filter((fn) => isProfileRepeatScalarJson(record && record[fn]));
  return inferred.length > 0 ? inferred : fromKinds;
}

function maxRepeatScalarRowCount(record, profileDoc) {
  let max = 0;
  for (const fn of profileDialogRepeatFieldNames(profileDoc, record)) {
    const parsed = parseProfileRepeatScalarValue(record && record[fn]);
    if (parsed.ok) max = Math.max(max, parsed.rows.length);
  }
  return max;
}

/** Row index for API response: last row with content in sibling repeat fields (e.g. last PROMPT). */
function resolveCorrespondingRepeatRowIndex(record, profileDoc, targetFieldName) {
  let bestIndex = -1;
  for (const fn of profileDialogRepeatFieldNames(profileDoc, record)) {
    if (fn === targetFieldName) continue;
    const parsed = parseProfileRepeatScalarValue(record && record[fn]);
    if (!parsed.ok) continue;
    for (let i = parsed.rows.length - 1; i >= 0; i--) {
      if (String(parsed.rows[i] || "").trim() !== "") {
        bestIndex = Math.max(bestIndex, i);
        break;
      }
    }
  }
  if (bestIndex >= 0) return bestIndex;
  const maxRows = maxRepeatScalarRowCount(record, profileDoc);
  if (maxRows > 0) return maxRows - 1;
  const parsed = parseProfileRepeatScalarValue(record && record[targetFieldName]);
  if (parsed.ok && parsed.rows.length > 0) return parsed.rows.length - 1;
  return 0;
}

function shouldMergePlainTextIntoRepeatField(value) {
  const s = String(value ?? "").trim();
  if (!s) return true;
  return !isProfileRepeatScalarJson(s);
}

function shouldApplyRepeatScalarCellWrite(profileDoc, record, fieldName, incomingValue) {
  if (!shouldMergePlainTextIntoRepeatField(incomingValue)) return false;
  if (isProfileRepeatField(profileDoc, fieldName)) return true;
  const dialogFields = profileDialogRepeatFieldNames(profileDoc, record);
  return dialogFields.length > 0 && dialogFields.includes(fieldName);
}

/** Write plain text into one row of a profile repeat field; sibling fields define the row index. */
function applyPlainValueToProfileField(profileDoc, record, fieldName, incomingValue) {
  if (!profileDoc || !record || !shouldApplyRepeatScalarCellWrite(profileDoc, record, fieldName, incomingValue)) {
    return incomingValue != null ? String(incomingValue) : "";
  }
  const rowIndex = resolveCorrespondingRepeatRowIndex(record, profileDoc, fieldName);
  const cellValue = incomingValue != null ? String(incomingValue) : "";
  let maxRows = maxRepeatScalarRowCount(record, profileDoc);
  maxRows = Math.max(maxRows, rowIndex + 1);

  const targetParsed = parseProfileRepeatScalarValue(record[fieldName]);
  let rows = targetParsed.ok ? [...targetParsed.rows] : [];

  const storedStr = record[fieldName] != null ? String(record[fieldName]).trim() : "";
  if (storedStr && !isProfileRepeatScalarJson(storedStr) && rowIndex > 0 && rows.length === 1) {
    rows = new Array(maxRows).fill("");
  } else {
    while (rows.length < maxRows) rows.push("");
  }
  rows[rowIndex] = cellValue;
  return serializeProfileRepeatScalarValue(rows);
}

/** Write plain text into a specific repeat row (view-mode draft edits). */
function applyPlainValueToProfileFieldAtRow(profileDoc, record, fieldName, rowIndex, incomingValue) {
  if (!profileDoc || !record || rowIndex < 0) {
    return incomingValue != null ? String(incomingValue) : "";
  }
  if (!shouldApplyRepeatScalarCellWrite(profileDoc, record, fieldName, incomingValue)) {
    return incomingValue != null ? String(incomingValue) : "";
  }
  const cellValue = incomingValue != null ? String(incomingValue) : "";
  let maxRows = maxRepeatScalarRowCount(record, profileDoc);
  maxRows = Math.max(maxRows, rowIndex + 1);
  const targetParsed = parseProfileRepeatScalarValue(record[fieldName]);
  let rows = targetParsed.ok ? [...targetParsed.rows] : [];
  while (rows.length < maxRows) rows.push("");
  rows[rowIndex] = cellValue;
  return serializeProfileRepeatScalarValue(rows);
}

function getDraftRepeatRowIndex(record) {
  if (!record || record.draftRepeatRowIndex == null || record.draftRepeatRowIndex === "") return -1;
  const idx = parseInt(record.draftRepeatRowIndex, 10);
  return Number.isFinite(idx) && idx >= 0 ? idx : -1;
}

function mergeDraftRepeatEditsIntoDataset(context, profileDoc, edits) {
  if (!context || !profileDoc || !edits || typeof edits !== "object" || Array.isArray(edits)) return;
  const dataset = context.dataset && typeof context.dataset === "object" ? { ...context.dataset } : {};
  const draftIdx = getDraftRepeatRowIndex(dataset);
  if (draftIdx < 0) return;
  const patch = { ...dataset };
  for (const key of Object.keys(edits)) {
    if (key === "rowIndex") continue;
    const val = edits[key];
    if (isProfileRepeatField(profileDoc, key) || profileDialogRepeatFieldNames(profileDoc, patch).includes(key)) {
      patch[key] = applyPlainValueToProfileFieldAtRow(profileDoc, patch, key, draftIdx, val);
    }
  }
  context.dataset = patch;
}

function mergeRepeatGroupRowsFromRecord(record, columns) {
  const cols = normalizeRepeatColumns(columns);
  if (cols.length === 0) return [];
  const arrays = cols.map((c) => {
    const raw = record && record[c.key] != null ? record[c.key] : "";
    const parsed = parseProfileRepeatScalarValue(raw);
    return parsed.ok ? parsed.rows : [];
  });
  const maxLen = Math.max(0, ...arrays.map((a) => a.length));
  const rows = [];
  for (let i = 0; i < maxLen; i++) {
    const row = {};
    for (let j = 0; j < cols.length; j++) {
      row[cols[j].key] = arrays[j][i] != null ? String(arrays[j][i]) : "";
    }
    rows.push(row);
  }
  return rows;
}

function splitRepeatGroupRowsToFieldValues(rows, columns) {
  const cols = normalizeRepeatColumns(columns);
  const list = Array.isArray(rows) ? rows : [];
  const out = {};
  for (const c of cols) {
    const arr = list.map((row) => (row && row[c.key] != null ? String(row[c.key]) : ""));
    out[c.key] = serializeProfileRepeatScalarValue(arr);
  }
  return out;
}

function summarizeProfileRepeatScalarForList(value) {
  const parsed = parseProfileRepeatScalarValue(value);
  if (!parsed.ok) return "(invalid repeat data)";
  if (parsed.rows.length === 0) return "empty";
  const first = parsed.rows[0];
  return first != null && String(first).trim() !== "" ? String(first) : "empty";
}

/** True when stored value is profile repeat scalar JSON ({ rows: ["a", ...] }), not combined object rows. */
function isProfileRepeatScalarJson(value) {
  const s = String(value || "").trim();
  if (!s.startsWith("{") && !s.startsWith("[")) return false;
  if (isEncryptedFieldValue(s)) return false;
  try {
    let parsed = JSON.parse(s);
    if (Array.isArray(parsed)) {
      return parsed.every((r) => r == null || typeof r !== "object");
    }
    if (parsed && typeof parsed === "object" && Array.isArray(parsed.rows)) {
      return parsed.rows.every((r) => r == null || typeof r !== "object");
    }
  } catch (_) {}
  return false;
}

function summarizeRepeatFieldValueForList(profileDoc, fieldName, value) {
  if (isProfileRepeatField(profileDoc, fieldName) || isProfileRepeatScalarJson(value)) {
    return summarizeProfileRepeatScalarForList(value);
  }
  if (looksLikeRepeatFieldJson(value)) {
    return summarizeRepeatFieldForList(value);
  }
  return value != null ? String(value) : "";
}

function isRepeatGroupLayoutItem(item) {
  if (!item || normalizeEntryFieldType(item.fieldType) !== "repeat") return false;
  const cols = normalizeRepeatColumns(item.repeatColumns);
  if (cols.length === 0) return false;
  const fn = typeof item.fieldName === "string" ? item.fieldName.trim() : "";
  return item.repeatGroup === true || !fn;
}

function legacyPlainTextAsRepeatFirstRow(stored, cols) {
  const text = stored != null ? String(stored) : "";
  const row = {};
  for (const c of cols) {
    row[c.key] = "";
  }
  if (cols.length > 0) {
    row[cols[0].key] = text;
  }
  return { ok: true, data: { version: 1, rows: [row] }, columns: cols };
}

/** @returns {{ ok: true, data: { version: number, rows: object[] }, columns: object[] } | { ok: false, error: string }} */
function parseRepeatFieldValue(stored, columns) {
  const defaultCols =
    normalizeRepeatColumns(columns).length > 0
      ? normalizeRepeatColumns(columns)
      : defaultRepeatColumnsForField("");
  const empty = { version: 1, rows: [] };
  const storedStr = stored == null ? "" : String(stored);
  if (storedStr.trim() === "") {
    return { ok: true, data: empty, columns: defaultCols };
  }
  if (isEncryptedFieldValue(storedStr)) {
    return { ok: false, error: "Repeat field value is encrypted." };
  }
  let parsed;
  try {
    parsed = JSON.parse(storedStr);
  } catch (_) {
    return legacyPlainTextAsRepeatFirstRow(storedStr, defaultCols);
  }
  if (typeof parsed === "string") {
    return legacyPlainTextAsRepeatFirstRow(parsed, defaultCols);
  }
  if (Array.isArray(parsed)) {
    parsed = { version: 1, rows: parsed };
  }
  if (!parsed || typeof parsed !== "object") {
    return legacyPlainTextAsRepeatFirstRow(storedStr, defaultCols);
  }
  if (!Array.isArray(parsed.rows)) {
    return legacyPlainTextAsRepeatFirstRow(storedStr, defaultCols);
  }
  const colsFromData = Array.isArray(parsed.columns) ? normalizeRepeatColumns(parsed.columns) : [];
  const cols = colsFromData.length > 0 ? colsFromData : defaultCols;
  const rawRows = Array.isArray(parsed.rows) ? parsed.rows : [];
  const rows = rawRows.map((row) => {
    const out = {};
    for (const c of cols) {
      out[c.key] = row && row[c.key] != null ? String(row[c.key]) : "";
    }
    return out;
  });
  return { ok: true, data: { version: 1, rows }, columns: cols };
}

function serializeRepeatFieldValue(rows) {
  const list = Array.isArray(rows) ? rows : [];
  return JSON.stringify({ version: 1, rows: list });
}

function appendRepeatRowToFieldValue(stored, columns, newRow) {
  const parsed = parseRepeatFieldValue(stored, columns);
  if (!parsed.ok) {
    throw new Error(parsed.error || "Invalid repeat field value.");
  }
  const row = {};
  for (const c of parsed.columns) {
    row[c.key] = newRow && newRow[c.key] != null ? String(newRow[c.key]) : "";
  }
  const rows = parsed.data.rows.slice();
  rows.push(row);
  return serializeRepeatFieldValue(rows);
}

/**
 * Param forms:
 * - PROMPT,RESPONSE — multi-field repeat group (profile field names)
 * - legacyField|col1,col2 — single combined JSON field (legacy)
 * - fieldName — legacy single field, columns from form
 */
function parseAppendRepeatParam(param) {
  const s = typeof param === "string" ? param.trim() : "";
  if (!s) return { profileFieldNames: [], columnKeys: null, legacyFieldName: "" };
  const pipeIdx = s.indexOf("|");
  if (pipeIdx !== -1) {
    const legacyFieldName = s.slice(0, pipeIdx).trim();
    const keysPart = s.slice(pipeIdx + 1).trim();
    const columnKeys = keysPart
      ? keysPart
          .split(",")
          .map((k) => k.trim())
          .filter(Boolean)
      : null;
    return {
      profileFieldNames: legacyFieldName ? [legacyFieldName] : [],
      columnKeys,
      legacyFieldName,
    };
  }
  if (s.includes(",")) {
    const profileFieldNames = s.split(",").map((k) => k.trim()).filter(Boolean);
    return { profileFieldNames, columnKeys: profileFieldNames, legacyFieldName: "" };
  }
  return { profileFieldNames: [s], columnKeys: null, legacyFieldName: s };
}

function getRepeatGroupLayoutFromForm(formDoc) {
  if (!formDoc || !Array.isArray(formDoc.fieldLayout)) return null;
  for (const item of formDoc.fieldLayout) {
    if (isRepeatGroupLayoutItem(item)) return item;
  }
  return null;
}

function buildRepeatRowFromDataset(columns, dataset, profileDoc) {
  const row = {};
  const explicit = dataset && dataset._repeatRow;
  if (explicit && typeof explicit === "object" && !Array.isArray(explicit)) {
    for (const c of columns) {
      row[c.key] = explicit[c.key] != null ? String(explicit[c.key]) : "";
    }
    return row;
  }
  for (const c of columns) {
    const raw = dataset && dataset[c.key] != null ? String(dataset[c.key]) : "";
    if (profileDoc && isProfileRepeatField(profileDoc, c.key)) {
      row[c.key] = shouldMergePlainTextIntoRepeatField(raw) ? raw : "";
    } else if (isProfileRepeatScalarJson(raw)) {
      row[c.key] = "";
    } else {
      row[c.key] = raw;
    }
  }
  return row;
}

async function loadEntryFormDocForContext(dbInstance, context) {
  if (!dbInstance || !context || !context.profileId) return null;
  let profileDoc = context.profileDoc;
  if (!profileDoc) {
    try {
      const pd = await dbInstance.get(context.profileId);
      if (pd && pd.type === "elenko_profile") {
        profileDoc = pd;
        context.profileDoc = pd;
      }
    } catch (_) {}
  }
  let record = context.dataset;
  if (context.entryId && (!record || record._id !== context.entryId)) {
    try {
      record = await dbInstance.get(context.entryId);
    } catch (_) {}
  }
  const formIds = getProfileEntryFormIds(profileDoc);
  const formId = record && record.entryFormId ? String(record.entryFormId).trim() : formIds[0] || "";
  if (!formId) return null;
  try {
    const formDoc = await dbInstance.get(formId);
    return formDoc && formDoc.type === "elenko_entry_form" ? formDoc : null;
  } catch (_) {
    return null;
  }
}

/** Infer PROMPT,RESPONSE (etc.) when the flow step Param is empty. */
async function resolveAppendRepeatParam(dbInstance, context, param) {
  const trimmed = typeof param === "string" ? param.trim() : "";
  if (trimmed) return trimmed;

  let profileDoc = context.profileDoc;
  if (!profileDoc && dbInstance && context.profileId) {
    try {
      const pd = await dbInstance.get(context.profileId);
      if (pd && pd.type === "elenko_profile") {
        profileDoc = pd;
        context.profileDoc = pd;
      }
    } catch (_) {}
  }

  const fromProfile = profileDoc ? getProfileRepeatFieldNames(profileDoc) : [];
  if (fromProfile.length > 0) return fromProfile.join(",");

  const formDoc = await loadEntryFormDocForContext(dbInstance, context);
  const groupItem = getRepeatGroupLayoutFromForm(formDoc);
  if (groupItem) {
    const keys = normalizeRepeatColumns(groupItem.repeatColumns)
      .map((c) => c.key)
      .filter(Boolean);
    if (keys.length > 0) return keys.join(",");
  }

  return "";
}

function getRepeatLayoutItemFromForm(formDoc, fieldName) {
  if (!formDoc || !Array.isArray(formDoc.fieldLayout)) return null;
  const fn = typeof fieldName === "string" ? fieldName.trim() : "";
  if (!fn) return null;
  for (const item of formDoc.fieldLayout) {
    if (item && item.fieldName === fn && normalizeEntryFieldType(item.fieldType) === "repeat") {
      return item;
    }
  }
  return null;
}

async function loadRepeatColumnsForEntryField(dbInstance, profileId, entryId, fieldName) {
  let profileDoc;
  try {
    profileDoc = await dbInstance.get(profileId);
  } catch (_) {
    return defaultRepeatColumnsForField(fieldName);
  }
  let record = null;
  if (entryId) {
    try {
      record = await dbInstance.get(entryId);
    } catch (_) {}
  }
  let formDoc = null;
  const formIds = getProfileEntryFormIds(profileDoc);
  const formId = record && record.entryFormId ? String(record.entryFormId).trim() : formIds[0] || "";
  if (formId) {
    try {
      formDoc = await dbInstance.get(formId);
    } catch (_) {}
  }
  const layoutItem = getRepeatLayoutItemFromForm(formDoc, fieldName);
  if (layoutItem) {
    const cols = normalizeRepeatColumns(layoutItem.repeatColumns);
    if (cols.length > 0) return cols;
  }
  const stored = record && record[fieldName] != null ? String(record[fieldName]) : "";
  if (stored && !isEncryptedFieldValue(stored)) {
    const parsed = parseRepeatFieldValue(stored, []);
    if (parsed.ok && parsed.columns.length > 0) return parsed.columns;
  }
  return defaultRepeatColumnsForField(fieldName);
}

async function loadRepeatGroupColumns(dbInstance, profileId, entryId, profileFieldNames) {
  if (profileFieldNames && profileFieldNames.length > 0) {
    return profileFieldNames.map((k) => ({ key: k, label: k, fieldType: "text" }));
  }
  let profileDoc;
  let formDoc = null;
  let record = null;
  if (dbInstance && profileId) {
    try {
      profileDoc = await dbInstance.get(profileId);
    } catch (_) {}
    if (entryId) {
      try {
        record = await dbInstance.get(entryId);
      } catch (_) {}
    }
    const formIds = getProfileEntryFormIds(profileDoc);
    const formId = record && record.entryFormId ? String(record.entryFormId).trim() : formIds[0] || "";
    if (formId) {
      try {
        formDoc = await dbInstance.get(formId);
      } catch (_) {}
    }
  }
  const groupItem = getRepeatGroupLayoutFromForm(formDoc);
  if (groupItem) {
    const cols = normalizeRepeatColumns(groupItem.repeatColumns);
    if (cols.length > 0) return cols;
  }
  return defaultRepeatColumnsForField("");
}

async function appendRepeatGroupRowToContext(dbInstance, context, profileFieldNames, columns) {
  const fieldNames = Array.isArray(profileFieldNames) ? profileFieldNames.filter(Boolean) : [];
  if (fieldNames.length === 0) {
    throw new Error("Param must list profile repeat field names (e.g. PROMPT,RESPONSE).");
  }
  const cols =
    columns && columns.length > 0
      ? columns
      : fieldNames.map((k) => ({ key: k, label: k, fieldType: "text" }));
  const dataset = context.dataset && typeof context.dataset === "object" ? { ...context.dataset } : {};
  let existing = null;
  if (context.entryId && dbInstance) {
    try {
      existing = await dbInstance.get(context.entryId);
    } catch (_) {}
  }
  let profileDoc = context.profileDoc;
  if (!profileDoc && dbInstance && context.profileId) {
    try {
      const pd = await dbInstance.get(context.profileId);
      if (pd && pd.type === "elenko_profile") profileDoc = pd;
    } catch (_) {}
  }
  const newRow = buildRepeatRowFromDataset(cols, dataset, profileDoc);
  let rowCount = 0;
  for (const fn of fieldNames) {
    let stored = dataset[fn] != null ? String(dataset[fn]) : "";
    if (!stored && existing && existing[fn] != null) stored = String(existing[fn]);
    if (isEncryptedFieldValue(stored)) {
      throw new Error("Cannot append to encrypted repeat field in this flow context.");
    }
    const parsed = parseProfileRepeatScalarValue(stored);
    const rows = parsed.ok ? parsed.rows.slice() : [];
    rows.push(newRow[fn] != null ? String(newRow[fn]) : "");
    dataset[fn] = serializeProfileRepeatScalarValue(rows);
    rowCount = Math.max(rowCount, rows.length);
  }
  context.dataset = {
    ...dataset,
    _lastAppendRepeatFields: fieldNames,
    _lastAppendRepeatRowCount: rowCount,
    draftRepeatRowIndex: rowCount > 0 ? rowCount - 1 : 0,
  };
  return { fieldNames, newRow, rowCount };
}

async function appendRepeatRowToContext(dbInstance, context, param) {
  const resolvedParam = await resolveAppendRepeatParam(dbInstance, context, param);
  const { profileFieldNames, columnKeys, legacyFieldName } = parseAppendRepeatParam(resolvedParam);

  if (profileFieldNames.length > 1 || (profileFieldNames.length >= 1 && !legacyFieldName && columnKeys && columnKeys.length > 1)) {
    const names = columnKeys && columnKeys.length > 0 ? columnKeys : profileFieldNames;
    let columns = names.map((k) => ({ key: k, label: k, fieldType: "text" }));
    if (dbInstance && context && context.profileId) {
      const fromForm = await loadRepeatGroupColumns(dbInstance, context.profileId, context.entryId, names);
      if (fromForm.length > 0) columns = fromForm;
    }
    const groupRes = await appendRepeatGroupRowToContext(dbInstance, context, names, columns);
    return { ...groupRes, resolvedParam };
  }

  const fieldName = legacyFieldName || profileFieldNames[0] || "";
  if (!fieldName) {
    throw new Error(
      "Append repeat row needs field names (e.g. PROMPT,RESPONSE). Set Param on the flow step, or configure repeat fields on the profile / repeat group on the entry form."
    );
  }

  let columns;
  if (columnKeys && columnKeys.length > 0) {
    columns = columnKeys.map((k) => ({ key: k, label: k, fieldType: "text" }));
  } else if (dbInstance && context && context.profileId) {
    columns = await loadRepeatColumnsForEntryField(dbInstance, context.profileId, context.entryId, fieldName);
  } else {
    columns = defaultRepeatColumnsForField(fieldName);
  }

  const dataset = context.dataset && typeof context.dataset === "object" ? { ...context.dataset } : {};
  let currentStored = dataset[fieldName] != null ? String(dataset[fieldName]) : "";
  if (isEncryptedFieldValue(currentStored)) {
    throw new Error("Cannot append to encrypted repeat field in this flow context.");
  }
  if (!currentStored && context.entryId && dbInstance) {
    try {
      const existing = await dbInstance.get(context.entryId);
      if (existing && existing[fieldName] != null) {
        currentStored = String(existing[fieldName]);
        if (isEncryptedFieldValue(currentStored)) {
          throw new Error("Cannot append to encrypted repeat field in this flow context.");
        }
      }
    } catch (e) {
      if (e && e.message && String(e.message).includes("encrypted repeat")) throw e;
    }
  }

  let profileDoc = context.profileDoc;
  if (!profileDoc && dbInstance && context.profileId) {
    try {
      const pd = await dbInstance.get(context.profileId);
      if (pd && pd.type === "elenko_profile") profileDoc = pd;
    } catch (_) {}
  }
  const newRow = buildRepeatRowFromDataset(columns, dataset, profileDoc);
  const updatedJson = appendRepeatRowToFieldValue(currentStored, columns, newRow);
  let rowCount = 0;
  try {
    rowCount = JSON.parse(updatedJson).rows.length;
  } catch (_) {}
  context.dataset = {
    ...dataset,
    [fieldName]: updatedJson,
    _lastAppendRepeatField: fieldName,
    _lastAppendRepeatRowCount: rowCount,
    draftRepeatRowIndex: rowCount > 0 ? rowCount - 1 : 0,
  };
  return { fieldName, updatedJson, newRow, rowCount, resolvedParam };
}

function summarizeRepeatFieldForList(value) {
  const parsed = parseRepeatFieldValue(value, []);
  if (!parsed.ok) return "(invalid repeat data)";
  const n = parsed.data.rows.length;
  if (n === 0) return "empty";
  return n === 1 ? "1 row" : n + " rows";
}

function looksLikeRepeatFieldJson(value) {
  const s = String(value || "").trim();
  if (!s.startsWith("{")) return false;
  try {
    const o = JSON.parse(s);
    return !!(o && typeof o === "object" && Array.isArray(o.rows));
  } catch (_) {
    return false;
  }
}

function compactMarkdownForDisplay(value) {
  let t = String(value != null ? value : "")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  t = t.replace(/\n{3,}/g, "\n\n");
  t = t.replace(/\n\n+(?=[-*+] )/gm, "\n");
  t = t.replace(/\n\n+(?=\d+\. )/gm, "\n");
  t = t.replace(/(#{1,6}[^\n]*)\n\n+(?=[-*+]\s|\d+\.\s)/gm, "$1\n");
  t = t.replace(/(^[-*+] .*(?:\n|$))(?:[ \t]*\n)+(?=[-*+] )/gm, "$1");
  t = t.replace(/(^\d+\. .*(?:\n|$))(?:[ \t]*\n)+(?=\d+\. )/gm, "$1");
  t = t.replace(/([^\n])\n(#{1,6}\s)/gm, "$1\n\n$2");
  return t.trim();
}

function tightenMarkdownDisplayHtml(html) {
  if (!html || typeof html !== "string") return html;
  return html
    .replace(/<p>\s*<\/p>/gi, "")
    .replace(/<\/ul>\s*<ul>/gi, "")
    .replace(/<\/ol>\s*<ol>/gi, "");
}

function parseMarkdownToDisplayHtml(value) {
  try {
    const html = marked.parse(compactMarkdownForDisplay(value));
    return typeof html === "string" ? tightenMarkdownDisplayHtml(html) : escapeHtml(value);
  } catch (_) {
    return escapeHtml(value);
  }
}

function formatRepeatSubValueHtml(fieldType, value) {
  const v = value != null ? String(value) : "";
  if (!v) return "";
  const ft = normalizeRepeatSubFieldType(fieldType);
  if (ft === "markdown") {
    return parseMarkdownToDisplayHtml(v);
  }
  if (ft === "url") {
    const raw = v.trim();
    const escapedText = escapeHtml(raw);
    const hrefRaw = /^(https?:\/\/|mailto:|tel:)/i.test(raw) ? raw : "https://" + raw;
    return `<a href="${escapeHtml(hrefRaw)}" target="_blank" rel="noopener noreferrer">${escapedText}</a>`;
  }
  return escapeHtml(v);
}

function formatRepeatFieldHtml(value, o) {
  const parsed = parseRepeatFieldValue(value, o.repeatColumns || []);
  if (!parsed.ok) {
    return `<span class="entry-repeat-error">${escapeHtml(parsed.error)}</span>`;
  }
  const { data, columns } = parsed;
  if (columns.length === 0) {
    return '<span class="entry-repeat-empty">No columns configured.</span>';
  }
  const mode = normalizeRepeatMode(o.repeatMode);
  if (data.rows.length === 0) {
    return '<span class="entry-repeat-empty">No rows yet.</span>';
  }
  if (mode === "stack") {
    return (
      `<div class="entry-repeat-stack">` +
      data.rows
        .map(
          (row, idx) =>
            `<div class="entry-repeat-stack-block">` +
            `<div class="entry-repeat-stack-head">#${idx + 1}</div>` +
            columns
              .map(
                (c) =>
                  `<div class="entry-repeat-stack-field"><div class="entry-repeat-col-label">${escapeHtml(c.label)}</div><div class="entry-repeat-col-value${c.fieldType === "markdown" ? " entry-repeat-col-markdown" : ""}">${formatRepeatSubValueHtml(c.fieldType, row[c.key])}</div></div>`
              )
              .join("") +
            `</div>`
        )
        .join("") +
      `</div>`
    );
  }
  const head = `<tr>${columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}</tr>`;
  const body = data.rows
    .map(
      (row) =>
        `<tr>${columns.map((c) => `<td${c.fieldType === "markdown" ? ' class="entry-repeat-col-markdown"' : ""}>${formatRepeatSubValueHtml(c.fieldType, row[c.key])}</td>`).join("")}</tr>`
    )
    .join("");
  return `<table class="entry-repeat-table elenko-entry-fields-table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function formatRepeatGroupRowCellHtml(column, value, isDraftRow) {
  if (isDraftRow) return buildRepeatCellEditInputHtml(column, value);
  return formatRepeatSubValueHtml(column.fieldType, value);
}

function formatRepeatGroupHtml(record, o) {
  const columns = normalizeRepeatColumns(o.repeatColumns || []);
  if (columns.length === 0) {
    return '<span class="entry-repeat-empty">No columns configured.</span>';
  }
  const rows = mergeRepeatGroupRowsFromRecord(record || {}, columns);
  const mode = normalizeRepeatMode(o.repeatMode);
  const draftRowIndex = getDraftRepeatRowIndex(record || {});
  if (rows.length === 0) {
    return '<span class="entry-repeat-empty">No rows yet.</span>';
  }
  if (mode === "stack") {
    return (
      `<div class="entry-repeat-stack">` +
      rows
        .map(
          (row, idx) => {
            const isDraft = idx === draftRowIndex;
            return (
              `<div class="entry-repeat-stack-block${isDraft ? " entry-repeat-draft-row" : ""}"${isDraft ? ' data-draft-row="1"' : ""}>` +
              `<div class="entry-repeat-stack-head">#${idx + 1}${isDraft ? ' <span class="entry-repeat-draft-badge">Draft</span>' : ""}</div>` +
              columns
                .map((c) => {
                  const inner = formatRepeatGroupRowCellHtml(c, row[c.key], isDraft);
                  if (isDraft) {
                    return `<div class="entry-repeat-stack-field"><div class="entry-repeat-col-label">${escapeHtml(c.label)}</div><div class="entry-repeat-col-value entry-repeat-col-draft">${inner}</div></div>`;
                  }
                  return `<div class="entry-repeat-stack-field"><div class="entry-repeat-col-label">${escapeHtml(c.label)}</div><div class="entry-repeat-col-value${c.fieldType === "markdown" ? " entry-repeat-col-markdown" : ""}">${inner}</div></div>`;
                })
                .join("") +
              `</div>`
            );
          }
        )
        .join("") +
      `</div>`
    );
  }
  const head = `<tr>${columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}</tr>`;
  const body = rows
    .map(
      (row, idx) => {
        const isDraft = idx === draftRowIndex;
        return (
          `<tr${isDraft ? ' class="entry-repeat-draft-row" data-draft-row="1"' : ""}>` +
          columns
            .map((c) => {
              if (isDraft) {
                return `<td class="entry-repeat-col-draft">${formatRepeatGroupRowCellHtml(c, row[c.key], true)}</td>`;
              }
              return `<td${c.fieldType === "markdown" ? ' class="entry-repeat-col-markdown"' : ""}>${formatRepeatSubValueHtml(c.fieldType, row[c.key])}</td>`;
            })
            .join("") +
          `</tr>`
        );
      }
    )
    .join("");
  return `<table class="entry-repeat-table elenko-entry-fields-table"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function buildRepeatCellEditInputHtml(column, cellVal) {
  const key = escapeHtml(column.key);
  const escapedVal = escapeHtml(cellVal != null ? String(cellVal) : "");
  const ft = normalizeRepeatSubFieldType(column.fieldType);
  if (ft === "url") {
    return `<input type="url" class="entry-repeat-cell" data-col-key="${key}" data-col-type="url" value="${escapedVal}">`;
  }
  if (ft === "markdown") {
    return `<textarea class="entry-repeat-cell entry-repeat-cell-textarea entry-repeat-cell-markdown" data-col-key="${key}" data-col-type="markdown" rows="6" spellcheck="false">${escapedVal}</textarea>`;
  }
  return `<textarea class="entry-repeat-cell entry-repeat-cell-textarea" data-col-key="${key}" data-col-type="text" rows="2">${escapedVal}</textarea>`;
}

function renderRepeatColumnEditorRowsHtml(columns, fieldName) {
  const cols = normalizeRepeatColumns(columns);
  const list = cols.length > 0 ? cols : defaultRepeatColumnsForField(fieldName || "");
  return list
    .map((c) => {
      const ft = normalizeRepeatSubFieldType(c.fieldType);
      return (
        `<tr class="fl-repeat-col-row">` +
        `<td><input type="text" class="fl-repeat-col-key" value="${escapeHtml(c.key)}" placeholder="PROMPT"></td>` +
        `<td><input type="text" class="fl-repeat-col-label" value="${escapeHtml(c.label)}" placeholder="Label"></td>` +
        `<td><select class="fl-repeat-col-type">` +
        `<option value="text"${ft === "text" ? " selected" : ""}>Text</option>` +
        `<option value="markdown"${ft === "markdown" ? " selected" : ""}>Markdown</option>` +
        `<option value="url"${ft === "url" ? " selected" : ""}>URL</option>` +
        `</select></td>` +
        `<td><button type="button" class="btn btn-remove fl-repeat-col-remove" aria-label="Remove column">Remove</button></td>` +
        `</tr>`
      );
    })
    .join("");
}

function buildRepeatFormDesignerConfigHtml(options) {
  const opts = options && typeof options === "object" ? options : {};
  const styleAttr = opts.visible ? "" : ' style="display:none;"';
  const mode = normalizeRepeatMode(opts.repeatMode);
  const addLabel =
    typeof opts.repeatAddLabel === "string" && opts.repeatAddLabel.trim() ? opts.repeatAddLabel.trim() : "Add row";
  const colRows = renderRepeatColumnEditorRowsHtml(opts.repeatColumns, opts.fieldName);
  return (
    `<div class="fl-repeat-config"${styleAttr}>` +
    `<label class="fl-repeat-sub-label">Repeat layout</label>` +
    `<select class="fl-repeat-mode"><option value="table"${mode === "table" ? " selected" : ""}>Table</option><option value="stack"${mode === "stack" ? " selected" : ""}>Vertical stack</option></select>` +
    `<label class="fl-repeat-sub-label">Add button label</label>` +
    `<input type="text" class="fl-repeat-add-label" value="${escapeHtml(addLabel)}" placeholder="Add row">` +
    `<label class="fl-repeat-sub-label">Profile fields (one row index links columns)</label>` +
    `<table class="fl-repeat-cols-table"><thead><tr><th>Profile field</th><th>Label</th><th>Type</th><th></th></tr></thead><tbody class="fl-repeat-cols-tbody">${colRows}</tbody></table>` +
    `<button type="button" class="btn btn-secondary fl-repeat-col-add" style="margin-top:0.35rem;">+ Add column</button>` +
    `</div>`
  );
}

function buildRepeatGroupEditControlHtml(record, o) {
  const columns =
    normalizeRepeatColumns(o.repeatColumns).length > 0
      ? normalizeRepeatColumns(o.repeatColumns)
      : defaultRepeatColumnsForField("");
  let rows = mergeRepeatGroupRowsFromRecord(record || {}, columns);
  if (rows.length === 0) {
    const emptyRow = {};
    for (const c of columns) emptyRow[c.key] = "";
    rows = [emptyRow];
  }
  const mode = normalizeRepeatMode(o.repeatMode);
  const addLabel =
    typeof o.repeatAddLabel === "string" && o.repeatAddLabel.trim()
      ? o.repeatAddLabel.trim()
      : "Add row";
  const colsJson = escapeHtml(JSON.stringify(columns));
  const fieldValues = splitRepeatGroupRowsToFieldValues(rows, columns);
  const hiddenInputs = columns
    .map((c) => {
      const fn = escapeHtml(c.key);
      const val = escapeHtml(fieldValues[c.key] || serializeProfileRepeatScalarValue([]));
      return `<input type="hidden" class="entry-field entry-repeat-field-json" name="${fn}" data-repeat-field="${fn}" value="${val}">`;
    })
    .join("");

  let rowsHtml;
  if (mode === "stack") {
    rowsHtml = rows
      .map(
        (row, idx) =>
          `<div class="entry-repeat-row entry-repeat-stack-row" data-row-index="${idx}">` +
          `<div class="entry-repeat-stack-row-head"><span>#${idx + 1}</span><button type="button" class="btn btn-secondary entry-repeat-remove">Remove</button></div>` +
          columns
            .map((c) => {
              const cellVal = row[c.key] != null ? String(row[c.key]) : "";
              return `<label class="entry-repeat-stack-edit-field"><span class="entry-repeat-col-label">${escapeHtml(c.label)}</span>${buildRepeatCellEditInputHtml(c, cellVal)}</label>`;
            })
            .join("") +
          `</div>`
      )
      .join("");
  } else {
    const head = `<tr>${columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}<th></th></tr>`;
    const body = rows
      .map(
        (row, idx) =>
          `<tr class="entry-repeat-row" data-row-index="${idx}">` +
          columns
            .map((c) => {
              const cellVal = row[c.key] != null ? String(row[c.key]) : "";
              return `<td>${buildRepeatCellEditInputHtml(c, cellVal)}</td>`;
            })
            .join("") +
          `<td><button type="button" class="btn btn-secondary entry-repeat-remove">Remove</button></td></tr>`
      )
      .join("");
    rowsHtml = `<table class="entry-repeat-edit-table"><thead>${head}</thead><tbody class="entry-repeat-tbody">${body}</tbody></table>`;
  }

  return (
    `<div class="entry-repeat-wrap entry-repeat-group" data-repeat-group="1" data-repeat-mode="${escapeHtml(mode)}" data-repeat-columns="${colsJson}">` +
    hiddenInputs +
    `<div class="entry-repeat-body">${rowsHtml}</div>` +
    `<div class="entry-repeat-actions"><button type="button" class="btn btn-secondary entry-repeat-add">${escapeHtml(addLabel)}</button></div>` +
    `</div>`
  );
}

function buildRepeatEditControlHtml(o, value) {
  const parsed = parseRepeatFieldValue(value, o.repeatColumns || []);
  const columns =
    parsed.ok && parsed.columns.length > 0
      ? parsed.columns
      : normalizeRepeatColumns(o.repeatColumns).length > 0
        ? normalizeRepeatColumns(o.repeatColumns)
        : defaultRepeatColumnsForField(o.fieldName);
  let rows = parsed.ok ? parsed.data.rows : [];
  if (rows.length === 0) {
    const emptyRow = {};
    for (const c of columns) emptyRow[c.key] = "";
    rows = [emptyRow];
  }
  const mode = normalizeRepeatMode(o.repeatMode);
  const addLabel =
    typeof o.repeatAddLabel === "string" && o.repeatAddLabel.trim()
      ? o.repeatAddLabel.trim()
      : "Add row";
  const storedJson = serializeRepeatFieldValue(rows);
  const colsJson = escapeHtml(JSON.stringify(columns));
  const escapedName = escapeHtml(o.fieldName);

  let rowsHtml;
  if (mode === "stack") {
    rowsHtml = rows
      .map(
        (row, idx) =>
          `<div class="entry-repeat-row entry-repeat-stack-row" data-row-index="${idx}">` +
          `<div class="entry-repeat-stack-row-head"><span>#${idx + 1}</span><button type="button" class="btn btn-secondary entry-repeat-remove">Remove</button></div>` +
          columns
            .map((c) => {
              const cellVal = row[c.key] != null ? String(row[c.key]) : "";
              return `<label class="entry-repeat-stack-edit-field"><span class="entry-repeat-col-label">${escapeHtml(c.label)}</span>${buildRepeatCellEditInputHtml(c, cellVal)}</label>`;
            })
            .join("") +
          `</div>`
      )
      .join("");
  } else {
    const head = `<tr>${columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}<th></th></tr>`;
    const body = rows
      .map(
        (row, idx) =>
          `<tr class="entry-repeat-row" data-row-index="${idx}">` +
          columns
            .map((c) => {
              const cellVal = row[c.key] != null ? String(row[c.key]) : "";
              return `<td>${buildRepeatCellEditInputHtml(c, cellVal)}</td>`;
            })
            .join("") +
          `<td><button type="button" class="btn btn-secondary entry-repeat-remove">Remove</button></td></tr>`
      )
      .join("");
    rowsHtml = `<table class="entry-repeat-edit-table"><thead>${head}</thead><tbody class="entry-repeat-tbody">${body}</tbody></table>`;
  }

  return (
    `<div class="entry-repeat-wrap" data-repeat-mode="${escapeHtml(mode)}" data-repeat-columns="${colsJson}">` +
    `<input type="hidden" class="entry-field entry-repeat-json" name="${escapedName}" value="${escapeHtml(storedJson)}">` +
    `<div class="entry-repeat-body">${rowsHtml}</div>` +
    `<div class="entry-repeat-actions"><button type="button" class="btn btn-secondary entry-repeat-add">${escapeHtml(addLabel)}</button></div>` +
    `</div>`
  );
}

/** Cap for Chart field series length (request/DoS guard). */
const ENTRY_CHART_MAX_POINTS = 25000;

/**
 * Chart field JSON — version 1
 *
 * Full object:
 *   {
 *     "version": 1,
 *     "chartType": "line" | "bar" | "scatter",
 *     "title": "optional",
 *     "xAxis": { "title": "X axis", "values": [ ... ] },
 *     "yAxis": { "title": "Y axis", "values": [ ... ] },
 *     "heightPx": 280
 *   }
 * - yAxis.values (or top-level "y") is required. xAxis.values optional; if omitted, X labels are "0" .. "n-1".
 * - Lengths of xAxis.values and yAxis.values must match when xAxis.values is present.
 * - scatter: xAxis.values required; all entries must be finite numbers (linear X scale).
 * - heightPx: optional canvas container height (120..900).
 * Shorthand: a JSON array of numbers is treated as y values (line chart, index labels).
 *
 * @returns {{ ok: true, spec: object } | { ok: false, error: string }}
 */
function normalizeEntryChartSpec(parsed) {
  let obj = parsed;
  if (obj != null && Array.isArray(obj)) {
    const y = [];
    for (const v of obj) {
      const n = Number(v);
      if (Number.isFinite(n)) y.push(n);
    }
    if (y.length === 0) return { ok: false, error: "Array has no numeric y values." };
    if (y.length > ENTRY_CHART_MAX_POINTS) return { ok: false, error: "Too many data points." };
    return {
      ok: true,
      spec: {
        chartType: "line",
        title: "",
        heightPx: 280,
        xTitle: "Index",
        yTitle: "Value",
        labels: y.map((_, i) => String(i)),
        xNumeric: null,
        y,
      },
    };
  }
  if (!obj || typeof obj !== "object") return { ok: false, error: "Chart field must be a JSON object or number array." };

  const ver = obj.version == null ? 1 : Number(obj.version);
  if (!Number.isFinite(ver) || ver !== 1) return { ok: false, error: "Unsupported chart version (use 1)." };

  const ctRaw = String(obj.chartType || "line").trim().toLowerCase();
  const chartType = ctRaw === "bar" || ctRaw === "scatter" ? ctRaw : "line";

  const title = obj.title != null ? String(obj.title) : "";

  let yVals = [];
  if (obj.yAxis && Array.isArray(obj.yAxis.values)) {
    for (const v of obj.yAxis.values) {
      const n = Number(v);
      if (Number.isFinite(n)) yVals.push(n);
      else return { ok: false, error: "yAxis.values must be numeric." };
    }
  } else if (Array.isArray(obj.y)) {
    for (const v of obj.y) {
      const n = Number(v);
      if (Number.isFinite(n)) yVals.push(n);
      else return { ok: false, error: "y must be numeric." };
    }
  }
  if (yVals.length === 0) return { ok: false, error: "Missing yAxis.values or y array." };
  if (yVals.length > ENTRY_CHART_MAX_POINTS) return { ok: false, error: "Too many data points." };

  const xa = obj.xAxis && typeof obj.xAxis === "object" ? obj.xAxis : null;
  const xTitle = xa && xa.title != null ? String(xa.title) : chartType === "scatter" ? "X" : "";
  const yTitle =
    obj.yAxis && typeof obj.yAxis === "object" && obj.yAxis.title != null ? String(obj.yAxis.title) : "Y";

  let heightPx = 280;
  if (obj.heightPx != null) {
    const h = Number(obj.heightPx);
    if (Number.isFinite(h) && h >= 120 && h <= 900) heightPx = Math.round(h);
  }

  if (chartType === "scatter") {
    if (!xa || !Array.isArray(xa.values) || xa.values.length === 0) {
      return { ok: false, error: "scatter requires xAxis.values (numeric, same length as y)." };
    }
    if (xa.values.length !== yVals.length) return { ok: false, error: "x and y length mismatch." };
    const xNumeric = [];
    for (const v of xa.values) {
      const n = Number(v);
      if (!Number.isFinite(n)) return { ok: false, error: "scatter requires numeric xAxis.values." };
      xNumeric.push(n);
    }
    return {
      ok: true,
      spec: { chartType: "scatter", title, heightPx, xTitle, yTitle, labels: null, xNumeric, y: yVals },
    };
  }

  let labels;
  if (xa && Array.isArray(xa.values)) {
    if (xa.values.length !== yVals.length) return { ok: false, error: "x and y length mismatch." };
    labels = xa.values.map((v) => (v == null ? "" : String(v)));
  } else {
    labels = yVals.map((_, i) => String(i));
  }

  return {
    ok: true,
    spec: {
      chartType,
      title,
      heightPx,
      xTitle,
      yTitle,
      labels,
      xNumeric: null,
      y: yVals,
    },
  };
}

function escapeJsonForInlineScript(jsonStr) {
  return String(jsonStr).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

function entryChartDomSlug(fieldName) {
  return "elenko_ch_" + String(fieldName || "chart").replace(/[^a-zA-Z0-9_-]/g, "_");
}

function formatEntryChartFieldHtml(fieldName, value) {
  if (value == null || String(value).trim() === "") {
    return '<p class="empty">No chart data.</p>';
  }
  let parsed;
  try {
    parsed = JSON.parse(String(value));
  } catch {
    return '<p class="entry-chart-error">Invalid JSON in chart field.</p>';
  }
  const norm = normalizeEntryChartSpec(parsed);
  if (!norm.ok) {
    return '<p class="entry-chart-error">' + escapeHtml(norm.error) + "</p>";
  }
  const spec = norm.spec;
  const slug = entryChartDomSlug(fieldName);
  const canvasId = slug + "_canvas";
  const specId = slug + "_spec";
  const h = spec.heightPx || 280;
  const payload = escapeJsonForInlineScript(JSON.stringify(spec));
  return (
    '<div class="entry-chart-mount" data-elenko-chart="1" style="height:' +
    escapeHtml(String(h)) +
    'px;position:relative;width:100%;min-width:0;max-width:100%;">' +
    '<canvas class="entry-chart-canvas" id="' +
    escapeHtml(canvasId) +
    '" aria-label="' +
    escapeHtml(spec.title || "Chart") +
    '"></canvas>' +
    '<script type="application/json" class="entry-chart-spec" id="' +
    escapeHtml(specId) +
    '">' +
    payload +
    "</script></div>"
  );
}

function entryViewChartInitScript() {
  return `(function(){function tc(){var b=document.body;return b&&(getComputedStyle(b).color||"").trim()||"#e6edf3";}function cfg(spec){var textColor=tc(),grid="rgba(139,148,158,0.28)";var titlePl=spec.title?{display:true,text:spec.title,color:textColor,font:{size:14}}:{display:false};var legendPl={labels:{color:textColor}};var axisTitle=function(t){return{display:!!(t&&String(t).trim()),text:t||"",color:textColor,font:{size:11}};};if(spec.chartType==="scatter"){return{type:"scatter",data:{datasets:[{label:spec.title||spec.yTitle||"Y",data:spec.xNumeric.map(function(x,i){return{x:x,y:spec.y[i]};}),borderColor:"#58a6ff",backgroundColor:"rgba(88,166,255,0.45)",pointRadius:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:legendPl,title:titlePl},scales:{x:{type:"linear",title:axisTitle(spec.xTitle),grid:{color:grid},ticks:{color:textColor}},y:{title:axisTitle(spec.yTitle),grid:{color:grid},ticks:{color:textColor}}}}};}var fill=spec.chartType==="line";return{type:spec.chartType==="bar"?"bar":"line",data:{labels:spec.labels,datasets:[{label:spec.title||spec.yTitle||"Y",data:spec.y,borderColor:"#58a6ff",backgroundColor:spec.chartType==="bar"?"rgba(88,166,255,0.55)":"rgba(88,166,255,0.12)",fill:fill,tension:0.15}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:legendPl,title:titlePl},scales:{x:{title:axisTitle(spec.xTitle),grid:{color:grid},ticks:{color:textColor,maxRotation:45,minRotation:0}},y:{title:axisTitle(spec.yTitle),grid:{color:grid},ticks:{color:textColor}}}}};}function run(){if(typeof Chart==="undefined")return;document.querySelectorAll(".entry-chart-mount[data-elenko-chart]").forEach(function(mount){var specEl=mount.querySelector('script.entry-chart-spec[type="application/json"]');var canvas=mount.querySelector("canvas.entry-chart-canvas");if(!specEl||!canvas)return;var spec;try{spec=JSON.parse(specEl.textContent||"{}");}catch(e){return;}var prev=typeof Chart.getChart==="function"?Chart.getChart(canvas):null;if(prev)prev.destroy();try{new Chart(canvas,cfg(spec));}catch(e){}});}if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",run);else run();})();`;
}

/** Safe attachment name for CouchDB (basename, no path segments). */
function normalizeEntryAttachmentFilename(original) {
  let s = path.basename(String(original || "").trim().replace(/\\/g, "/"));
  if (!s || s === "." || s === "..") return "";
  s = s.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9._-]/g, "");
  if (s.length > 200) s = s.slice(0, 200);
  return s;
}

function entryImageMimeToExt(mime) {
  if (mime === "image/jpeg") return ".jpg";
  if (mime === "image/png") return ".png";
  if (mime === "image/webp") return ".webp";
  if (mime === "image/gif") return ".gif";
  return "";
}

/** Non-image MIME types allowed for profile-level "file" fields (extend as needed). */
const ALLOWED_PROFILE_FILE_ATTACHMENT_MIMES = new Set(["application/pdf", "text/plain"]);

function attachmentMimeToExt(mime) {
  const img = entryImageMimeToExt(mime);
  if (img) return img;
  if (mime === "application/pdf") return ".pdf";
  if (mime === "text/plain") return ".txt";
  return "";
}

function getImageFieldNamesFromFormLayout(formDoc) {
  const out = new Set();
  if (!formDoc || !Array.isArray(formDoc.fieldLayout)) return out;
  for (const item of formDoc.fieldLayout) {
    if (
      item &&
      typeof item.fieldName === "string" &&
      item.fieldName.trim() &&
      normalizeEntryFieldType(item.fieldType) === "image"
    ) {
      out.add(item.fieldName.trim());
    }
  }
  return out;
}

function getFieldLayoutItemForFieldName(formDoc, fieldName) {
  if (!formDoc || !Array.isArray(formDoc.fieldLayout) || !fieldName) return null;
  const fn = String(fieldName).trim();
  for (const item of formDoc.fieldLayout) {
    if (item && typeof item.fieldName === "string" && item.fieldName.trim() === fn) return item;
  }
  return null;
}

/**
 * Maps Single Entry form field "width" (CSS-like) to a max edge in pixels for upload-time resize.
 * Unknown units fall back to MAX_IMAGE_DISPLAY_EDGE.
 */
function uploadMaxEdgeFromFieldLayoutWidth(widthRaw) {
  const fallback = MAX_IMAGE_DISPLAY_EDGE;
  const cap = Math.max(MAX_IMAGE_UPLOAD_EDGE_CAP, fallback);
  const clamp = (n) => {
    const x = Math.floor(Number(n));
    if (!Number.isFinite(x)) return fallback;
    return Math.min(Math.max(x, 1), cap);
  };
  if (widthRaw == null) return clamp(fallback);
  const w = String(widthRaw).trim();
  if (!w) return clamp(fallback);
  let m = /^(\d+(?:\.\d+)?)px$/i.exec(w);
  if (m) return clamp(m[1]);
  m = /^(\d+(?:\.\d+)?)%$/i.exec(w);
  if (m) {
    const p = Number(m[1]);
    if (Number.isFinite(p) && p > 0) return clamp((fallback * p) / 100);
  }
  m = /^(\d+(?:\.\d+)?)ch$/i.exec(w);
  if (m) return clamp(Number(m[1]) * 9);
  m = /^(\d+(?:\.\d+)?)rem$/i.exec(w);
  if (m) return clamp(Number(m[1]) * 16);
  m = /^(\d+(?:\.\d+)?)em$/i.exec(w);
  if (m) return clamp(Number(m[1]) * 16);
  m = /^(\d+(?:\.\d+)?)$/.exec(w);
  if (m) return clamp(m[1]);
  return clamp(fallback);
}

/** Max files per request for Export/Import data → picture import (admin). */
const MAX_PICTURE_IMPORT_FILES = 500;

/**
 * Resize / name an image like POST .../attachments (image path). Used for bulk picture import.
 * @returns {{ ok: true, outBuffer: Buffer, outMime: string, safeName: string } | { ok: false, error: string }}
 */
async function prepareImageAttachmentPayloadForProfileField(profileDoc, formDoc, fieldName, buffer, originalname, mime) {
  const fn = fieldName && typeof fieldName === "string" ? fieldName.trim() : "";
  if (!fn) return { ok: false, error: "Missing field name." };
  const formImageField = getImageFieldNamesFromFormLayout(formDoc).has(fn);
  const profileFileField = isProfileFileField(profileDoc, fn);
  if (!formImageField && !profileFileField) {
    return { ok: false, error: "Field is not a profile file field or a Single Entry image field." };
  }
  let normMime =
    mime && String(mime).split(";")[0] ? String(mime).split(";")[0].trim().toLowerCase() : "";
  if (!ALLOWED_ENTRY_IMAGE_MIMES.has(normMime)) {
    return { ok: false, error: "Only JPEG, PNG, WebP, and GIF are supported for picture import." };
  }
  const treatAsImage = formImageField || (profileFileField && ALLOWED_ENTRY_IMAGE_MIMES.has(normMime));
  if (!treatAsImage) {
    return { ok: false, error: "Picture import applies to images only for this field." };
  }
  let meta;
  try {
    meta = await sharp(buffer, { failOn: "truncated" }).metadata();
    if (!meta.width || !meta.height) {
      return { ok: false, error: "Invalid image file." };
    }
  } catch (_) {
    return { ok: false, error: "Invalid image file." };
  }
  const layoutItem = getFieldLayoutItemForFieldName(formDoc, fn);
  const layoutWidthStr =
    layoutItem && typeof layoutItem.width === "string" && layoutItem.width.trim()
      ? layoutItem.width.trim()
      : "";
  const uploadMaxEdge = uploadMaxEdgeFromFieldLayoutWidth(layoutWidthStr || undefined);
  const exceedsLayout = meta.width > uploadMaxEdge || meta.height > uploadMaxEdge;
  let outBuffer = buffer;
  let outMime = normMime;
  if (exceedsLayout) {
    try {
      outBuffer = await sharp(buffer)
        .rotate()
        .resize(uploadMaxEdge, uploadMaxEdge, { fit: "inside", withoutEnlargement: true })
        .jpeg({ quality: 85, mozjpeg: true })
        .toBuffer();
      outMime = "image/jpeg";
    } catch (e) {
      console.warn("Picture import resize failed:", e && e.message);
      return { ok: false, error: "Could not process image." };
    }
  }
  let baseName = normalizeEntryAttachmentFilename(originalname);
  if (!baseName) baseName = "image";
  if (exceedsLayout) {
    const stem = baseName.includes(".") ? baseName.slice(0, baseName.lastIndexOf(".")) : baseName;
    baseName = stem + ".jpg";
  } else {
    const extFromOrig = entryImageMimeToExt(normMime);
    if (extFromOrig && !baseName.toLowerCase().endsWith(extFromOrig)) {
      baseName += extFromOrig;
    }
  }
  const safeName = baseName;
  return { ok: true, outBuffer, outMime, safeName };
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
      const isGroup =
        normalizeEntryFieldType(item.fieldType) === "repeat" &&
        normalizeRepeatColumns(item.repeatColumns).length > 0 &&
        (item.repeatGroup === true || !hasField);
      return hasField || hasLabel || isGroup;
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
      const fieldTypeRaw = normalizeEntryFieldType(item.fieldType);
      const repeatCols = normalizeRepeatColumns(item.repeatColumns);
      const fieldNameTrim = typeof item.fieldName === "string" ? item.fieldName.trim() : "";
      if (
        fieldTypeRaw === "repeat" &&
        repeatCols.length > 0 &&
        (item.repeatGroup === true || !fieldNameTrim)
      ) {
        return {
          ...base,
          fieldType: "repeat",
          repeatGroup: true,
          repeatMode: normalizeRepeatMode(item.repeatMode),
          repeatColumns: repeatCols,
          repeatAddLabel:
            typeof item.repeatAddLabel === "string" && item.repeatAddLabel.trim()
              ? item.repeatAddLabel.trim()
              : "Add row",
        };
      }
      if (fieldNameTrim) {
        const fieldType = fieldTypeRaw;
        const out = { ...base, fieldName: fieldNameTrim, fieldType };
        if (fieldType === "repeat") {
          out.repeatMode = normalizeRepeatMode(item.repeatMode);
          out.repeatColumns = repeatCols.length > 0 ? repeatCols : defaultRepeatColumnsForField(fieldNameTrim);
          out.repeatAddLabel =
            typeof item.repeatAddLabel === "string" && item.repeatAddLabel.trim()
              ? item.repeatAddLabel.trim()
              : "Add row";
        }
        return out;
      }
      return { ...base, labelId: item.labelId.trim() };
    });
  const flowButtonEnabled = !!(body.flowButtonEnabled === true || body.flowButtonEnabled === "true");
  const flowTargetRaw = typeof body.flowTarget === "string" ? body.flowTarget.trim() : "";
  const flowTarget =
    flowTargetRaw === "localDb" ? "localDb" : flowTargetRaw === "api" ? "api" : flowTargetRaw === "response" ? "response" : "log";
  const flowButtonLabel = typeof body.flowButtonLabel === "string" ? body.flowButtonLabel.trim() : "";
  const flowButtonParam = typeof body.flowButtonParam === "string" ? body.flowButtonParam.trim() : "";
  const linkedQueryRaw = body && typeof body.linkedQuery === "object" && body.linkedQuery ? body.linkedQuery : {};
  const linkedQueryId =
    linkedQueryRaw && typeof linkedQueryRaw.id === "string" && linkedQueryRaw.id.trim() ? linkedQueryRaw.id.trim() : "";
  const linkedQueryWidth =
    linkedQueryRaw && typeof linkedQueryRaw.width === "string" && linkedQueryRaw.width.trim() ? linkedQueryRaw.width.trim() : "";
  const linkedQueryButtonLabel =
    linkedQueryRaw && typeof linkedQueryRaw.buttonLabel === "string" && linkedQueryRaw.buttonLabel.trim()
      ? linkedQueryRaw.buttonLabel.trim()
      : "";
  const linkedQueryX = parseNum(linkedQueryRaw && linkedQueryRaw.x);
  const linkedQueryY = parseNum(linkedQueryRaw && linkedQueryRaw.y);
  const linkedQueryHeight = parseNum(linkedQueryRaw && linkedQueryRaw.height);
  const linkedQueryLoadOnDemand = !!(linkedQueryRaw && (linkedQueryRaw.loadOnDemand === true || linkedQueryRaw.loadOnDemand === "true"));
  const linkedQuery =
    linkedQueryId
      ? {
          id: linkedQueryId,
          ...(linkedQueryWidth ? { width: linkedQueryWidth } : {}),
          ...(linkedQueryLoadOnDemand && linkedQueryButtonLabel ? { buttonLabel: linkedQueryButtonLabel } : {}),
          ...(linkedQueryX != null ? { x: linkedQueryX } : {}),
          ...(linkedQueryY != null ? { y: linkedQueryY } : {}),
          ...(linkedQueryHeight != null ? { height: linkedQueryHeight } : {}),
          ...(linkedQueryLoadOnDemand ? { loadOnDemand: true } : {}),
        }
      : null;

  function normalizeFlowConfigItem(item) {
    if (!item || typeof item !== "object") return null;
    const enabled = !!(item.enabled === true || item.enabled === "true");
    const flowId = typeof item.flowId === "string" ? item.flowId.trim() : "";
    const targetRaw = typeof item.target === "string" ? item.target.trim() : "";
    const target = flowId
      ? (targetRaw === "localDb" ? "localDb" : targetRaw === "api" ? "api" : targetRaw === "response" ? "response" : "")
      : (targetRaw === "localDb" ? "localDb" : targetRaw === "api" ? "api" : targetRaw === "response" ? "response" : "log");
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

  const entryNavForwardBackEnabled = !!(
    body.entryNavForwardBackEnabled === true || body.entryNavForwardBackEnabled === "true"
  );

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
    linkedQuery,
    entryNavForwardBackEnabled,
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
            target: c && c.target === "localDb" ? "localDb" : c && c.target === "api" ? "api" : c && c.target === "response" ? "response" : "log",
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
    linkedQuery: baseForm && baseForm.linkedQuery && typeof baseForm.linkedQuery === "object" ? baseForm.linkedQuery : null,
    entryNavForwardBackEnabled: !!(
      baseForm.entryNavForwardBackEnabled === true || baseForm.entryNavForwardBackEnabled === "true"
    ),
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

function makeUniqueTimerCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "timer");
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
  const authT = normalizeElenkoApiAuthType(baseApi);
  return {
    type: "elenko_api",
    name,
    description: typeof baseApi.description === "string" ? baseApi.description.trim() : "",
    url: typeof baseApi.url === "string" ? baseApi.url.trim() : "",
    method: baseApi.method === "POST" || baseApi.method === "PUT" || baseApi.method === "PATCH" ? baseApi.method : "GET",
    apiAuthType: authT,
    apiKeyRef: "",
    apiUserRef: "",
    apiPasswordRef: "",
    responseTarget:
      baseApi.responseTarget === "create" ? "create" : baseApi.responseTarget === "forward" ? "forward" : "update",
    template: typeof baseApi.template === "string" ? baseApi.template.trim() : "",
    responseField: typeof baseApi.responseField === "string" ? baseApi.responseField.trim() : "",
    responseStart: typeof baseApi.responseStart === "string" ? baseApi.responseStart : "",
    responseEnd: typeof baseApi.responseEnd === "string" ? baseApi.responseEnd : "",
    ...(typeof baseApi.getQueryFromEntry === "boolean" ? { getQueryFromEntry: baseApi.getQueryFromEntry } : {}),
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

/** Repeat interval keys for elenko_timer.intervalKey (milliseconds). */
const TIMER_INTERVAL_MS = {
  m10: 10 * 60 * 1000,
  m20: 20 * 60 * 1000,
  m30: 30 * 60 * 1000,
  h1: 60 * 60 * 1000,
  h2: 2 * 60 * 60 * 1000,
  h6: 6 * 60 * 60 * 1000,
  h12: 12 * 60 * 60 * 1000,
  h24: 24 * 60 * 60 * 1000,
  w1: 7 * 24 * 60 * 60 * 1000,
};

const TIMER_INTERVAL_LABEL = {
  m10: "Every 10 minutes",
  m20: "Every 20 minutes",
  m30: "Every 30 minutes",
  h1: "Every hour",
  h2: "Every 2 hours",
  h6: "Every 6 hours",
  h12: "Every 12 hours",
  h24: "Every 24 hours",
  w1: "Every week",
};

/** Stable order for timer interval dropdowns. */
const TIMER_INTERVAL_ORDER = ["m10", "m20", "m30", "h1", "h2", "h6", "h12", "h24", "w1"];

function normalizeTimerIntervalMs(key) {
  const k = typeof key === "string" ? key.trim() : "";
  const v = TIMER_INTERVAL_MS[k];
  return typeof v === "number" && v >= 60000 ? v : TIMER_INTERVAL_MS.h1;
}

function normalizeTimerIntervalKeyString(k) {
  const x = typeof k === "string" ? k.trim() : "";
  return TIMER_INTERVAL_MS[x] ? x : "h1";
}

function defaultTimerStartDateLocal() {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function defaultTimerStartTimeNextHourLocal() {
  const d = new Date();
  d.setMinutes(0, 0, 0);
  d.setHours(d.getHours() + 1);
  const hh = String(d.getHours()).padStart(2, "0");
  return `${hh}:00`;
}

/** Interpret date + time in server local timezone. @returns {number} ms or NaN */
function parseTimerLocalDateTimeMs(dateStr, timeStr) {
  const ds = typeof dateStr === "string" ? dateStr.trim() : "";
  const ts = typeof timeStr === "string" ? timeStr.trim() : "";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(ds)) return NaN;
  const m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(ts);
  if (!m) return NaN;
  const hh = parseInt(m[1], 10);
  const mm = parseInt(m[2], 10);
  const ss = m[3] != null ? parseInt(m[3], 10) : 0;
  if (
    !Number.isFinite(hh) ||
    !Number.isFinite(mm) ||
    !Number.isFinite(ss) ||
    mm < 0 ||
    mm > 59 ||
    ss < 0 ||
    ss > 59 ||
    hh < 0 ||
    hh > 23
  ) {
    return NaN;
  }
  const tnorm = `${String(hh).padStart(2, "0")}:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
  const inst = new Date(`${ds}T${tnorm}`);
  return inst.getTime();
}

function timerDocumentToWorkerPayload(doc) {
  if (!doc || doc.type !== "elenko_timer" || !doc._id) return null;
  const anchorMs = parseTimerLocalDateTimeMs(doc.startDate, doc.startTime);
  if (!Number.isFinite(anchorMs)) return null;
  const intervalMs = normalizeTimerIntervalMs(doc.intervalKey);
  const flowId = typeof doc.flowId === "string" ? doc.flowId.trim() : "";
  const profileId = typeof doc.profileId === "string" ? doc.profileId.trim() : "";
  if (!flowId || !profileId) return null;
  return {
    id: doc._id,
    active: !!(doc.active === true || doc.active === "true" || doc.active === "on"),
    anchorMs,
    intervalMs,
    flowId,
    profileId,
    entryId: typeof doc.entryId === "string" ? doc.entryId.trim() : "",
    param: typeof doc.param === "string" ? doc.param.trim() : "",
  };
}

function normalizeTimerCreateBody(body) {
  const out = {};
  out.name = typeof body.name === "string" ? body.name.trim() : "";
  out.description = typeof body.description === "string" ? body.description.trim() : "";
  out.flowId = typeof body.flowId === "string" ? body.flowId.trim() : "";
  out.profileId = typeof body.profileId === "string" ? body.profileId.trim() : "";
  out.entryId = typeof body.entryId === "string" ? body.entryId.trim() : "";
  out.param = typeof body.param === "string" ? body.param.trim() : "";
  out.startDate =
    typeof body.startDate === "string" && body.startDate.trim() ? body.startDate.trim() : defaultTimerStartDateLocal();
  out.startTime =
    typeof body.startTime === "string" && body.startTime.trim()
      ? body.startTime.trim()
      : defaultTimerStartTimeNextHourLocal();
  out.intervalKey = normalizeTimerIntervalKeyString(body.intervalKey);
  out.active = !!(body.active === true || body.active === "true" || body.active === "on");
  return out;
}

/** New elenko_timer from an existing timer (new _id on insert). */
function buildTimerDocFromSource(baseTimer, name) {
  return {
    type: "elenko_timer",
    name,
    description: typeof baseTimer.description === "string" ? baseTimer.description.trim() : "",
    flowId: typeof baseTimer.flowId === "string" ? baseTimer.flowId.trim() : "",
    profileId: typeof baseTimer.profileId === "string" ? baseTimer.profileId.trim() : "",
    entryId: typeof baseTimer.entryId === "string" ? baseTimer.entryId.trim() : "",
    param: typeof baseTimer.param === "string" ? baseTimer.param.trim() : "",
    startDate: typeof baseTimer.startDate === "string" && baseTimer.startDate.trim()
      ? baseTimer.startDate.trim()
      : defaultTimerStartDateLocal(),
    startTime:
      typeof baseTimer.startTime === "string" && baseTimer.startTime.trim()
        ? baseTimer.startTime.trim()
        : defaultTimerStartTimeNextHourLocal(),
    intervalKey: normalizeTimerIntervalKeyString(baseTimer.intervalKey),
    active: !!(baseTimer.active === true || baseTimer.active === "true"),
  };
}

/** Flow log line when an active timer is persisted (create / update / copy). */
function sendFlowMessageTimerSaved(action, timerId, fields) {
  if (!fields || !fields.active) return;
  const tid = timerId != null ? String(timerId).trim() : "";
  if (!tid) return;
  sendFlowMessage("timer.saved", {
    action,
    timerId: tid,
    name: fields.name,
    flowId: fields.flowId,
    profileId: fields.profileId,
    entryId: fields.entryId || "",
    param: fields.param || "",
    intervalKey: fields.intervalKey,
    startDate: fields.startDate,
    startTime: fields.startTime,
    active: true,
  });
}

function makeUniqueProfileCopyName(originalName, existingNames) {
  return makeUniqueCopyOfLabel(originalName, existingNames, "profile");
}

/** Deep clone elenko_profile for Copy (new _id on insert). */
function buildProfileDocFromSource(baseProfile, name) {
  const raw = JSON.parse(JSON.stringify(baseProfile));
  delete raw._id;
  delete raw._rev;
  delete raw.dbCode8;
  raw.type = "elenko_profile";
  raw.name = name;
  raw.createdAt = new Date().toISOString();
  return raw;
}

function escapeRegex(s) {
  return String(s).replace(/[\\^$.*+?()|[\]{}]/g, "\\$&");
}

/**
 * Fold string for entry search: case-insensitive and diacritic/umlaut-insensitive
 * (e.g. Lourié ≈ Lourie, Müller ≈ muller).
 */
function normalizeForSearch(s) {
  if (s == null) return "";
  try {
    return String(s)
      .replace(/\u00df/gi, "ss")
      .replace(/\u1e9e/g, "ss")
      .normalize("NFD")
      .replace(/\p{M}/gu, "")
      .toLowerCase();
  } catch {
    return String(s).toLowerCase();
  }
}

function entryMatchesSearchQuery(doc, fieldNames, normalizedQuery) {
  if (!normalizedQuery) return true;
  if (!Array.isArray(fieldNames) || fieldNames.length === 0) return true;
  for (const fn of fieldNames) {
    const v = doc[fn];
    if (v == null) continue;
    if (Array.isArray(v)) {
      for (const item of v) {
        if (normalizeForSearch(item).includes(normalizedQuery)) return true;
      }
    } else if (normalizeForSearch(v).includes(normalizedQuery)) return true;
  }
  return false;
}

/** When true, entry list search folds accents/umlauts (slower on large profiles). Default off. */
function isProfileSearchAccentFoldingEnabled(profileDoc) {
  return !!(profileDoc && profileDoc.searchAccentFolding === true);
}

function buildProfileEntrySearchSelector(profileId, fieldNames, searchQuery, useAccentFolding) {
  const selector = { type: "elenko_record", profileId };
  if (
    searchQuery &&
    Array.isArray(fieldNames) &&
    fieldNames.length > 0 &&
    !useAccentFolding
  ) {
    // Inline (?i): CouchDB Mango here rejects { $regex, $options } ("Invalid operator: $options").
    const pattern = "(?i).*" + escapeRegex(searchQuery) + ".*";
    selector.$or = fieldNames.map((fn) => ({ [fn]: { $regex: pattern } }));
  }
  return selector;
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

/** Escape one CSV cell for semicolon-separated export (RFC-style quoted fields). */
function formatSemicolonCsvField(value) {
  const s = value == null ? "" : String(value);
  if (/[;"\r\n]/.test(s) || /^\s|\s$/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function formatSemicolonCsvRow(cells) {
  return cells.map(formatSemicolonCsvField).join(";");
}

/** Build CSV text from rows (array of string arrays). Uses CRLF line endings. */
function buildSemicolonCsvText(rows) {
  return rows.map(formatSemicolonCsvRow).join("\r\n");
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
          : t === "response"
          ? "response"
          : t === "script"
          ? "script"
          : t === "update"
          ? "update"
          : t === "create"
          ? "create"
          : t === "purgeOld"
          ? "purgeOld"
          : t === "appendRepeat"
          ? "appendRepeat"
          : t === "refresh"
          ? "refresh"
          : "log";
      const param = typeof (s && s.param) === "string" ? s.param.trim() : "";
      const label = typeof (s && s.label) === "string" ? s.label.trim() : "";
      return { target, param, label: label || target };
    })
    .filter(Boolean);
}

/** Purge Param: only days (d) or weeks (w), e.g. 7d, 2w. Minimum 1. */
function parsePurgeOldAgeParam(param) {
  const s = typeof param === "string" ? param.trim().toLowerCase() : "";
  const m = /^(\d+)(d|w)$/.exec(s);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (!Number.isFinite(n) || n < 1) return null;
  const unit = m[2];
  const ageMs = unit === "w" ? n * 7 * PURGE_OLD_MS_PER_DAY : n * PURGE_OLD_MS_PER_DAY;
  return { ageMs, label: s };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Param: optional timeout in seconds (e.g. 20 or 20s). Default 15s. */
function parseFlowRefreshTimeoutParam(param) {
  const s = typeof param === "string" ? param.trim().toLowerCase() : "";
  if (!s) return FLOW_REFRESH_DEFAULT_TIMEOUT_MS;
  const m = /^(\d+)\s*s(?:ec(?:onds?)?)?$/.exec(s) || /^(\d+)$/.exec(s);
  if (!m) return FLOW_REFRESH_DEFAULT_TIMEOUT_MS;
  const sec = parseInt(m[1], 10);
  if (!Number.isFinite(sec) || sec < 1) return FLOW_REFRESH_DEFAULT_TIMEOUT_MS;
  return Math.min(sec * 1000, 300000);
}

/** Poll until the current entry _rev changes from the flow-start revision (view refresh). */
async function runFlowRefreshStep(dbInstance, context, stepIndex, param) {
  const timeoutMs = parseFlowRefreshTimeoutParam(param);
  const pollIntervalMs = FLOW_REFRESH_POLL_INTERVAL_MS;
  const entryId = context && context.entryId;
  const profileId = context && context.profileId;
  if (!entryId || !profileId || !dbInstance) {
    sendFlowMessage("flow.refreshError", {
      stepIndex,
      profileId: profileId || "",
      entryId: entryId || "",
      param,
      timeoutMs,
      pollIntervalMs,
      error: "Refresh requires a current entry in the flow context.",
    });
    return { ok: false };
  }
  const baselineRev = context._entryRevAtFlowStart != null ? String(context._entryRevAtFlowStart) : "";
  const deadline = Date.now() + timeoutMs;
  let currentRev = baselineRev;
  let updated = false;
  while (Date.now() < deadline) {
    try {
      const doc = await dbInstance.get(entryId);
      currentRev = doc && doc._rev ? String(doc._rev) : "";
      if (currentRev && currentRev !== baselineRev) {
        updated = true;
        break;
      }
    } catch (e) {
      sendFlowMessage("flow.refreshError", {
        stepIndex,
        profileId,
        entryId,
        param,
        timeoutMs,
        pollIntervalMs,
        baselineRev,
        error: e && e.message ? String(e.message) : "Failed to load entry while waiting for refresh",
      });
      return { ok: false };
    }
    if (Date.now() + pollIntervalMs >= deadline) break;
    await delay(pollIntervalMs);
  }
  if (updated) {
    sendFlowMessage("flow.refresh", {
      stepIndex,
      profileId,
      entryId,
      param,
      timeoutMs,
      pollIntervalMs,
      baselineRev,
      currentRev,
    });
    context.reloadEntry = true;
    return { ok: true };
  }
  const errorMsg = `Entry did not update within ${Math.round(timeoutMs / 1000)}s (polled every ${Math.round(pollIntervalMs / 1000)}s).`;
  sendFlowMessage("flow.refreshError", {
    stepIndex,
    profileId,
    entryId,
    param,
    timeoutMs,
    pollIntervalMs,
    baselineRev,
    currentRev,
    error: errorMsg,
  });
  context.refreshTimedOut = true;
  return { ok: false };
}

/**
 * Delete up to PURGE_OLD_MAX_DELETE elenko_record docs in profile with createdAt strictly before cutoff.
 */
async function purgeOldEntriesInProfile(dbInstance, profileId, parsed, stepIndex) {
  const pid = (profileId != null ? String(profileId) : "").trim();
  const emptyResult = { deleted: 0, capped: false };
  if (!pid || !dbInstance || !parsed) return emptyResult;
  const cutoffIso = new Date(Date.now() - parsed.ageMs).toISOString();
  let deleted = 0;
  let capped = false;
  try {
    const result = await dbInstance.find({
      selector: {
        type: "elenko_record",
        profileId: pid,
        createdAt: { $lt: cutoffIso },
      },
      limit: PURGE_OLD_MAX_DELETE + 1,
      fields: ["_id", "_rev", "type", "profileId", "createdAt"],
    });
    let docs = result.docs || [];
    if (docs.length > PURGE_OLD_MAX_DELETE) {
      capped = true;
      docs = docs.slice(0, PURGE_OLD_MAX_DELETE);
    }
    for (const doc of docs) {
      if (!doc || doc.type !== "elenko_record" || doc.profileId !== pid || !doc._id || !doc._rev) continue;
      try {
        await dbInstance.destroy(doc._id, doc._rev);
        deleted++;
      } catch (e) {
        console.error("purgeOldEntriesInProfile destroy:", doc._id, e);
      }
    }
    if (deleted > 0) clearProfileListCache(pid);
    sendFlowMessage("flow.purgeOld", {
      stepIndex,
      profileId: pid,
      param: parsed.label,
      cutoffIso,
      deleted,
      capped,
      maxPerRun: PURGE_OLD_MAX_DELETE,
    });
    return { deleted, capped };
  } catch (e) {
    sendFlowMessage("flow.purgeOldError", {
      stepIndex,
      profileId: pid,
      param: parsed.label,
      error: e && e.message ? String(e.message) : "Query or delete failed",
    });
    return emptyResult;
  }
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

/** Flow log preview: never derive previews from username/password (treated as credential leaks). */
function previewApiCredentialsForFlow(bundle) {
  const t = bundle && bundle.authType ? String(bundle.authType).trim().toLowerCase() : "";
  if (t === "digest" || t === "basic" || t === "fritz") return "";
  return previewApiKey(bundle && bundle.apiKey != null ? bundle.apiKey : "");
}

function apiKeyLookupErrorInfo(err) {
  if (!err) return { message: "unknown error", code: "" };
  const message = err && err.message ? String(err.message) : String(err);
  const code = err && (err.statusCode != null || err.code != null)
    ? String(err.statusCode != null ? err.statusCode : err.code)
    : "";
  return { message, code };
}

/** Stored on `elenko_api.apiAuthType`. Legacy docs without it use bearer when `apiKeyRef` is set, else none. */
function normalizeElenkoApiAuthType(apiDoc) {
  const t = apiDoc && typeof apiDoc.apiAuthType === "string" ? apiDoc.apiAuthType.trim().toLowerCase() : "";
  if (t === "none" || t === "bearer" || t === "basic" || t === "digest" || t === "fritz") return t;
  const kr = apiDoc && typeof apiDoc.apiKeyRef === "string" ? apiDoc.apiKeyRef.trim() : "";
  return kr ? "bearer" : "none";
}

function credentialFromElenkoKeyDoc(doc) {
  if (!doc) return null;
  if (doc.key != null) return String(doc.key);
  if (doc.value != null) return String(doc.value);
  return null;
}

/**
 * Loads secrets for `apiWorker` from config DB. Used by pipeline and flow worker Call API.
 * @returns {Promise<{ authType: string, apiKey: string | null, apiUsername: string | null, apiPassword: string | null, apiKeyRef: string, apiUserRef: string, apiPasswordRef: string }>}
 */
async function resolveApiWorkerAuthBundle(apiDoc) {
  const authType = normalizeElenkoApiAuthType(apiDoc);
  let apiKey = null;
  let apiUsername = null;
  let apiPassword = null;
  let apiKeyRef = "";
  let apiUserRef = "";
  let apiPasswordRef = "";

  async function loadRef(ref) {
    if (!ref || !configDb) return { value: null, err: null, empty: false };
    try {
      const kd = await configDb.get(ref);
      const v = credentialFromElenkoKeyDoc(kd);
      if (v == null || v === "") return { value: null, err: null, empty: true };
      return { value: v, err: null, empty: false };
    } catch (e) {
      return { value: null, err: e, empty: false };
    }
  }

  if (authType === "bearer") {
    apiKeyRef = apiDoc && typeof apiDoc.apiKeyRef === "string" ? apiDoc.apiKeyRef.trim() : "";
    if (apiKeyRef) {
      const r = await loadRef(apiKeyRef);
      if (r.err) throw Object.assign(new Error("apiKeyRef"), { credentialField: "apiKeyRef", apiKeyRef, cause: r.err });
      if (r.empty) throw Object.assign(new Error("emptyKey"), { credentialField: "apiKeyRef", apiKeyRef });
      apiKey = r.value;
    }
  } else if (authType === "basic" || authType === "digest" || authType === "fritz") {
    apiUserRef = apiDoc && typeof apiDoc.apiUserRef === "string" ? apiDoc.apiUserRef.trim() : "";
    apiPasswordRef = apiDoc && typeof apiDoc.apiPasswordRef === "string" ? apiDoc.apiPasswordRef.trim() : "";
    if (apiUserRef) {
      const r = await loadRef(apiUserRef);
      if (r.err) throw Object.assign(new Error("apiUserRef"), { credentialField: "apiUserRef", apiUserRef, cause: r.err });
      if (r.empty) throw Object.assign(new Error("emptyKey"), { credentialField: "apiUserRef", apiUserRef });
      apiUsername = r.value;
    }
    if (apiPasswordRef) {
      const r = await loadRef(apiPasswordRef);
      if (r.err) throw Object.assign(new Error("apiPasswordRef"), { credentialField: "apiPasswordRef", apiPasswordRef, cause: r.err });
      if (r.empty) throw Object.assign(new Error("emptyKey"), { credentialField: "apiPasswordRef", apiPasswordRef });
      apiPassword = r.value;
    }
  }

  return { authType, apiKey, apiUsername, apiPassword, apiKeyRef, apiUserRef, apiPasswordRef };
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

/** Same ordering as the profile entry list (sortKey tiers + profile sort direction; tie-break _id). */
function compareRecordsByProfileSort(a, b, sortDirection) {
  const sa = Array.isArray(a.sortKey) ? a.sortKey : [];
  const sb = Array.isArray(b.sortKey) ? b.sortKey : [];
  for (let i = 0; i < Math.max(sa.length, sb.length); i++) {
    const va = sa[i] != null ? String(sa[i]) : "";
    const vb = sb[i] != null ? String(sb[i]) : "";
    const c = va.localeCompare(vb, undefined, { sensitivity: "base" });
    if (c !== 0) return sortDirection === "desc" ? -c : c;
  }
  const ida = a && a._id != null ? String(a._id) : "";
  const idb = b && b._id != null ? String(b._id) : "";
  return ida.localeCompare(idb, undefined, { sensitivity: "base" });
}

const ADJACENT_ENTRY_FETCH_LIMIT = 50000;

/**
 * Previous / next entry _id in the same profile, using the profile’s sort key and direction (same as list view).
 */
async function getAdjacentEntryIdsForProfile(dbInstance, profileDoc, currentEntryId) {
  const profileId = profileDoc && profileDoc._id;
  const cur = currentEntryId != null ? String(currentEntryId) : "";
  if (!profileId || !cur) return { prevId: null, nextId: null };
  const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
  const sortDirection = profileDoc.sortDirection === "desc" ? "desc" : "asc";
  try {
    const sortResult = await dbInstance.find({
      selector: { type: "elenko_record", profileId },
      fields: ["_id", "sortKey"],
      limit: ADJACENT_ENTRY_FETCH_LIMIT,
    });
    let docs = sortResult.docs || [];
    if (sortKeyFields.length > 0) {
      docs.sort((a, b) => compareRecordsByProfileSort(a, b, sortDirection));
    } else {
      docs.sort((a, b) => String(a._id).localeCompare(String(b._id)));
    }
    const idx = docs.findIndex((d) => d && d._id === cur);
    if (idx < 0) return { prevId: null, nextId: null };
    return {
      prevId: idx > 0 && docs[idx - 1] ? docs[idx - 1]._id : null,
      nextId: idx < docs.length - 1 && docs[idx + 1] ? docs[idx + 1]._id : null,
    };
  } catch (_) {
    return { prevId: null, nextId: null };
  }
}

/** All profile entries for CSV export, sorted like the database list view. */
async function loadProfileRecordsForExport(dbInstance, profileDoc) {
  const profileId = profileDoc && profileDoc._id;
  const fieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  if (!profileId) return { fieldNames, docs: [] };
  const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
  const sortDirection = profileDoc.sortDirection === "desc" ? "desc" : "asc";
  const fieldsForFind = fieldNames.length ? ["_id", "sortKey", ...fieldNames] : ["_id", "sortKey"];
  const sortResult = await dbInstance.find({
    selector: { type: "elenko_record", profileId },
    fields: fieldsForFind,
    limit: MAX_CSV_IMPORT_ROWS,
  });
  let docs = sortResult.docs || [];
  if (sortKeyFields.length > 0) {
    docs.sort((a, b) => compareRecordsByProfileSort(a, b, sortDirection));
  } else {
    docs.sort((a, b) => String(a._id).localeCompare(String(b._id)));
  }
  return { fieldNames, docs };
}

function normalizeProfileNameForDbCode(name) {
  return String(name || "")
    .replace(/\s+/g, "")
    .toUpperCase();
}

async function loadUsedDbCodes(dbInstance, excludeProfileId) {
  const used = new Set();
  try {
    const result = await dbInstance.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "dbCode8"],
      limit: 10000,
    });
    for (const d of result.docs || []) {
      if (!d || d._id === excludeProfileId) continue;
      if (typeof d.dbCode8 === "string" && d.dbCode8.length === DB_CODE_LEN) used.add(d.dbCode8);
    }
  } catch (_) {}
  return used;
}

async function assignDbCode8(dbInstance, profileName, excludeProfileId) {
  const normalized = normalizeProfileNameForDbCode(profileName);
  if (!normalized) {
    const used = await loadUsedDbCodes(dbInstance, excludeProfileId);
    for (let n = 1; n <= 99; n++) {
      const candidate = "ELENKO" + String(n).padStart(2, "0");
      if (!used.has(candidate)) return candidate;
    }
    throw new Error("Could not allocate unique database code (dbCode8).");
  }
  const used = await loadUsedDbCodes(dbInstance, excludeProfileId);
  const firstEight =
    normalized.length >= DB_CODE_LEN
      ? normalized.slice(0, DB_CODE_LEN)
      : normalized + " ".repeat(DB_CODE_LEN - normalized.length);
  if (!used.has(firstEight)) return firstEight;
  const prefix6 = (normalized + "      ").slice(0, 6);
  for (let n = 1; n <= 99; n++) {
    const candidate = prefix6 + String(n).padStart(2, "0");
    if (candidate.length === DB_CODE_LEN && !used.has(candidate)) return candidate;
  }
  throw new Error(
    "Could not allocate unique database code (dbCode8); too many profiles with similar names."
  );
}

function normalizePrimaryKeyFieldsFromBody(fieldNames, rawFields, rawLengths) {
  const names = Array.isArray(fieldNames) ? fieldNames : [];
  const fields = Array.isArray(rawFields)
    ? rawFields
        .filter((f) => typeof f === "string" && f.trim())
        .slice(0, PRIMARY_KEY_FIELDS_MAX)
        .map((f) => f.trim())
        .filter((f) => names.includes(f))
    : [];
  const lengths = Array.isArray(rawLengths) ? rawLengths : [];
  const primaryKeySegmentLengths = [];
  for (let i = 0; i < fields.length; i++) {
    const n = Number(lengths[i]);
    if (Number.isFinite(n)) {
      const len = Math.floor(n);
      primaryKeySegmentLengths.push(
        len >= PRIMARY_KEY_SEGMENT_LEN_MIN && len <= PRIMARY_KEY_SEGMENT_LEN_MAX
          ? len
          : Math.min(Math.max(len, PRIMARY_KEY_SEGMENT_LEN_MIN), PRIMARY_KEY_SEGMENT_LEN_MAX)
      );
    } else {
      primaryKeySegmentLengths.push(32);
    }
  }
  return { primaryKeyFields: fields, primaryKeySegmentLengths };
}

function computePrimaryKeyForRecord(record, profileDoc) {
  const fields = Array.isArray(profileDoc.primaryKeyFields) ? profileDoc.primaryKeyFields : [];
  if (fields.length === 0) return { value: null };
  const lengths = Array.isArray(profileDoc.primaryKeySegmentLengths) ? profileDoc.primaryKeySegmentLengths : [];
  const dbCode8 =
    typeof profileDoc.dbCode8 === "string" && profileDoc.dbCode8.length === DB_CODE_LEN
      ? profileDoc.dbCode8.slice(0, DB_CODE_LEN)
      : null;
  if (!dbCode8) {
    return { error: "Profile is missing dbCode8; save the profile again to assign a database code." };
  }
  let str = dbCode8;
  for (let i = 0; i < fields.length; i++) {
    const fn = fields[i];
    const maxLen =
      lengths[i] != null && Number.isFinite(Number(lengths[i]))
        ? Math.floor(Number(lengths[i]))
        : 32;
    const segLen =
      maxLen >= PRIMARY_KEY_SEGMENT_LEN_MIN && maxLen <= PRIMARY_KEY_SEGMENT_LEN_MAX
        ? maxLen
        : 32;
    const raw = record[fn] != null ? String(record[fn]) : "";
    const segment = raw.length > segLen ? raw.slice(0, segLen) : raw;
    str += segment + " ".repeat(segLen - segment.length);
  }
  return { value: str };
}

function applyPrimaryKeyToRecord(record, profileDoc) {
  const result = computePrimaryKeyForRecord(record, profileDoc);
  if (result.error) throw new Error(result.error);
  if (result.value == null) {
    delete record.primaryKey;
  } else {
    record.primaryKey = result.value;
  }
}

async function findPrimaryKeyConflict(dbInstance, primaryKey, excludeDocId) {
  if (primaryKey == null || primaryKey === "") return null;
  try {
    const res = await dbInstance.find({
      selector: { type: "elenko_record", primaryKey },
      limit: 5,
    });
    for (const d of res.docs || []) {
      if (d._id !== excludeDocId) return d;
    }
  } catch (_) {}
  return null;
}

async function ensureProfileDbCode8(dbInstance, profileDoc) {
  if (
    typeof profileDoc.dbCode8 === "string" &&
    profileDoc.dbCode8.length === DB_CODE_LEN &&
    profileDoc.name
  ) {
    return profileDoc;
  }
  const name = typeof profileDoc.name === "string" ? profileDoc.name.trim() : "";
  if (!name) return profileDoc;
  profileDoc.dbCode8 = await assignDbCode8(dbInstance, name, profileDoc._id);
  const ins = await dbInstance.insert(profileDoc);
  profileDoc._rev = ins.rev;
  return profileDoc;
}

async function recomputePrimaryKeysForProfileRecords(dbInstance, profileDoc) {
  const profileId = profileDoc._id;
  const result = await dbInstance.find({
    selector: { type: "elenko_record", profileId },
    limit: 50000,
  });
  const docs = result.docs || [];
  const now = new Date().toISOString();
  for (const rec of docs) {
    try {
      applyPrimaryKeyToRecord(rec, profileDoc);
    } catch (_) {
      delete rec.primaryKey;
    }
    rec.updatedAt = now;
    await dbInstance.insert(rec);
  }
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

async function loadDefaultEntryFormForProfile(dbInstance, profileDoc) {
  const formId = getProfileDefaultEntryFormId(profileDoc);
  if (!formId) return null;
  try {
    const loaded = await dbInstance.get(formId);
    if (loaded && loaded.type === "elenko_entry_form") return loaded;
  } catch (_) {}
  return null;
}

/**
 * New entry row for bulk picture import: defaults from profile, then attachment filename on the target field.
 */
async function buildInitialRecordForPictureImport(dbInstance, profileDoc, req, fieldName, safeName) {
  const profileId = profileDoc._id;
  const fieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const record = { type: "elenko_record", profileId };
  for (const f of fieldNames) {
    record[f] = "";
  }
  const now = new Date().toISOString();
  record.createdAt = now;
  record.updatedAt = now;
  setEntryAuditOnCreate(record, req);
  const sources = Array.isArray(profileDoc.fieldDefaultSources) ? profileDoc.fieldDefaultSources : [];
  for (let i = 0; i < fieldNames.length; i++) {
    const src = sources[i];
    if (src === "createdAt" || src === "updatedAt" || src === "currentUser") {
      record[fieldNames[i]] = resolveDefaultValue(src, req);
    }
  }
  record[fieldName] = safeName;
  let pdoc = profileDoc;
  pdoc = await ensureProfileDbCode8(dbInstance, pdoc);
  const sortKeyFields = Array.isArray(pdoc.sortKeyFields) ? pdoc.sortKeyFields : [];
  const profileFormIds = getProfileEntryFormIds(pdoc);
  if (profileFormIds.length > 0) {
    record.entryFormId = profileFormIds[0];
  }
  record.sortKey = buildSortKey(record, sortKeyFields);
  applyPrimaryKeyToRecord(record, pdoc);
  return { record, pdoc };
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
async function createEntryInProfileFromContext(dbInstance, context, targetProfileId, options = {}) {
  const tid = (targetProfileId != null ? String(targetProfileId) : "").trim();
  if (!tid) throw new Error("createEntryInProfileFromContext: missing targetProfileId");
  const opts = options && typeof options === "object" ? options : {};
  const responseToDocId =
    opts.responseToDocId != null && String(opts.responseToDocId).trim()
      ? String(opts.responseToDocId).trim()
      : "";
  const markAsResponse = !!(opts.isResponse && responseToDocId);
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
  if (markAsResponse) {
    record.isResponse = true;
    record.responseToDocId = responseToDocId;
  }
  for (const fn of fieldNames) {
    record[fn] = dataset[fn] != null ? String(dataset[fn]).trim() : "";
  }
  const now = new Date().toISOString();
  record.createdAt = now;
  record.updatedAt = now;
  setEntryAuditOnCreate(record, context && context.req);
  const sources = Array.isArray(targetProfile.fieldDefaultSources) ? targetProfile.fieldDefaultSources : [];
  const req = context && context.req;
  for (let i = 0; i < fieldNames.length; i++) {
    const src = sources[i];
    if (src === "createdAt" || src === "updatedAt" || src === "currentUser") {
      record[fieldNames[i]] = resolveDefaultValue(src, req);
    }
  }
  targetProfile = await ensureProfileDbCode8(dbInstance, targetProfile);
  const sortKeyFields = Array.isArray(targetProfile.sortKeyFields) ? targetProfile.sortKeyFields : [];
  record.sortKey = buildSortKey(record, sortKeyFields);
  const profileFormIds = getProfileEntryFormIds(targetProfile);
  if (profileFormIds.length > 0) {
    record.entryFormId = profileFormIds[0];
  }
  if (isProfilePersonalEncryptionEnabled(targetProfile)) {
    throw new Error("Cannot create entries in an encrypted profile via flows or pipelines.");
  }
  try {
    applyPrimaryKeyToRecord(record, targetProfile);
  } catch (e) {
    throw new Error(e && e.message ? e.message : "Primary key could not be computed.");
  }
  if (record.primaryKey) {
    const conflict = await findPrimaryKeyConflict(dbInstance, record.primaryKey, "");
    if (conflict) {
      throw new Error("Duplicate primary key: another entry already uses this key.");
    }
  }
  const result = await dbInstance.insert(record);
  clearProfileListCache(resolvedProfileId);
  const created = { ...record, _id: result.id, _rev: result.rev };
  if (markAsResponse) {
    try {
      const parentDoc = await dbInstance.get(responseToDocId);
      if (parentDoc && parentDoc.type === "elenko_record") {
        const existingIds = Array.isArray(parentDoc.responseDocIds) ? parentDoc.responseDocIds.map((x) => String(x)) : [];
        if (!existingIds.includes(created._id)) existingIds.push(created._id);
        parentDoc.hasResponses = existingIds.length > 0;
        parentDoc.responseDocIds = existingIds;
        parentDoc.updatedAt = new Date().toISOString();
        setEntryAuditOnUpdate(parentDoc, context && context.req);
        await dbInstance.insert(parentDoc);
        clearProfileListCache(parentDoc.profileId);
      }
    } catch (_) {
      // Parent document may have been deleted; keep created response as-is.
    }
  }
  return created;
}

async function createResponseEntryFromContext(dbInstance, context, parentEntryId) {
  if (!dbInstance) throw new Error("Database unavailable");
  const pid = parentEntryId != null ? String(parentEntryId).trim() : "";
  if (!pid) throw new Error("Missing parent entry id for response");
  const targetProfileId = context && context.profileId ? String(context.profileId).trim() : "";
  if (!targetProfileId) throw new Error("Missing profile id for response");
  return createEntryInProfileFromContext(dbInstance, context, targetProfileId, {
    isResponse: true,
    responseToDocId: pid,
  });
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
  let profileDoc = context.profileDoc;
  if (!profileDoc && profileId) {
    try {
      const pd = await dbInstance.get(profileId);
      if (pd && pd.type === "elenko_profile") profileDoc = pd;
    } catch (_) {}
  }
  const dataset = context.dataset && typeof context.dataset === "object" ? context.dataset : {};
  const patch = { ...dataset };
  // Do not persist helper fields used only inside the pipeline
  delete patch._lastCreatedId;
  delete patch._repeatRow;
  delete patch._lastAppendRepeatField;
  delete patch._lastAppendRepeatFields;
  delete patch._lastAppendRepeatRowCount;
  delete patch.createdBy;
  delete patch.updatedBy;
  if (profileDoc) {
    for (const key of Object.keys(patch)) {
      if (key.startsWith("_") || key === "type" || key === "profileId" || key === "sortKey" || key === "draftRepeatRowIndex") continue;
      patch[key] = applyPlainValueToProfileField(profileDoc, existing, key, patch[key]);
    }
  }
  const updated = { ...existing, ...patch };
  if (context && context.clearDraftRepeatRowIndex) {
    delete updated.draftRepeatRowIndex;
  }
  setEntryAuditOnUpdate(updated, context && context.req);
  await dbInstance.insert(updated);
  clearProfileListCache(profileId);
}

/** Subset of elenko_api sent to apiWorker (no secrets). */
function apiDocPayloadForApiWorker(apiDoc) {
  const o = {
    url: apiDoc.url,
    method: apiDoc.method,
    responseTarget: apiDoc.responseTarget,
    template: apiDoc.template,
    responseField: apiDoc.responseField,
    responseStart: apiDoc.responseStart,
    responseEnd: apiDoc.responseEnd,
  };
  if (typeof apiDoc.getQueryFromEntry === "boolean") o.getQueryFromEntry = apiDoc.getQueryFromEntry;
  return o;
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
    pendingApiRequests.set(requestId, { resolve, reject, timeoutId: timeout, apiKeyPreview: "", authType: "" });
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
        let bundle;
        try {
          bundle = await resolveApiWorkerAuthBundle(apiDoc);
        } catch (credErr) {
          const p = pendingApiRequests.get(requestId);
          const field = credErr.credentialField || "apiKeyRef";
          const ref =
            credErr.apiKeyRef || credErr.apiUserRef || credErr.apiPasswordRef || "";
          if (p) p.apiKeyPreview = previewApiKey("");
          if (flowWorker) {
            if (credErr.message === "emptyKey") {
              sendFlowMessage("api.keyLookupError", {
                entryId: context.entryId,
                profileId: context.profileId,
                apiKeyRef: ref,
                credentialField: field,
                code: "",
                reason: "Credential document has no key/value field",
              });
            } else {
              const info = apiKeyLookupErrorInfo(credErr.cause || credErr);
              sendFlowMessage("api.keyLookupError", {
                entryId: context.entryId,
                profileId: context.profileId,
                apiKeyRef: ref,
                credentialField: field,
                code: info.code,
                reason: info.message,
              });
            }
          }
          if (p) {
            pendingApiRequests.delete(requestId);
            clearTimeout(timeout);
            p.reject(new Error(credErr.message === "emptyKey" ? "Credential document has no key/value field" : "Credential lookup failed"));
          }
          return;
        }
        if (bundle.authType === "basic" || bundle.authType === "digest" || bundle.authType === "fritz") {
          if (!bundle.apiUserRef || !bundle.apiPasswordRef) {
            const p = pendingApiRequests.get(requestId);
            if (p) p.apiKeyPreview = "";
            if (flowWorker) {
              sendFlowMessage("api.keyLookupError", {
                entryId: context.entryId,
                profileId: context.profileId,
                apiKeyRef: "",
                credentialField: !bundle.apiUserRef ? "apiUserRef" : "apiPasswordRef",
                code: "",
                reason: "Set username and password key document IDs for Basic or Digest auth.",
              });
            }
            if (p) {
              pendingApiRequests.delete(requestId);
              clearTimeout(timeout);
              p.reject(new Error("API auth requires username and password key documents"));
            }
            return;
          }
        }
        const p = pendingApiRequests.get(requestId);
        if (p) {
          p.apiKeyPreview = previewApiCredentialsForFlow(bundle);
          p.authType = bundle.authType || "";
        }
        apiWorker.postMessage({
          type: "apiRequest",
          requestId,
          apiDoc: apiDocPayloadForApiWorker(apiDoc),
          authType: bundle.authType,
          apiKey: bundle.apiKey,
          apiUsername: bundle.apiUsername,
          apiPassword: bundle.apiPassword,
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
  if (!context.profileDoc && context.profileId && db) {
    try {
      const pd = await db.get(context.profileId);
      if (pd && pd.type === "elenko_profile") context.profileDoc = pd;
    } catch (_) {}
  }
  if (context.entryId && db && context._entryRevAtFlowStart == null) {
    try {
      const startDoc = await db.get(context.entryId);
      context._entryRevAtFlowStart = startDoc && startDoc._rev ? String(startDoc._rev) : "";
    } catch (_) {
      context._entryRevAtFlowStart = "";
    }
  }
  const steps = Array.isArray(flowDoc && flowDoc.steps) ? flowDoc.steps : [];
  let hasExplicitPersistStep = false;
  /** Skip update/response (need a current entry). Timer without entry uses this; guardian import always. */
  const suppressPipelineEntryWrites = !!(context && context.suppressPipelineEntryWrites);
  /** Skip stand-alone create step. Guardian import uses this so only script _createMany adds rows. */
  const suppressPipelineCreate = !!(context && context.suppressPipelineCreate);
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const rawTarget = step && step.target;
    const target =
      rawTarget === "localDb"
        ? "localDb"
        : rawTarget === "api"
        ? "api"
        : rawTarget === "response"
        ? "response"
        : rawTarget === "script"
        ? "script"
        : rawTarget === "update"
        ? "update"
        : rawTarget === "create"
        ? "create"
        : rawTarget === "purgeOld"
        ? "purgeOld"
        : rawTarget === "appendRepeat"
        ? "appendRepeat"
        : rawTarget === "refresh"
        ? "refresh"
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
      if (suppressPipelineEntryWrites) continue;
      hasExplicitPersistStep = true;
      if (getDraftRepeatRowIndex(context.dataset) >= 0) {
        context.clearDraftRepeatRowIndex = true;
      }
      await updateCurrentEntryFromDataset(db, context);
      if (context.dataset && typeof context.dataset === "object") {
        delete context.dataset.draftRepeatRowIndex;
      }
      continue;
    }
    if (target === "create") {
      if (suppressPipelineCreate) continue;
      hasExplicitPersistStep = true;
      if (context.profileId && db) {
        const created = await createEntryInProfileFromContext(db, context, context.profileId);
        context.dataset = { ...(context.dataset || {}), _lastCreatedId: created._id };
      }
      continue;
    }
    if (target === "response") {
      if (suppressPipelineEntryWrites) continue;
      hasExplicitPersistStep = true;
      if (context.profileId && context.entryId && db) {
        const created = await createResponseEntryFromContext(db, context, context.entryId);
        context.dataset = { ...(context.dataset || {}), _lastCreatedId: created._id, _lastResponseId: created._id };
      }
      continue;
    }
    if (target === "purgeOld") {
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      const parsed = parsePurgeOldAgeParam(param);
      if (!parsed) {
        sendFlowMessage("flow.purgeOldError", {
          stepIndex: i,
          error: 'Invalid Param: use age only, e.g. 7d or 2w (days or weeks; minimum 1).',
          param,
          profileId: context.profileId,
        });
        continue;
      }
      const profileIdFlow = context.profileId != null ? String(context.profileId).trim() : "";
      if (!profileIdFlow || !db) {
        sendFlowMessage("flow.purgeOldError", {
          stepIndex: i,
          error: "Missing profile or database in flow context.",
          param: parsed.label,
          profileId: context.profileId,
        });
        continue;
      }
      const purgeRes = await purgeOldEntriesInProfile(db, profileIdFlow, parsed, i);
      context.dataset = {
        ...(context.dataset || {}),
        _lastPurgeDeleted: purgeRes.deleted,
        _lastPurgeCapped: purgeRes.capped,
      };
      continue;
    }
    if (target === "appendRepeat") {
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      try {
        const appendRes = await appendRepeatRowToContext(db, context, param);
        sendFlowMessage("flow.appendRepeat", {
          stepIndex: i,
          profileId: context.profileId,
          entryId: context.entryId,
          param: appendRes.resolvedParam || param,
          fieldName: appendRes.fieldName,
          fieldNames: appendRes.fieldNames,
          rowCount: appendRes.rowCount,
          newRow: appendRes.newRow,
        });
        if (!suppressPipelineEntryWrites && context.entryId && context.profileId && db) {
          await updateCurrentEntryFromDataset(db, context);
          hasExplicitPersistStep = true;
        }
      } catch (e) {
        let resolvedParam = param;
        try {
          resolvedParam = (await resolveAppendRepeatParam(db, context, param)) || param;
        } catch (_) {}
        sendFlowMessage("flow.appendRepeatError", {
          stepIndex: i,
          profileId: context.profileId,
          entryId: context.entryId,
          param: resolvedParam,
          error: e && e.message ? String(e.message) : "Append repeat row failed",
        });
      }
      continue;
    }
    if (target === "refresh") {
      const param = (step && typeof step.param === "string") ? step.param.trim() : "";
      await runFlowRefreshStep(db, context, i, param);
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
          for (let rowIndex = 0; rowIndex < createManyRaw.length; rowIndex++) {
            const row = createManyRaw[rowIndex];
            if (!row || typeof row !== "object") continue;
            try {
              await createEntryInProfileFromContext(db, { dataset: row }, context.profileId);
              createdCount++;
            } catch (err) {
              console.error("REST API import _createMany row failed:", {
                profileId: context.profileId,
                stepIndex: i,
                rowIndex,
                message: err && err.message ? err.message : String(err),
              });
            }
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
        const fn = result.responseField.trim();
        let bodyToStore = bodyStr;
        if ((result.responseStart || result.responseEnd) && bodyStr) {
          const start =
            typeof result.responseStart === "string" && result.responseStart
              ? bodyStr.indexOf(result.responseStart)
              : 0;
          const startIdx =
            start === -1 ? 0 : start + (typeof result.responseStart === "string" && result.responseStart ? result.responseStart.length : 0);
          const endIdx =
            typeof result.responseEnd === "string" && result.responseEnd
              ? bodyStr.indexOf(result.responseEnd, startIdx) === -1
                ? bodyStr.length
                : bodyStr.indexOf(result.responseEnd, startIdx)
              : bodyStr.length;
          bodyToStore = bodyStr.slice(startIdx, endIdx).trim();
        }
        context.dataset[fn] = applyPlainValueToProfileField(
          context.profileDoc,
          context.dataset,
          fn,
          bodyToStore
        );
      }
    }
  }
}

const PBKDF2_ITERATIONS = 100000;
const SALT_LEN = 16;
const KEY_LEN = 32;

let flowWorker;
let timerWorker;
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
        type: "flow.scriptRequest",
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
/** False after a failed configDb read so the next request retries instead of using the 30s TTL. */
let cachedAppConfigAuthoritative = false;

function invalidateAppUiConfigCache() {
  cachedAppConfig = null;
  cachedAppConfigLoadedAt = 0;
  cachedAppConfigAuthoritative = false;
}

function defaultAppUiConfigObject() {
  return {
    theme: { ...DEFAULT_APP_THEME },
    logoUrl: "",
    logoWidth: 0,
    logoHeight: 0,
    loginTextAbove: "",
    loginTextBelow: "",
    couchdbPassword: "",
    flowLogDisplayMode: "utc",
    flowLogIana: "",
    flowLogUtcOffsetMinutes: 0,
    flowLogDockerAdjustMinutes: 0,
  };
}

async function getAppUiConfig() {
  const now = Date.now();
  if (cachedAppConfig && cachedAppConfigAuthoritative && now - cachedAppConfigLoadedAt < 30000) {
    return cachedAppConfig;
  }
  if (!configDb) {
    cachedAppConfig = defaultAppUiConfigObject();
    cachedAppConfigLoadedAt = now;
    cachedAppConfigAuthoritative = true;
    ensureAppUiTimeFields(cachedAppConfig);
    return cachedAppConfig;
  }

  let loadError = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      if (attempt > 0) await new Promise((r) => setTimeout(r, 200 * attempt));
      const result = await configDb.find({
        selector: { type: "elenko_app_config" },
        limit: 1,
      });
      const doc = (result.docs && result.docs[0]) || null;
      if (!doc) {
        cachedAppConfig = defaultAppUiConfigObject();
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
          flowLogDisplayMode: normalizeFlowLogDisplayMode(doc.flowLogDisplayMode),
          flowLogIana: typeof doc.flowLogIana === "string" ? doc.flowLogIana.trim() : "",
          flowLogUtcOffsetMinutes: parseBoundedInt(doc.flowLogUtcOffsetMinutes, 0, -840, 840),
          flowLogDockerAdjustMinutes: parseBoundedInt(doc.flowLogDockerAdjustMinutes, 0, -10080, 10080),
        };
      }
      cachedAppConfigLoadedAt = Date.now();
      cachedAppConfigAuthoritative = true;
      loadError = null;
      break;
    } catch (e) {
      loadError = e;
    }
  }

  if (loadError) {
    console.warn("getAppUiConfig: failed to load elenko_app_config from CouchDB after retries:", loadError.message || loadError);
    cachedAppConfigAuthoritative = false;
    if (!cachedAppConfig) {
      cachedAppConfig = defaultAppUiConfigObject();
    }
  }

  // Ensure new fields always present for older config docs or cache
  if (cachedAppConfig && typeof cachedAppConfig.loginTextAbove !== "string") cachedAppConfig.loginTextAbove = "";
  if (cachedAppConfig && typeof cachedAppConfig.loginTextBelow !== "string") cachedAppConfig.loginTextBelow = "";
  if (cachedAppConfig && typeof cachedAppConfig.couchdbPassword !== "string") cachedAppConfig.couchdbPassword = "";
  if (cachedAppConfig) ensureAppUiTimeFields(cachedAppConfig);
  return cachedAppConfig;
}

const FLOW_LOG_DISPLAY_MODES = new Set(["utc", "iana", "utc_offset"]);

function normalizeFlowLogDisplayMode(m) {
  const s = typeof m === "string" ? m.trim().toLowerCase() : "";
  return FLOW_LOG_DISPLAY_MODES.has(s) ? s : "utc";
}

function parseBoundedInt(v, def, min, max) {
  const n = typeof v === "number" ? v : parseInt(String(v || "").trim(), 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

/** Ensure flow-log time settings exist on an app UI object (mutates). */
function ensureAppUiTimeFields(obj) {
  if (!obj || typeof obj !== "object") return;
  obj.flowLogDisplayMode = normalizeFlowLogDisplayMode(obj.flowLogDisplayMode);
  obj.flowLogIana = typeof obj.flowLogIana === "string" ? obj.flowLogIana.trim() : "";
  obj.flowLogUtcOffsetMinutes = parseBoundedInt(obj.flowLogUtcOffsetMinutes, 0, -840, 840);
  obj.flowLogDockerAdjustMinutes = parseBoundedInt(obj.flowLogDockerAdjustMinutes, 0, -10080, 10080);
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function pad3(n) {
  return String(n).padStart(3, "0");
}

/** Civil time = UTC wall + fixed offset; ISO-like string with zone suffix ±HH:MM. */
function formatInstantWithFixedUtcOffsetLabel(ms, offsetMinutes) {
  const off = Math.round(offsetMinutes);
  const d = new Date(ms);
  const tic = Date.UTC(
    d.getUTCFullYear(),
    d.getUTCMonth(),
    d.getUTCDate(),
    d.getUTCHours(),
    d.getUTCMinutes() + off,
    d.getUTCSeconds(),
    d.getUTCMilliseconds()
  );
  const c = new Date(tic);
  const y = c.getUTCFullYear();
  const mo = pad2(c.getUTCMonth() + 1);
  const day = pad2(c.getUTCDate());
  const h = pad2(c.getUTCHours());
  const mi = pad2(c.getUTCMinutes());
  const s = pad2(c.getUTCSeconds());
  const f = pad3(c.getUTCMilliseconds());
  const sign = off >= 0 ? "+" : "-";
  const abs = Math.abs(off);
  const oh = pad2(Math.floor(abs / 60));
  const om = pad2(abs % 60);
  return `${y}-${mo}-${day}T${h}:${mi}:${s}.${f}${sign}${oh}:${om}`;
}

function formatFlowLogIanaDisplay(ms, timeZone) {
  const tz = typeof timeZone === "string" ? timeZone.trim() : "";
  if (!tz) return null;
  const d = new Date(ms);
  try {
    const fmt = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      fractionalSecondDigits: 3,
    });
    let s = fmt.format(d);
    s = s.replace(", ", "T");
    return `${s} [${tz}]`;
  } catch {
    return null;
  }
}

/** Human-oriented flow log time for an instant and app settings (empty if mode is UTC). */
function computeFlowLogTsDisplay(msEvent, cfg) {
  if (!cfg) return "";
  ensureAppUiTimeFields(cfg);
  const dockAdj = Number.isFinite(cfg.flowLogDockerAdjustMinutes) ? cfg.flowLogDockerAdjustMinutes : 0;
  const t = msEvent + dockAdj * 60000;
  const mode = cfg.flowLogDisplayMode || "utc";
  if (mode === "utc") return "";
  if (mode === "iana") {
    return formatFlowLogIanaDisplay(t, cfg.flowLogIana) || "";
  }
  if (mode === "utc_offset") {
    const off = Number.isFinite(cfg.flowLogUtcOffsetMinutes) ? cfg.flowLogUtcOffsetMinutes : 0;
    return formatInstantWithFixedUtcOffsetLabel(t, off);
  }
  return "";
}

/** Adds ts (UTC ISO) and optional tsDisplay for flow log lines from sync app cache. */
function augmentFlowLogMessageTimestamps(msg) {
  const msEvent = Date.now();
  msg.ts = new Date(msEvent).toISOString();
  const disp = computeFlowLogTsDisplay(msEvent, cachedAppConfig);
  if (disp) msg.tsDisplay = disp;
}

const CONFIG_EXPORT_VERSION = 1;
const EXPORTABLE_DB_TYPES = new Set(["elenko_profile", "elenko_entry_form"]);
const EXPORTABLE_CONFIG_TYPES = new Set([
  "elenko_app_config",
  "elenko_flow",
  "elenko_api",
  "elenko_js_processing",
  "elenko_query",
  "elenko_timer",
]);

function stripForExport(doc, type) {
  if (!doc || typeof doc !== "object") return null;
  const out = { ...doc };
  delete out._rev;
  if (type === "elenko_api") {
    out.apiKeyRef = "";
    out.apiUserRef = "";
    out.apiPasswordRef = "";
  }
  if (type === "elenko_app_config") {
    delete out.couchdbPassword;
  }
  if (type === "elenko_query") {
    // No secret fields yet; keep all properties for now.
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

  /** UI pseudo-profile "Elenko App Design" — not an elenko_profile _id in the main DB. */
  if (scope === "profile" && profileId === "__app__") {
    if (configDb) {
      const appResult = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 1 });
      const appDoc = appResult.docs && appResult.docs[0];
      if (appDoc) addConfig(appDoc);
    }
    return {
      version: CONFIG_EXPORT_VERSION,
      scope: "profile",
      profileId: "__app__",
      exportedAt: new Date().toISOString(),
      documents: { db: docsDb, configDb: docsConfig },
    };
  }

  const profileIds = scope === "all"
    ? (await db.find({ selector: { type: "elenko_profile" }, fields: ["_id"], limit: 1000 })).docs.map((p) => p._id)
    : (profileId ? [profileId] : []);

  let allTimerDocs = [];
  if (configDb && profileIds.length > 0) {
    try {
      const timerFind = await configDb.find({ selector: { type: "elenko_timer" }, limit: 500 });
      allTimerDocs = Array.isArray(timerFind.docs) ? timerFind.docs : [];
    } catch (_) {}
  }

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

    // Linked queries referenced from Single Entry forms.
    if (configDb) {
      const linkedQueryRefs = new Set();
      for (const form of formDocs) {
        const linkedQuery =
          form && form.linkedQuery && typeof form.linkedQuery === "object" ? form.linkedQuery : null;
        const linkedQueryId =
          linkedQuery && typeof linkedQuery.id === "string" ? linkedQuery.id.trim() : "";
        if (linkedQueryId) linkedQueryRefs.add(linkedQueryId);
      }
      if (linkedQueryRefs.size > 0) {
        const resolvedQueryIds = await resolveConfigDocIds(
          configDb,
          [...linkedQueryRefs],
          "elenko_query",
          "name"
        );
        for (const qid of resolvedQueryIds) {
          try {
            const queryDoc = await configDb.get(qid);
            if (queryDoc && queryDoc.type === "elenko_query") addConfig(queryDoc);
          } catch (_) {}
        }
      }
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

    const profileNameTrim = typeof profile.name === "string" ? profile.name.trim() : "";
    const timerDocsForProfile = allTimerDocs.filter((t) => {
      if (!t || t.type !== "elenko_timer") return false;
      const tPid = typeof t.profileId === "string" ? t.profileId.trim() : "";
      return tPid === pid || (profileNameTrim !== "" && tPid === profileNameTrim);
    });
    if (configDb) {
      for (const t of timerDocsForProfile) {
        const flowRef = typeof t.flowId === "string" ? t.flowId.trim() : "";
        if (!flowRef) continue;
        const resolvedTimerFlow = await resolveConfigDocIds(configDb, [flowRef], "elenko_flow", "name");
        for (const rf of resolvedTimerFlow) flowIdSet.add(rf);
      }
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

    for (const t of timerDocsForProfile) addConfig(t);

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

/**
 * There must be only one elenko_app_config; getAppUiConfig uses find(..., limit: 1).
 * Exports carry the source CouchDB _id, so a plain get+insert creates a second doc and
 * the UI keeps showing the old one. Merge into the existing server doc (by _id match or
 * stable first doc) and remove any extra app_config documents.
 */
async function upsertAppConfigFromImport(rawDoc, overwrite) {
  if (!configDb) return 0;
  if (!overwrite) return 0;
  const incoming = { ...rawDoc };
  delete incoming._rev;
  const incomingId = incoming._id != null ? String(incoming._id) : "";

  const listRes = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 100 });
  let existingList = Array.isArray(listRes.docs) ? listRes.docs.slice() : [];
  existingList.sort((a, b) => String(a._id || "").localeCompare(String(b._id || "")));

  let canonical = null;
  if (incomingId && existingList.some((d) => d && d._id === incomingId)) {
    canonical = existingList.find((d) => d && d._id === incomingId);
  } else if (existingList.length > 0) {
    canonical = existingList[0];
  }

  const incomingPw =
    incoming.couchdbPassword != null && String(incoming.couchdbPassword).trim() !== ""
      ? String(incoming.couchdbPassword)
      : "";

  let keepId = null;

  if (!canonical) {
    const ins = await configDb.insert({ ...incoming });
    keepId = ins.id || incomingId || null;
  } else {
    const preservePassword =
      typeof canonical.couchdbPassword === "string" && canonical.couchdbPassword.trim() !== "";
    const merged = { ...canonical, ...incoming };
    merged._id = canonical._id;
    merged._rev = canonical._rev;
    if (!incomingPw && preservePassword) merged.couchdbPassword = canonical.couchdbPassword;
    await configDb.insert(merged);
    keepId = canonical._id;
  }

  if (keepId) {
    const dupRes = await configDb.find({ selector: { type: "elenko_app_config" }, limit: 100 });
    for (const d of dupRes.docs || []) {
      if (d && d._id && d._id !== keepId) {
        try {
          await configDb.destroy(d._id, d._rev);
        } catch (_) {}
      }
    }
  }

  return 1;
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
    if (toInsert.type === "elenko_api") {
      toInsert.apiKeyRef = toInsert.apiKeyRef || "";
      toInsert.apiUserRef = toInsert.apiUserRef || "";
      toInsert.apiPasswordRef = toInsert.apiPasswordRef || "";
    }
    try {
      if (!configDb) {
        errors.push({ id: id || "(new)", type: doc.type, message: "Config store not available" });
        continue;
      }
      if (toInsert.type === "elenko_app_config") {
        await upsertAppConfigFromImport(doc, overwrite);
        importedConfig++;
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
    invalidateAppUiConfigCache();
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
    if (msg.type !== "apiResponse") return;
    const requestId = msg.requestId;
    if (requestId != null && pendingApiRequests.has(requestId)) {
      const p = pendingApiRequests.get(requestId);
      pendingApiRequests.delete(requestId);
      if (p.timeoutId) clearTimeout(p.timeoutId);
      const apiKeyPreview = p.apiKeyPreview;
      const authType = p.authType || "";
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
          authType,
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
          let profileDoc = null;
          try {
            const pd = await db.get(profileId);
            if (pd && pd.type === "elenko_profile") profileDoc = pd;
          } catch (_) {}
          record[fieldName] = applyPlainValueToProfileField(profileDoc, record, fieldName, bodyToStore);
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
    if (msg && msg.type === "flow.scriptResponse") {
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
    if (msg && msg.type === "scriptWorker.error") {
      console.error("Script worker error:", msg.error || msg);
      return;
    }
    if (msg.type === "callApi") {
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
          let bundle;
          try {
            bundle = await resolveApiWorkerAuthBundle(apiDoc);
          } catch (credErr) {
            const field = credErr.credentialField || "apiKeyRef";
            const ref =
              credErr.apiKeyRef || credErr.apiUserRef || credErr.apiPasswordRef || "";
            if (credErr.message === "emptyKey") {
              sendFlowMessage("api.keyLookupError", {
                entryId: msg.entryId,
                profileId: msg.profileId,
                apiKeyRef: ref,
                credentialField: field,
                code: "",
                reason: "Credential document has no key/value field",
              });
            } else {
              const info = apiKeyLookupErrorInfo(credErr.cause || credErr);
              sendFlowMessage("api.keyLookupError", {
                entryId: msg.entryId,
                profileId: msg.profileId,
                apiKeyRef: ref,
                credentialField: field,
                code: info.code,
                reason: info.message,
              });
            }
            return;
          }
          if (bundle.authType === "basic" || bundle.authType === "digest" || bundle.authType === "fritz") {
            if (!bundle.apiUserRef || !bundle.apiPasswordRef) {
              sendFlowMessage("api.keyLookupError", {
                entryId: msg.entryId,
                profileId: msg.profileId,
                apiKeyRef: "",
                credentialField: !bundle.apiUserRef ? "apiUserRef" : "apiPasswordRef",
                code: "",
                reason: "Set username and password key document IDs for Basic, Digest, or FRITZ!Box session auth.",
              });
              return;
            }
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
            authType: bundle.authType,
          });
          const apiKeyPreview = previewApiCredentialsForFlow(bundle);
          apiWorker.postMessage({
            type: "apiRequest",
            apiDoc: apiDocPayloadForApiWorker(apiDoc),
            authType: bundle.authType,
            apiKey: bundle.apiKey,
            apiUsername: bundle.apiUsername,
            apiPassword: bundle.apiPassword,
            dataset: msg.dataset,
            entryId: msg.entryId,
            profileId: msg.profileId,
          });
          sendFlowMessage("api.keyPreview", {
            entryId: msg.entryId,
            profileId: msg.profileId,
            authType: bundle.authType,
            apiKeyPreview: apiKeyPreview || "",
          });
        } catch (err) {
          console.error("Flow worker: callApi failed:", err);
        }
      })();
      return;
    }
    if (msg.type === "createResponseInProfile") {
      const sourceDocId = (msg.sourceDocId != null ? String(msg.sourceDocId) : "").trim();
      const profileId = (msg.profileId != null ? String(msg.profileId) : "").trim();
      if (!sourceDocId || !profileId) {
        console.error("Flow worker: createResponseInProfile missing sourceDocId/profileId");
        return;
      }
      (async () => {
        try {
          await createResponseEntryFromContext(db, { dataset: msg.dataset, profileId, entryId: sourceDocId }, sourceDocId);
        } catch (err) {
          console.error("Flow worker: createResponseInProfile failed:", err);
        }
      })();
      return;
    }
    if (msg.type !== "createEntryInProfile") return;
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

async function syncTimersFromDb() {
  if (!timerWorker || !configDb) return;
  try {
    const result = await configDb.find({ selector: { type: "elenko_timer" }, limit: 500 });
    const timers = [];
    for (const doc of result.docs || []) {
      const p = timerDocumentToWorkerPayload(doc);
      if (p) timers.push(p);
    }
    timerWorker.postMessage({ type: "syncTimers", timers });
  } catch (e) {
    console.error("syncTimersFromDb:", e);
  }
}

function syncTimersFromDbSoon(reason) {
  syncTimersFromDb().catch((e) => console.error("syncTimersFromDb (" + reason + "):", e));
}

async function handleTimerFireMessage(msg) {
  if (!msg || msg.type !== "timerFire") return;
  const timerId = msg.timerId != null ? String(msg.timerId) : "";
  if (!timerId || !configDb || !db) return;

  let timerDoc = null;
  try {
    timerDoc = await configDb.get(timerId);
  } catch (e) {
    if (e.statusCode !== 404) console.error("Timer load:", e);
    return;
  }
  if (!timerDoc || timerDoc.type !== "elenko_timer") return;
  if (!(timerDoc.active === true || timerDoc.active === "true" || timerDoc.active === "on")) return;

  const flowRef = timerDoc.flowId != null ? String(timerDoc.flowId).trim() : "";
  const profileId = timerDoc.profileId != null ? String(timerDoc.profileId).trim() : "";
  if (!flowRef || !profileId) return;

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
    sendFlowMessage("timer.error", { timerId, error: "Flow not found", flowRef });
    return;
  }

  let profileDoc = null;
  try {
    profileDoc = await db.get(profileId);
  } catch (e) {
    if (e.statusCode !== 404) throw e;
  }
  if (!profileDoc || profileDoc.type !== "elenko_profile") {
    sendFlowMessage("timer.error", { timerId, error: "Profile not found", profileId });
    return;
  }

  const entryIdRaw = timerDoc.entryId != null ? String(timerDoc.entryId).trim() : "";
  const param = timerDoc.param != null ? String(timerDoc.param).trim() : "";

  let record = null;
  if (entryIdRaw) {
    try {
      record = await db.get(entryIdRaw);
    } catch (e) {
      if (e.statusCode !== 404) throw e;
    }
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      sendFlowMessage("timer.error", { timerId, error: "Entry not found or wrong profile", entryId: entryIdRaw });
      return;
    }
  }

  const firedAt = new Date().toISOString();
  sendFlowMessage("timer.fire", {
    timerId,
    timerName: timerDoc.name || timerId,
    flowId: flowDoc._id,
    flowName: flowDoc.name || flowDoc._id,
    profileId,
    entryId: entryIdRaw,
    param,
    firedAt,
  });

  const context = {
    profileId,
    entryId: entryIdRaw,
    profileName: profileDoc.name || profileId,
    dataset: record ? { ...record } : { _timerFiredAt: firedAt },
    param,
    suppressPipelineCreate: false,
    suppressPipelineEntryWrites: !entryIdRaw,
  };

  try {
    await runPipeline(context, flowDoc);
  } catch (pipeErr) {
    console.error("Timer pipeline error:", pipeErr);
    sendFlowMessage("timer.pipelineError", {
      timerId,
      error: pipeErr && pipeErr.message ? String(pipeErr.message) : "Pipeline failed",
    });
  }
}

function startTimerWorker() {
  const workerPath = path.join(__dirname, "timerWorker.js");
  timerWorker = new Worker(workerPath, {
    workerData: {},
  });
  timerWorker.on("error", (err) => {
    console.error("Timer worker error:", err);
  });
  timerWorker.on("exit", (code) => {
    if (code !== 0) console.error(`Timer worker exited with code ${code}`);
  });
  timerWorker.on("message", (wmsg) => {
    if (!wmsg || wmsg.type !== "timerFire") return;
    handleTimerFireMessage(wmsg).catch((e) => console.error("handleTimerFireMessage:", e));
  });
}

function sendFlowMessage(type, payload) {
  if (!flowWorker) return;
  try {
    const msg = { type, payload };
    augmentFlowLogMessageTimestamps(msg);
    flowWorker.postMessage(msg);
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

const ELNK_MAGIC = Buffer.from("ELNK", "ascii");
const ELNK_VERSION_V1 = Buffer.from("0001", "ascii");
const ELNK_HEADER_LEN = 12;
const ELNK_MASTER_KEY_LEN = 32;
const ELNK_PAYLOAD_V1_LEN = ELNK_MASTER_KEY_LEN;
const KEYFILE_DOWNLOAD_TTL_MS = 5 * 60 * 1000;

/** sessionId → { masterKey: Buffer, expiresAt: number } — never persisted to CouchDB or session store */
const inMemoryUserKeys = new Map();
/** one-time admin download tokens after key generation */
const keyFileDownloadTokens = new Map();

function sanitizeUsernameForFilename(username) {
  return String(username || "user")
    .replace(/[^\w.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64) || "user";
}

function keyFileDownloadFilename(username) {
  return `elenko-${sanitizeUsernameForFilename(username)}.key`;
}

function userKeyFileRegistered(userDoc) {
  return !!(userDoc && userDoc.keyFile && userDoc.keyFile.registered === true);
}

function userEnforceKeyLogin(userDoc) {
  return !!(userDoc && userDoc.enforceKeyLogin === true);
}

function buildElnkKeyBlob(masterKey) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== ELNK_MASTER_KEY_LEN) {
    throw new Error("Master key must be 32 bytes");
  }
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(ELNK_PAYLOAD_V1_LEN, 0);
  return Buffer.concat([ELNK_MAGIC, ELNK_VERSION_V1, lenBuf, masterKey]);
}

function parseElnkKeyBlob(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);
  if (buf.length < ELNK_HEADER_LEN) {
    throw new Error("Key file is too short");
  }
  if (!buf.subarray(0, 4).equals(ELNK_MAGIC)) {
    throw new Error('Key file must start with "ELNK"');
  }
  const version = buf.subarray(4, 8).toString("ascii");
  if (version !== "0001") {
    throw new Error(`Unsupported key file version: ${version}`);
  }
  const payloadLen = buf.readUInt32BE(8);
  const payload = buf.subarray(ELNK_HEADER_LEN, ELNK_HEADER_LEN + payloadLen);
  if (payload.length !== payloadLen) {
    throw new Error("Key file length does not match header");
  }
  if (buf.length !== ELNK_HEADER_LEN + payloadLen) {
    throw new Error("Key file contains trailing data");
  }
  if (version === "0001" && payloadLen !== ELNK_PAYLOAD_V1_LEN) {
    throw new Error("Invalid v1 key payload length");
  }
  return { version, payload, masterKey: payload.subarray(0, ELNK_MASTER_KEY_LEN) };
}

function hashKeyFilePayload(payloadBytes, saltHex) {
  const salt = Buffer.from(saltHex, "hex");
  const payload = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(payloadBytes || []);
  return crypto.createHash("sha256").update(Buffer.concat([salt, payload])).digest("hex");
}

function buildKeyFileRegistrationFromBlob(buffer) {
  const parsed = parseElnkKeyBlob(buffer);
  const salt = crypto.randomBytes(SALT_LEN).toString("hex");
  const hash = hashKeyFilePayload(parsed.payload, salt);
  const now = new Date().toISOString();
  return {
    keyFile: {
      registered: true,
      blobVersion: parsed.version,
      salt,
      hash,
      payloadLength: parsed.payload.length,
      createdAt: now,
      lastUsedAt: null,
    },
  };
}

function buildKeyFileRegistrationFromMasterKey(masterKey) {
  const blob = buildElnkKeyBlob(masterKey);
  const built = buildKeyFileRegistrationFromBlob(blob);
  return { blob, keyFile: built.keyFile };
}

/** Admin upload: file name must be elenko-<sanitized-username>.key */
function validateKeyFileUploadFilename(originalName, username) {
  const base = path.basename(String(originalName || "").trim());
  if (!base) return { ok: false, error: "Missing file name." };
  const m = /^elenko-([\w.-]+)\.key$/i.exec(base);
  if (!m) {
    return { ok: false, error: "File name must be elenko-<username>.key (e.g. elenko-admin.key)." };
  }
  const expected = sanitizeUsernameForFilename(username);
  if (m[1].toLowerCase() !== expected.toLowerCase()) {
    return { ok: false, error: `File name must be elenko-${expected}.key for user "${username}".` };
  }
  return { ok: true, filename: base };
}

function verifyKeyFileBlob(buffer, keyFileDoc) {
  if (!keyFileDoc || keyFileDoc.registered !== true) {
    return { ok: false, error: "No key file registered for this user" };
  }
  try {
    const parsed = parseElnkKeyBlob(buffer);
    if (parsed.payload.length !== keyFileDoc.payloadLength) {
      return { ok: false, error: "Key file payload length mismatch" };
    }
    const expected = keyFileDoc.hash;
    const actual = hashKeyFilePayload(parsed.payload, keyFileDoc.salt);
    const a = Buffer.from(actual, "hex");
    const b = Buffer.from(expected, "hex");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, error: "Invalid key file" };
    }
    return { ok: true, masterKey: parsed.masterKey, payload: parsed.payload };
  } catch (e) {
    return { ok: false, error: e && e.message ? String(e.message) : "Invalid key file" };
  }
}

function setUserMasterKey(sessionId, masterKey) {
  if (!sessionId || !Buffer.isBuffer(masterKey)) return;
  inMemoryUserKeys.set(sessionId, {
    masterKey: Buffer.from(masterKey),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
  });
}

function getUserMasterKey(sessionId) {
  if (!sessionId) return null;
  const entry = inMemoryUserKeys.get(sessionId);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    inMemoryUserKeys.delete(sessionId);
    return null;
  }
  return entry.masterKey;
}

function clearUserMasterKey(sessionId) {
  if (sessionId) inMemoryUserKeys.delete(sessionId);
}

const ELENKO_ENC_PREFIX = "elenkoenc:v1:";
const ELENKO_ENC_ATTACH_MAGIC = Buffer.from("ELNKENC1", "ascii");
const PROFILE_KEY_HKDF_INFO = Buffer.from("elenko-db-v1", "utf8");

function isEncryptedFieldValue(value) {
  return typeof value === "string" && value.startsWith(ELENKO_ENC_PREFIX);
}

function isProfilePersonalEncryptionEnabled(profileDoc) {
  return !!(
    profileDoc &&
    profileDoc.encryption &&
    profileDoc.encryption.enabled === true &&
    profileDoc.encryption.mode === "personal"
  );
}

function getProfileEncryptionOwnerUsername(profileDoc) {
  if (!isProfilePersonalEncryptionEnabled(profileDoc)) return null;
  const u = profileDoc.encryption.ownerUsername;
  return typeof u === "string" && u.trim() ? u.trim() : null;
}

function isSessionUserAdmin(req) {
  return (req.session && req.session.role) === "admin";
}

/** Personal encrypted profiles appear only for the encryption owner and admins. */
function canUserSeePersonalEncryptedProfile(req, profileDoc) {
  if (!isProfilePersonalEncryptionEnabled(profileDoc)) return true;
  if (isSessionUserAdmin(req)) return true;
  return getSessionUsername(req) === getProfileEncryptionOwnerUsername(profileDoc);
}

function filterProfilesVisibleToUser(req, profiles) {
  return (profiles || []).filter((p) => canUserSeePersonalEncryptedProfile(req, p));
}

function respondEncryptionAccessDenied(res, encAccess, format = "json") {
  if (encAccess && encAccess.hidden) {
    if (format === "html") return res.status(404).send(renderErrorPage("Profile not found"));
    if (format === "empty") return res.status(404).end();
    return res.status(404).json({ error: "Profile not found" });
  }
  const status = (encAccess && encAccess.status) || 403;
  const message = (encAccess && encAccess.error) || "Access denied";
  if (format === "html") return res.status(status).send(renderErrorPage(message));
  if (format === "empty") return res.status(status).end();
  return res.status(status).json({ error: message });
}

function deriveProfileKey(masterKey, profileId) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== ELNK_MASTER_KEY_LEN) {
    throw new Error("Invalid master key");
  }
  return crypto.hkdfSync(
    "sha256",
    masterKey,
    Buffer.from(String(profileId), "utf8"),
    PROFILE_KEY_HKDF_INFO,
    ELNK_MASTER_KEY_LEN
  );
}

function encryptFieldValue(profileKey, plaintext) {
  const text = plaintext != null ? String(plaintext) : "";
  if (text === "") return "";
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", profileKey, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ELENKO_ENC_PREFIX + Buffer.concat([iv, tag, enc]).toString("base64url");
}

function decryptFieldValue(profileKey, stored) {
  if (stored == null || stored === "") return "";
  const s = String(stored);
  if (!s.startsWith(ELENKO_ENC_PREFIX)) return s;
  const buf = Buffer.from(s.slice(ELENKO_ENC_PREFIX.length), "base64url");
  if (buf.length < 28) throw new Error("Invalid encrypted field");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", profileKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

function computePrimaryKeyToken(profileKey, primaryKeyPlaintext) {
  return crypto.createHmac("sha256", profileKey).update(String(primaryKeyPlaintext), "utf8").digest("hex");
}

function encryptAttachmentBuffer(profileKey, buffer) {
  const data = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", profileKey, iv);
  const enc = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ELENKO_ENC_ATTACH_MAGIC, iv, tag, enc]);
}

function decryptAttachmentBuffer(profileKey, buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);
  if (buf.length < ELENKO_ENC_ATTACH_MAGIC.length + 28) return buf;
  if (!buf.subarray(0, ELENKO_ENC_ATTACH_MAGIC.length).equals(ELENKO_ENC_ATTACH_MAGIC)) {
    return buf;
  }
  const base = ELENKO_ENC_ATTACH_MAGIC.length;
  const iv = buf.subarray(base, base + 12);
  const tag = buf.subarray(base + 12, base + 28);
  const data = buf.subarray(base + 28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", profileKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function getNonEncryptableFieldSet(profileDoc, formDoc) {
  return getAttachmentBackedFieldNames(profileDoc, formDoc);
}

function encryptRecordFieldsForStorage(record, profileDoc, profileKey, formDoc) {
  const fieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const skip = getNonEncryptableFieldSet(profileDoc, formDoc);
  if (record.primaryKey) {
    record.primaryKey = computePrimaryKeyToken(profileKey, record.primaryKey);
  }
  record.sortKey = [record.createdAt || "", record._id || ""];
  for (const fn of fieldNames) {
    if (skip.has(fn)) continue;
    const v = record[fn] != null ? String(record[fn]) : "";
    record[fn] = v === "" ? "" : encryptFieldValue(profileKey, v);
  }
  record.encrypted = true;
  return record;
}

function decryptRecordFieldsInPlace(record, profileDoc, profileKey, formDoc) {
  if (!record || !profileKey) return record;
  const fieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
  const skip = getNonEncryptableFieldSet(profileDoc, formDoc);
  for (const fn of fieldNames) {
    if (skip.has(fn)) continue;
    if (record[fn] != null && isEncryptedFieldValue(record[fn])) {
      record[fn] = decryptFieldValue(profileKey, record[fn]);
    }
  }
  return record;
}

function decryptRecordsForProfile(records, profileDoc, profileKey, formDoc) {
  return (records || []).map((rec) => {
    const copy = { ...rec };
    decryptRecordFieldsInPlace(copy, profileDoc, profileKey, formDoc);
    return copy;
  });
}

async function resolveProfileEncryptionAccess(req, profileDoc) {
  if (!isProfilePersonalEncryptionEnabled(profileDoc)) {
    return { ok: true, profileKey: null };
  }
  const owner = getProfileEncryptionOwnerUsername(profileDoc);
  if (!owner) {
    return {
      ok: false,
      status: 403,
      error: "This encrypted database has no encryption owner configured.",
      needKeyUnlock: false,
    };
  }
  const sessionUser = getSessionUsername(req);
  if (sessionUser !== owner) {
    if (isSessionUserAdmin(req)) {
      return {
        ok: false,
        status: 403,
        error: `This database is encrypted for personal use. Only ${owner} can access its entries.`,
        needKeyUnlock: false,
      };
    }
    return {
      ok: false,
      status: 404,
      error: "Profile not found",
      hidden: true,
      needKeyUnlock: false,
    };
  }
  const masterKey = getUserMasterKey(req.sessionID);
  if (!masterKey) {
    return {
      ok: false,
      status: 403,
      error: "Unlock your key file to access this encrypted database.",
      needKeyUnlock: true,
    };
  }
  return { ok: true, profileKey: deriveProfileKey(masterKey, profileDoc._id), owner };
}

async function loadUsersWithRegisteredKeyFiles(dbInstance) {
  try {
    const result = await dbInstance.find({
      selector: { type: "elenko_user" },
      fields: ["_id", "username", "keyFile"],
      limit: 500,
    });
    return (result.docs || [])
      .filter((u) => userKeyFileRegistered(u))
      .sort((a, b) => String(a.username).localeCompare(String(b.username)));
  } catch (_) {
    return [];
  }
}

async function userHasRegisteredKeyFile(dbInstance, username) {
  const u = String(username || "").trim();
  if (!u) return false;
  try {
    const result = await dbInstance.find({ selector: { type: "elenko_user", username: u }, limit: 1 });
    return userKeyFileRegistered(result.docs && result.docs[0]);
  } catch (_) {
    return false;
  }
}

function entryMatchesSearchQueryCaseInsensitive(record, fieldNames, query) {
  const q = String(query || "").toLowerCase();
  if (!q) return true;
  for (const fn of fieldNames) {
    const v = record[fn] != null ? String(record[fn]).toLowerCase() : "";
    if (v.includes(q)) return true;
  }
  return false;
}

async function loadEncryptedProfileEntryList(dbInstance, profileDoc, profileKey, opts) {
  const profileId = profileDoc._id;
  const fieldNames = opts.fieldNames || [];
  const page = Math.max(1, opts.page || 1);
  const pageSize = opts.profileEntriesPageSize || ENTRIES_PAGE_SIZE;
  const searchQuery = (opts.searchQuery || "").trim();
  const useAccentFolding = !!opts.useAccentFolding;
  const normalizedSearch = opts.normalizedSearch || "";
  const sortKeyFields = Array.isArray(opts.sortKeyFields) ? opts.sortKeyFields : [];
  const sortDirection = opts.sortDirection === "desc" ? "desc" : "asc";
  const skip = (page - 1) * pageSize;
  const SORT_FETCH_LIMIT = 50000;
  const fieldsForFind = fieldNames.length
    ? ["_id", "_rev", "sortKey", "isResponse", "createdAt", ...fieldNames]
    : ["_id", "_rev", "sortKey", "isResponse", "createdAt"];
  const sortResult = await dbInstance.find({
    selector: { type: "elenko_record", profileId },
    fields: fieldsForFind,
    limit: SORT_FETCH_LIMIT,
  });
  let fullDocs = sortResult.docs || [];
  for (const d of fullDocs) {
    decryptRecordFieldsInPlace(d, profileDoc, profileKey, null);
  }
  if (searchQuery) {
    if (useAccentFolding) {
      fullDocs =
        searchQuery && !normalizedSearch
          ? []
          : fullDocs.filter((d) => entryMatchesSearchQuery(d, fieldNames, normalizedSearch));
    } else {
      fullDocs = fullDocs.filter((d) => entryMatchesSearchQueryCaseInsensitive(d, fieldNames, searchQuery));
    }
  }
  if (sortKeyFields.length > 0) {
    for (const d of fullDocs) {
      d.sortKey = buildSortKey(d, sortKeyFields);
    }
    fullDocs.sort((a, b) => compareRecordsByProfileSort(a, b, sortDirection));
  } else {
    fullDocs.sort((a, b) => String(a._id).localeCompare(String(b._id)));
  }
  const totalPages = Math.max(1, Math.ceil(fullDocs.length / pageSize));
  const pageDocs = fullDocs.slice(skip, skip + pageSize + 1);
  return {
    records: pageDocs.slice(0, pageSize),
    pagination: { totalPages, hasNext: pageDocs.length > pageSize, hasPrev: page > 1 },
  };
}

async function profileHasUnencryptedEntries(dbInstance, profileId) {
  try {
    const result = await dbInstance.find({
      selector: { type: "elenko_record", profileId },
      fields: ["_id", "encrypted"],
      limit: 50000,
    });
    return (result.docs || []).some((d) => d && d.encrypted !== true);
  } catch (_) {
    return false;
  }
}

async function migrateProfileRecordsToEncryption(dbInstance, profileDoc, profileKey) {
  const profileId = profileDoc._id;
  const result = await dbInstance.find({
    selector: { type: "elenko_record", profileId },
    limit: 50000,
  });
  const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
  const now = new Date().toISOString();
  for (const rec of result.docs || []) {
    if (rec.encrypted === true) continue;
    rec.sortKey = buildSortKey(rec, sortKeyFields);
    try {
      applyPrimaryKeyToRecord(rec, profileDoc);
    } catch (_) {
      delete rec.primaryKey;
    }
    encryptRecordFieldsForStorage(rec, profileDoc, profileKey, null);
    rec.updatedAt = now;
    await dbInstance.insert(rec);
  }
}

async function recomputeEncryptedPrimaryKeysForProfile(dbInstance, profileDoc, profileKey) {
  const profileId = profileDoc._id;
  const result = await dbInstance.find({
    selector: { type: "elenko_record", profileId },
    limit: 50000,
  });
  const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
  const now = new Date().toISOString();
  for (const rec of result.docs || []) {
    if (rec.encrypted === true) {
      decryptRecordFieldsInPlace(rec, profileDoc, profileKey, null);
    }
    rec.sortKey = buildSortKey(rec, sortKeyFields);
    try {
      applyPrimaryKeyToRecord(rec, profileDoc);
    } catch (_) {
      delete rec.primaryKey;
    }
    encryptRecordFieldsForStorage(rec, profileDoc, profileKey, null);
    rec.updatedAt = now;
    await dbInstance.insert(rec);
  }
}

function storeKeyFileDownloadToken(username, blob) {
  const token = crypto.randomBytes(24).toString("hex");
  keyFileDownloadTokens.set(token, {
    username,
    blob: Buffer.from(blob),
    filename: keyFileDownloadFilename(username),
    expiresAt: Date.now() + KEYFILE_DOWNLOAD_TTL_MS,
  });
  return token;
}

function consumeKeyFileDownloadToken(token) {
  if (!token) return null;
  const entry = keyFileDownloadTokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    keyFileDownloadTokens.delete(token);
    return null;
  }
  keyFileDownloadTokens.delete(token);
  return entry;
}

function peekKeyFileDownloadToken(token) {
  if (!token) return null;
  const entry = keyFileDownloadTokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    keyFileDownloadTokens.delete(token);
    return null;
  }
  return entry;
}

function loginKeyFileParser(req, res, next) {
  const ct = req.get("content-type") || "";
  if (ct.includes("multipart/form-data")) {
    return keyFileUpload.single("keyFile")(req, res, next);
  }
  next();
}

function applyKeyFileToSession(req, userDoc, uploadedBuffer) {
  const registered = userKeyFileRegistered(userDoc);
  const enforce = userEnforceKeyLogin(userDoc);
  req.session.keyFileRegistered = registered;
  req.session.enforceKeyLogin = enforce;
  req.session.keyFileUnlocked = false;
  clearUserMasterKey(req.sessionID);

  if (!registered) {
    if (uploadedBuffer && uploadedBuffer.length > 0) {
      return { ok: false, error: "This user has no registered key file" };
    }
    return { ok: true };
  }

  if (!uploadedBuffer || uploadedBuffer.length === 0) {
    if (enforce) {
      return { ok: false, error: "Key file is required for this account" };
    }
    return { ok: true, keyFileMissing: true };
  }

  const verified = verifyKeyFileBlob(uploadedBuffer, userDoc.keyFile);
  if (!verified.ok) {
    return { ok: false, error: verified.error || "Invalid key file" };
  }
  setUserMasterKey(req.sessionID, verified.masterKey);
  req.session.keyFileUnlocked = true;
  return { ok: true, keyFileUnlocked: true };
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
    invalidateAppUiConfigCache();
    syncTimersFromDbSoon("after-bootstrap-restore");
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

  // Index for purge-old flow step (createdAt older than cutoff)
  try {
    await db.createIndex({
      index: { fields: ["type", "profileId", "createdAt"] },
      name: "records-by-profile-createdAt",
    });
  } catch (e) {
    // Index may already exist
  }

  // Index for response documents linked to a parent entry
  try {
    await db.createIndex({
      index: { fields: ["type", "profileId", "isResponse", "responseToDocId"] },
      name: "records-by-response-parent",
    });
  } catch (e) {
    // Index may already exist
  }
  // Index for business primaryKey (global uniqueness / lookup)
  try {
    await db.createIndex({
      index: { fields: ["type", "primaryKey"] },
      name: "records-by-primarykey",
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
      const ins = await db.insert({
        type: "elenko_profile",
        name: "Example profile",
        description: "Sample Elenko database profile (CouchDB documents). Edit or delete in CouchDB.",
        createdAt: new Date().toISOString(),
      });
      let seedProf = await db.get(ins.id);
      seedProf = await ensureProfileDbCode8(db, seedProf);
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
        if (db) {
          syncTimersFromDbSoon("lazy-init-admin");
          return next();
        }
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
          syncTimersFromDbSoon("setup-get-admin");
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
    invalidateAppUiConfigCache();
    syncTimersFromDbSoon("setup-complete");
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
    invalidateAppUiConfigCache();
  } catch (e) {
    console.error("Failed to update app config with new password:", e);
  }
  syncTimersFromDbSoon("couch-password-changed");
  return res.redirect("/login");
});

app.get("/login", async (req, res) => {
  if (req.session && req.session.user) return res.redirect("/");
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8").send(renderLoginPage(null, appUi));
});

app.post("/login", loginKeyFileParser, async (req, res) => {
  const appUi = await getAppUiConfig();
  const username = String((req.body && req.body.username) || "").trim();
  const password = (req.body && req.body.password) || "";
  const uploadedKey = req.file && req.file.buffer ? req.file.buffer : null;
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
    const keyResult = applyKeyFileToSession(req, user, uploadedKey);
    if (!keyResult.ok) {
      return res
        .set("Content-Type", "text/html; charset=utf-8")
        .send(renderLoginPage(keyResult.error || "Invalid key file.", appUi));
    }
    req.session.user = user.username;
    req.session.role = (user.role === "user" ? "editor" : user.role) || "editor";
    if (keyResult.keyFileUnlocked && user.keyFile) {
      try {
        user.keyFile.lastUsedAt = new Date().toISOString();
        await db.insert(user);
      } catch (e) {
        console.warn("Failed to update keyFile.lastUsedAt:", e.message || e);
      }
    }
    sendFlowMessage("auth.login", {
      username: user.username,
      role: req.session.role,
      keyFileUnlocked: !!req.session.keyFileUnlocked,
    });
    return res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderLoginPage("Invalid username or password.", appUi));
  }
});

app.get("/logout", (req, res) => {
  clearUserMasterKey(req.sessionID);
  req.session.destroy(() => {});
  res.redirect("/login");
});

app.get("/account/unlock-keyfile", async (req, res) => {
  if (!req.session || !req.session.user) return res.redirect("/login");
  const appUi = await getAppUiConfig();
  res.set("Content-Type", "text/html; charset=utf-8").send(renderUnlockKeyFilePage(null, appUi, req.session));
});

app.post("/account/unlock-keyfile", loginKeyFileParser, async (req, res) => {
  if (!req.session || !req.session.user) return res.redirect("/login");
  const appUi = await getAppUiConfig();
  const username = req.session.user;
  const uploadedKey = req.file && req.file.buffer ? req.file.buffer : null;
  if (!uploadedKey || uploadedKey.length === 0) {
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderUnlockKeyFilePage("Choose your key file.", appUi, req.session));
  }
  try {
    const result = await db.find({ selector: { type: "elenko_user", username }, limit: 1 });
    const user = result.docs && result.docs[0];
    if (!user) {
      return res
        .set("Content-Type", "text/html; charset=utf-8")
        .send(renderUnlockKeyFilePage("User not found.", appUi, req.session));
    }
    if (!userKeyFileRegistered(user)) {
      return res
        .set("Content-Type", "text/html; charset=utf-8")
        .send(renderUnlockKeyFilePage("No key file is registered for your account.", appUi, req.session));
    }
    const verified = verifyKeyFileBlob(uploadedKey, user.keyFile);
    if (!verified.ok) {
      return res
        .set("Content-Type", "text/html; charset=utf-8")
        .send(renderUnlockKeyFilePage(verified.error || "Invalid key file.", appUi, req.session));
    }
    setUserMasterKey(req.sessionID, verified.masterKey);
    req.session.keyFileRegistered = true;
    req.session.keyFileUnlocked = true;
    try {
      user.keyFile.lastUsedAt = new Date().toISOString();
      await db.insert(user);
    } catch (e) {
      console.warn("Failed to update keyFile.lastUsedAt:", e.message || e);
    }
    return res.redirect("/");
  } catch (err) {
    console.error("Unlock key file error:", err);
    return res
      .set("Content-Type", "text/html; charset=utf-8")
      .send(renderUnlockKeyFilePage("Could not verify key file.", appUi, req.session));
  }
});

app.get("/api/account/keyfile-status", requireAuth, (req, res) => {
  res.json({
    registered: !!(req.session && req.session.keyFileRegistered),
    unlocked: !!(req.session && req.session.keyFileUnlocked),
    enforceKeyLogin: !!(req.session && req.session.enforceKeyLogin),
    hasMasterKey: !!getUserMasterKey(req.sessionID),
  });
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

async function hydrateKeyFileSession(req, res, next) {
  if (!req.session || !req.session.user || !db) return next();
  if (typeof req.session.keyFileRegistered === "boolean") return next();
  try {
    const result = await db.find({
      selector: { type: "elenko_user", username: req.session.user },
      limit: 1,
    });
    const user = result.docs && result.docs[0];
    req.session.keyFileRegistered = userKeyFileRegistered(user);
    req.session.enforceKeyLogin = userEnforceKeyLogin(user);
    req.session.keyFileUnlocked = !!getUserMasterKey(req.sessionID);
  } catch (_) {}
  next();
}

app.use(hydrateKeyFileSession);

function buildKeyFileNoticeHtml(session) {
  if (!session || !session.keyFileRegistered || session.keyFileUnlocked) return "";
  return `<p class="keyfile-banner" style="background:#3d2e00;color:#f0c040;padding:0.75rem 1rem;border-radius:6px;margin:0 0 1rem;">Your key file is not loaded. <a href="/account/unlock-keyfile" style="color:#ffe066;">Provide key file</a> for encrypted database access (when enabled).</p>`;
}

app.get("/", async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "_rev", "name", "description", "createdAt", "encryption"],
      sort: [{ name: "asc" }],
    });
    const profiles = filterProfilesVisibleToUser(req, result.docs || []);
    const appUi = await getAppUiConfig();
    const role = (req.session && req.session.role) || "editor";
    const keyFileNotice = buildKeyFileNoticeHtml(req.session);
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderStartPage(profiles, role, appUi, keyFileNotice));
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
    invalidateAppUiConfigCache();
  } catch (e) {
    console.error("Failed to update app config with new password:", e);
  }
  syncTimersFromDbSoon("account-couch-password");
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

app.get("/application-properties", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderApplicationPropertiesPage(appUi, null));
  } catch (err) {
    console.error("Error loading application properties:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/application-properties", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const body = req.body || {};
    const mode = normalizeFlowLogDisplayMode(body.flowLogDisplayMode);
    const iana = typeof body.flowLogIana === "string" ? body.flowLogIana.trim() : "";
    const utcOff = parseBoundedInt(body.flowLogUtcOffsetMinutes, 0, -840, 840);
    const dockAdj = parseBoundedInt(body.flowLogDockerAdjustMinutes, 0, -10080, 10080);

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
      doc = { type: "elenko_app_config", theme: { ...DEFAULT_APP_THEME } };
    }
    doc.flowLogDisplayMode = mode;
    doc.flowLogIana = iana;
    doc.flowLogUtcOffsetMinutes = utcOff;
    doc.flowLogDockerAdjustMinutes = dockAdj;
    const ins = await configDb.insert(doc);
    invalidateAppUiConfigCache();
    res.json({ ok: true, id: ins.id, rev: ins.rev });
  } catch (err) {
    console.error("Error saving application properties:", err);
    res.status(500).json({ error: err.message });
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
    const encAccess = await resolveProfileEncryptionAccess(req, profileDoc);
    if (isProfilePersonalEncryptionEnabled(profileDoc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "json");
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

    profileDoc = await ensureProfileDbCode8(db, profileDoc);
    const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
    const profileFormIds = getProfileEntryFormIds(profileDoc);
    const defaultFormId = profileFormIds.length > 0 ? profileFormIds[0] : "";
    const importPolicy =
      typeof profileDoc.primaryKeyImportPolicy === "string" ? profileDoc.primaryKeyImportPolicy.trim() : "";
    const now = new Date().toISOString();
    let imported = 0;
    let overwritten = 0;
    let skippedDuplicates = 0;
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
        setEntryAuditOnCreate(record, req);
        record.sortKey = buildSortKey(record, sortKeyFields);
        try {
          applyPrimaryKeyToRecord(record, profileDoc);
        } catch (ePk) {
          const msg = ePk && ePk.message ? String(ePk.message) : String(ePk);
          if (errors.length < 50) {
            errors.push({ row: lineNo, message: msg });
          }
          continue;
        }
        const pkForLookup =
          encAccess.profileKey && record.primaryKey
            ? computePrimaryKeyToken(encAccess.profileKey, record.primaryKey)
            : record.primaryKey;
        if (pkForLookup) {
          const conflict = await findPrimaryKeyConflict(db, pkForLookup, "");
          if (conflict) {
            if (importPolicy === "overwrite") {
              if (conflict.profileId !== profileId) {
                if (errors.length < 50) {
                  errors.push({
                    row: lineNo,
                    message: "Primary key matches an entry in another profile; not overwritten.",
                  });
                }
                continue;
              }
              const updated = { ...conflict };
              if (encAccess.profileKey) {
                decryptRecordFieldsInPlace(updated, profileDoc, encAccess.profileKey, null);
              }
              for (const fn of fieldNames) {
                updated[fn] = record[fn];
              }
              updated.updatedAt = now;
              setEntryAuditOnUpdate(updated, req);
              updated.sortKey = buildSortKey(updated, sortKeyFields);
              try {
                applyPrimaryKeyToRecord(updated, profileDoc);
              } catch (e2) {
                const msg = e2 && e2.message ? String(e2.message) : String(e2);
                if (errors.length < 50) {
                  errors.push({ row: lineNo, message: msg });
                }
                continue;
              }
              if (encAccess.profileKey) {
                encryptRecordFieldsForStorage(updated, profileDoc, encAccess.profileKey, null);
              }
              await db.insert(updated);
              overwritten++;
            } else {
              skippedDuplicates++;
            }
            continue;
          }
        }
        if (encAccess.profileKey) {
          encryptRecordFieldsForStorage(record, profileDoc, encAccess.profileKey, null);
        }
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
      overwritten,
      skippedDuplicates,
      failed: errors.length,
      rowErrorSample: errors.slice(0, 3),
    });
    res.json({
      ok: true,
      imported,
      overwritten,
      skippedDuplicates,
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

app.get("/api/profiles/:id/export-data", requireAdmin, async (req, res) => {
  const profileId = req.params.id;
  try {
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
    const encAccess = await resolveProfileEncryptionAccess(req, profileDoc);
    if (isProfilePersonalEncryptionEnabled(profileDoc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "json");
    }
    const { fieldNames, docs } = await loadProfileRecordsForExport(db, profileDoc);
    if (fieldNames.length === 0) {
      return res.status(400).json({ error: "This profile has no field names defined." });
    }
    const exportDocs =
      encAccess.profileKey
        ? decryptRecordsForProfile(docs, profileDoc, encAccess.profileKey, null)
        : docs;
    const rows = [fieldNames.slice()];
    for (const docRow of exportDocs) {
      rows.push(fieldNames.map((fn) => (docRow[fn] != null ? String(docRow[fn]) : "")));
    }
    const csvText = "\uFEFF" + buildSemicolonCsvText(rows);
    const safeName = String(profileDoc.name || profileId)
      .replace(/[^\w\-]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 60) || "profile";
    const date = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="elenko-export-${safeName}-${date}.csv"`);
    console.log("[export-data] success", { profileId, rowCount: docs.length, fieldCount: fieldNames.length });
    res.send(csvText);
  } catch (err) {
    console.error("[export-data] error", { profileId, message: err && err.message });
    res.status(500).json({ error: err.message || "Export failed" });
  }
});

app.get("/api/profiles/:id/data-import-meta", requireAdmin, async (req, res) => {
  const profileId = req.params.id;
  try {
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
    const kinds = normalizeFieldKinds(fieldNames, profileDoc.fieldKinds);
    const fileFields = fieldNames.filter((_, i) => kinds[i] === "file");
    const pkSet = new Set(
      (Array.isArray(profileDoc.primaryKeyFields) ? profileDoc.primaryKeyFields : [])
        .filter((f) => typeof f === "string" && f.trim())
        .map((f) => f.trim())
    );
    const fileFieldsInPrimaryKey = fileFields.filter((f) => pkSet.has(f));
    const primaryKeyImportPolicy =
      typeof profileDoc.primaryKeyImportPolicy === "string" ? profileDoc.primaryKeyImportPolicy.trim() : "";
    res.json({ fileFields, fileFieldsInPrimaryKey, primaryKeyImportPolicy });
  } catch (err) {
    console.error("[data-import-meta] error", { profileId, message: err && err.message });
    res.status(500).json({ error: err.message || "Failed to load import metadata" });
  }
});

app.post(
  "/api/profiles/:id/import-pictures",
  requireAdmin,
  entryImageUpload.array("files", MAX_PICTURE_IMPORT_FILES),
  async (req, res) => {
    const profileId = req.params.id;
    try {
      const fieldName =
        req.body && typeof req.body.fieldName === "string" ? req.body.fieldName.trim() : "";
      const files = Array.isArray(req.files) ? req.files : [];
      if (!fieldName) {
        return res.status(400).json({ error: "fieldName is required (profile file field)." });
      }
      if (files.length === 0) {
        return res.status(400).json({ error: "Select at least one image file." });
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
      const encAccess = await resolveProfileEncryptionAccess(req, profileDoc);
      if (isProfilePersonalEncryptionEnabled(profileDoc) && !encAccess.ok) {
        return respondEncryptionAccessDenied(res, encAccess, "json");
      }
      if (!isProfileFileField(profileDoc, fieldName)) {
        return res.status(400).json({ error: "Choose a profile field whose type is File." });
      }
      profileDoc = await ensureProfileDbCode8(db, profileDoc);
      const formDoc = await loadDefaultEntryFormForProfile(db, profileDoc);
      const importPolicy =
        typeof profileDoc.primaryKeyImportPolicy === "string" ? profileDoc.primaryKeyImportPolicy.trim() : "";
      const now = new Date().toISOString();
      let imported = 0;
      let overwritten = 0;
      let skippedDuplicates = 0;
      const rowErrors = [];

      for (let fi = 0; fi < files.length; fi++) {
        const file = files[fi];
        const rowLabel = file.originalname != null ? String(file.originalname) : "file " + (fi + 1);
        try {
          const prep = await prepareImageAttachmentPayloadForProfileField(
            profileDoc,
            formDoc,
            fieldName,
            file.buffer,
            file.originalname,
            file.mimetype
          );
          if (!prep.ok) {
            if (rowErrors.length < 50) rowErrors.push({ row: rowLabel, message: prep.error });
            continue;
          }
          const { outBuffer, outMime, safeName } = prep;
          const attachBytes =
            encAccess.profileKey ? encryptAttachmentBuffer(encAccess.profileKey, outBuffer) : outBuffer;
          const attachMime =
            encAccess.profileKey ? "application/vnd.elenko.encrypted" : outMime;
          let record;
          let pdoc;
          try {
            const built = await buildInitialRecordForPictureImport(db, profileDoc, req, fieldName, safeName);
            record = built.record;
            pdoc = built.pdoc;
            profileDoc = pdoc;
          } catch (ePk) {
            if (rowErrors.length < 50) {
              rowErrors.push({ row: rowLabel, message: ePk.message || String(ePk) });
            }
            continue;
          }
          const pkForLookup =
            encAccess.profileKey && record.primaryKey
              ? computePrimaryKeyToken(encAccess.profileKey, record.primaryKey)
              : record.primaryKey;
          if (pkForLookup) {
            const conflict = await findPrimaryKeyConflict(db, pkForLookup, "");
            if (conflict) {
              if (importPolicy === "overwrite" && conflict.profileId === profileId) {
                try {
                  let updated = await db.get(conflict._id);
                  if (encAccess.profileKey) {
                    decryptRecordFieldsInPlace(updated, pdoc, encAccess.profileKey, formDoc);
                  }
                  const oldFile = updated[fieldName] != null ? String(updated[fieldName]).trim() : "";
                  if (oldFile && updated._attachments && updated._attachments[oldFile]) {
                    await db.attachment.destroy(conflict._id, oldFile, { rev: updated._rev });
                    updated = await db.get(conflict._id);
                  }
                  await db.attachment.insert(conflict._id, safeName, attachBytes, attachMime, {
                    rev: updated._rev,
                  });
                  updated = await db.get(conflict._id);
                  updated[fieldName] = safeName;
                  updated.updatedAt = now;
                  setEntryAuditOnUpdate(updated, req);
                  updated.sortKey = buildSortKey(
                    updated,
                    Array.isArray(pdoc.sortKeyFields) ? pdoc.sortKeyFields : []
                  );
                  applyPrimaryKeyToRecord(updated, pdoc);
                  const pkStored =
                    encAccess.profileKey && updated.primaryKey
                      ? computePrimaryKeyToken(encAccess.profileKey, updated.primaryKey)
                      : updated.primaryKey;
                  if (pkStored) {
                    const other = await findPrimaryKeyConflict(db, pkStored, updated._id);
                    if (other) {
                      if (rowErrors.length < 50) {
                        rowErrors.push({
                          row: rowLabel,
                          message: "After overwrite, primary key would duplicate another entry.",
                        });
                      }
                      continue;
                    }
                  }
                  if (encAccess.profileKey) {
                    encryptRecordFieldsForStorage(updated, pdoc, encAccess.profileKey, formDoc);
                  }
                  await db.insert(updated);
                  overwritten++;
                } catch (eOw) {
                  if (rowErrors.length < 50) {
                    rowErrors.push({ row: rowLabel, message: eOw.message || String(eOw) });
                  }
                }
              } else {
                skippedDuplicates++;
              }
              continue;
            }
          }
          if (encAccess.profileKey) {
            encryptRecordFieldsForStorage(record, pdoc, encAccess.profileKey, formDoc);
          }
          const ins = await db.insert(record);
          await db.attachment.insert(ins.id, safeName, attachBytes, attachMime, { rev: ins.rev });
          imported++;
        } catch (e) {
          if (rowErrors.length < 50) {
            rowErrors.push({ row: rowLabel, message: e.message || String(e) });
          }
        }
      }

      clearProfileListCache(profileId);
      res.json({
        ok: true,
        imported,
        overwritten,
        skippedDuplicates,
        failed: rowErrors.length,
        rowErrors,
      });
    } catch (err) {
      console.error("[import-pictures] error", { profileId, message: err && err.message });
      res.status(500).json({ error: err.message || "Import failed" });
    }
  }
);

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
    if (result.importedConfig > 0) syncTimersFromDbSoon("config-import");
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
    invalidateAppUiConfigCache();
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error saving app config:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/account/users/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  const created = req.query.created === "1";
  const keyfileToken = typeof req.query.keyfileToken === "string" ? req.query.keyfileToken.trim() : "";
  res
    .set("Content-Type", "text/html; charset=utf-8")
    .send(renderCreateUserPage(null, created, appUi, keyfileToken));
});

app.get("/account/users/keyfile-download", requireAdmin, (req, res) => {
  const token = typeof req.query.token === "string" ? req.query.token.trim() : "";
  const download = req.query.download === "1";
  const entry = download ? consumeKeyFileDownloadToken(token) : peekKeyFileDownloadToken(token);
  if (!entry) {
    return res.status(404).set("Content-Type", "text/html; charset=utf-8").send(renderErrorPage("Download link expired or invalid."));
  }
  if (download) {
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${entry.filename}"`);
    return res.send(entry.blob);
  }
  res
    .set("Content-Type", "text/html; charset=utf-8")
    .send(renderKeyFileDownloadPage(entry.filename, token));
});

app.post("/account/users/create", requireAdmin, async (req, res) => {
  const username = String((req.body && req.body.username) || "").trim();
  const password = (req.body && req.body.password) || "";
  const roleRaw = (req.body && req.body.role) || "editor";
  const role = roleRaw === "admin" || roleRaw === "reader" ? roleRaw : "editor";
  const generateKeyFile = !!(req.body && (req.body.generateKeyFile === "1" || req.body.generateKeyFile === "on" || req.body.generateKeyFile === true));
  const enforceKeyLogin = !!(req.body && (req.body.enforceKeyLogin === "1" || req.body.enforceKeyLogin === "on" || req.body.enforceKeyLogin === true));
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
    const userDoc = {
      type: "elenko_user",
      username,
      passwordHash: hash,
      salt,
      role,
      enforceKeyLogin,
    };
    let keyfileToken = "";
    if (generateKeyFile) {
      const masterKey = crypto.randomBytes(ELNK_MASTER_KEY_LEN);
      const built = buildKeyFileRegistrationFromMasterKey(masterKey);
      userDoc.keyFile = built.keyFile;
      keyfileToken = storeKeyFileDownloadToken(username, built.blob);
    }
    await db.insert(userDoc);
    if (keyfileToken) {
      return res.redirect(`/account/users/create?created=1&keyfileToken=${encodeURIComponent(keyfileToken)}`);
    }
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
      fields: ["_id", "_rev", "username", "role", "keyFile", "enforceKeyLogin"],
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
    if (req.body && req.body.enforceKeyLogin !== undefined) {
      doc.enforceKeyLogin = !!req.body.enforceKeyLogin;
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

app.post("/api/account/users/:id/generate-keyfile", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_user") {
      return res.status(404).json({ error: "User not found" });
    }
    if (userKeyFileRegistered(doc)) {
      return res.status(400).json({ error: "User already has a key file. Use regenerate instead." });
    }
    const masterKey = crypto.randomBytes(ELNK_MASTER_KEY_LEN);
    const built = buildKeyFileRegistrationFromMasterKey(masterKey);
    doc.keyFile = built.keyFile;
    await db.insert(doc);
    const token = storeKeyFileDownloadToken(doc.username, built.blob);
    res.json({
      ok: true,
      downloadUrl: `/account/users/keyfile-download?token=${encodeURIComponent(token)}`,
      filename: keyFileDownloadFilename(doc.username),
    });
  } catch (err) {
    console.error("Generate key file error:", err);
    res.status(500).json({ error: err.message || "Generate failed" });
  }
});

app.post("/api/account/users/:id/regenerate-keyfile", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_user") {
      return res.status(404).json({ error: "User not found" });
    }
    const masterKey = crypto.randomBytes(ELNK_MASTER_KEY_LEN);
    const built = buildKeyFileRegistrationFromMasterKey(masterKey);
    doc.keyFile = built.keyFile;
    await db.insert(doc);
    const token = storeKeyFileDownloadToken(doc.username, built.blob);
    res.json({
      ok: true,
      downloadUrl: `/account/users/keyfile-download?token=${encodeURIComponent(token)}`,
      filename: keyFileDownloadFilename(doc.username),
      warning: "Previous key file no longer works. Encrypted databases will need re-wrapping (future step).",
    });
  } catch (err) {
    console.error("Regenerate key file error:", err);
    res.status(500).json({ error: err.message || "Regenerate failed" });
  }
});

app.delete("/api/account/users/:id/keyfile", requireAdmin, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_user") {
      return res.status(404).json({ error: "User not found" });
    }
    if (!userKeyFileRegistered(doc)) {
      return res.status(400).json({ error: "User has no registered key file." });
    }
    delete doc.keyFile;
    await db.insert(doc);
    res.json({
      ok: true,
      message:
        "Key registration removed. Upload the previous elenko-<username>.key file if you need to restore access. Encrypted databases (future) remain locked until the correct key is registered again.",
    });
  } catch (err) {
    console.error("Remove key file error:", err);
    res.status(500).json({ error: err.message || "Remove failed" });
  }
});

app.post(
  "/api/account/users/:id/upload-keyfile",
  requireAdmin,
  keyFileUpload.single("keyFile"),
  async (req, res) => {
    try {
      const doc = await db.get(req.params.id);
      if (!doc || doc.type !== "elenko_user") {
        return res.status(404).json({ error: "User not found" });
      }
      const replacing = userKeyFileRegistered(doc);
      const file = req.file;
      if (!file || !file.buffer || file.buffer.length === 0) {
        return res.status(400).json({ error: "Choose a key file to upload." });
      }
      const nameCheck = validateKeyFileUploadFilename(file.originalname, doc.username);
      if (!nameCheck.ok) {
        return res.status(400).json({ error: nameCheck.error || "Invalid file name." });
      }
      let built;
      try {
        built = buildKeyFileRegistrationFromBlob(file.buffer);
      } catch (e) {
        return res.status(400).json({ error: e && e.message ? String(e.message) : "Invalid key file format." });
      }
      const verify = verifyKeyFileBlob(file.buffer, built.keyFile);
      if (!verify.ok) {
        return res.status(400).json({ error: verify.error || "Key file verification failed." });
      }
      doc.keyFile = built.keyFile;
      await db.insert(doc);
      res.json({
        ok: true,
        filename: nameCheck.filename,
        blobVersion: built.keyFile.blobVersion,
        replaced: replacing,
        message: replacing
          ? "Key file replaced from upload. The previous registration no longer works on this instance."
          : "Key file registered from upload. The same file can be used on other instances for this username.",
      });
    } catch (err) {
      console.error("Upload key file error:", err);
      res.status(500).json({ error: err.message || "Upload failed" });
    }
  }
);

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
      fields: ["_id", "_rev", "name", "description", "createdAt", "encryption"],
      sort: [{ name: "asc" }],
    });
    res.json({ profiles: filterProfilesVisibleToUser(req, result.docs || []) });
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
    let queries = [];
    if (configDb) {
      try {
        const result = await configDb.find({ selector: { type: "elenko_flow" }, fields: ["_id", "name"], sort: [{ name: "asc" }], limit: 500 });
        flows = result.docs || [];
      } catch (_) {}
      try {
        const result = await configDb.find({ selector: { type: "elenko_query" }, fields: ["_id", "name"], sort: [{ name: "asc" }], limit: 500 });
        queries = result.docs || [];
      } catch (_) {}
    }
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderCreateEntryFormPage(null, flows, queries, appUi));
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
      if (!flowId && target !== "log" && target !== "localDb" && target !== "api" && target !== "response") {
        return res.status(400).json({ error: "When using Single step, please select a Target (Log file, Send to Local Database, Call API, or Save as response) for each flow button." });
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
      linkedQuery: normalized.linkedQuery,
      entryNavForwardBackEnabled: normalized.entryNavForwardBackEnabled,
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
    let queries = [];
    if (configDb) {
      try {
        const result = await configDb.find({ selector: { type: "elenko_flow" }, fields: ["_id", "name"], sort: [{ name: "asc" }], limit: 500 });
        flows = result.docs || [];
      } catch (_) {}
      try {
        const result = await configDb.find({ selector: { type: "elenko_query" }, fields: ["_id", "name"], sort: [{ name: "asc" }], limit: 500 });
        queries = result.docs || [];
      } catch (_) {}
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditEntryFormPage(doc, null, flows, queries, appUi));
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
    const normalized = normalizeEntryFormDoc(req.body || {});
    const flowConfigsRaw = Array.isArray(req.body.flowConfigs) ? req.body.flowConfigs : [];
    for (let i = 0; i < flowConfigsRaw.length; i++) {
      const c = flowConfigsRaw[i];
      const flowId = (c && typeof c.flowId === "string") ? c.flowId.trim() : "";
      const target = (c && typeof c.target === "string") ? c.target.trim() : "";
      if (!flowId && target !== "log" && target !== "localDb" && target !== "api" && target !== "response") {
        return res.status(400).json({ error: "When using Single step, please select a Target (Log file, Send to Local Database, Call API, or Save as response) for each flow button." });
      }
    }
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
    doc.linkedQuery = normalized.linkedQuery;
    doc.entryNavForwardBackEnabled = normalized.entryNavForwardBackEnabled;
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

function pickQueryString(req, name) {
  const v = req.query && req.query[name];
  if (typeof v === "string") return v.trim();
  if (Array.isArray(v) && typeof v[0] === "string") return v[0].trim();
  return "";
}

app.get("/apis/create", requireAdmin, async (req, res) => {
  const appUi = await getAppUiConfig();
  const prefillKeyRef = pickQueryString(req, "apiKeyRef");
  const prefillUserRef = pickQueryString(req, "apiUserRef");
  const prefillPasswordRef = pickQueryString(req, "apiPasswordRef");
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderEditApiPage(null, null, req.originalUrl || "/apis/create", appUi, prefillKeyRef, prefillUserRef, prefillPasswordRef));
});

app.get("/apis/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const doc = await configDb.get(req.params.id);
    if (!doc || doc.type !== "elenko_api") {
      return res.status(404).send(renderErrorPage("API not found"));
    }
    const qKey = pickQueryString(req, "apiKeyRef");
    const qUser = pickQueryString(req, "apiUserRef");
    const qPass = pickQueryString(req, "apiPasswordRef");
    // After Create/Update API key, browser returns with ?apiKeyRef= / ?apiUserRef= / ?apiPasswordRef= — persist to CouchDB
    // (export strips refs; slug sync in the form is UI-only until Save unless we save here).
    if (qKey || qUser || qPass) {
      if (qKey) doc.apiKeyRef = qKey;
      if (qUser) doc.apiUserRef = qUser;
      if (qPass) doc.apiPasswordRef = qPass;
      await configDb.insert(doc);
      return res.redirect(303, "/apis/" + encodeURIComponent(req.params.id) + "/edit");
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditApiPage(doc, null, "/apis/" + encodeURIComponent(req.params.id) + "/edit", appUi, "", "", ""));
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
      apiAuthType: normalizeElenkoApiAuthType(body),
      apiKeyRef: typeof body.apiKeyRef === "string" ? body.apiKeyRef.trim() : "",
      apiUserRef: typeof body.apiUserRef === "string" ? body.apiUserRef.trim() : "",
      apiPasswordRef: typeof body.apiPasswordRef === "string" ? body.apiPasswordRef.trim() : "",
      responseTarget: body.responseTarget === "create" ? "create" : body.responseTarget === "forward" ? "forward" : "update",
      template: typeof body.template === "string" ? body.template.trim() : "",
      responseField: typeof body.responseField === "string" ? body.responseField.trim() : "",
      responseStart: typeof body.responseStart === "string" ? body.responseStart : "",
      responseEnd: typeof body.responseEnd === "string" ? body.responseEnd : "",
    };
    if (Object.prototype.hasOwnProperty.call(body, "getQueryFromEntry")) {
      doc.getQueryFromEntry = body.getQueryFromEntry === true;
    }
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
    doc.apiAuthType = normalizeElenkoApiAuthType(body);
    doc.apiKeyRef = typeof body.apiKeyRef === "string" ? body.apiKeyRef.trim() : "";
    doc.apiUserRef = typeof body.apiUserRef === "string" ? body.apiUserRef.trim() : "";
    doc.apiPasswordRef = typeof body.apiPasswordRef === "string" ? body.apiPasswordRef.trim() : "";
    doc.responseTarget = body.responseTarget === "create" ? "create" : body.responseTarget === "forward" ? "forward" : "update";
    doc.template = typeof body.template === "string" ? body.template.trim() : "";
    doc.responseField = typeof body.responseField === "string" ? body.responseField.trim() : "";
    doc.responseStart = typeof body.responseStart === "string" ? body.responseStart : "";
    doc.responseEnd = typeof body.responseEnd === "string" ? body.responseEnd : "";
    if (Object.prototype.hasOwnProperty.call(body, "getQueryFromEntry")) {
      doc.getQueryFromEntry = body.getQueryFromEntry === true;
    }
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

// —— Linked queries (Elenko Query config) ——

app.get("/api/queries", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const result = await configDb.find({
      selector: { type: "elenko_query" },
      fields: ["_id", "_rev", "name", "description", "baseProfileId", "queryProfileId"],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    res.json({ queries: result.docs || [] });
  } catch (err) {
    console.error("Error loading queries:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/queries", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    if (!db) return res.status(503).send(renderErrorPage("Database not available"));
    const result = await configDb.find({
      selector: { type: "elenko_query" },
      sort: [{ name: "asc" }],
      limit: 500,
    });
    const queries = result.docs || [];
    const profilesResult = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "name"],
      limit: 1000,
    });
    const profiles = profilesResult.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderQueriesListPage(queries, appUi, profiles));
  } catch (err) {
    console.error("Error loading queries:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/queries/create", requireAdmin, async (req, res) => {
  try {
    if (!db) return res.status(503).send(renderErrorPage("Database not available"));
    const profilesResult = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "name"],
      sort: [{ name: "asc" }],
      limit: 1000,
    });
    const profiles = profilesResult.docs || [];
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditQueryPage(null, null, appUi, profiles));
  } catch (err) {
    console.error("Error loading query create page:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/queries/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    if (!db) return res.status(503).send(renderErrorPage("Database not available"));
    const profilesResult = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "name"],
      sort: [{ name: "asc" }],
      limit: 1000,
    });
    const profiles = profilesResult.docs || [];
    const doc = await configDb.get(req.params.id);
    if (!doc || doc.type !== "elenko_query") {
      return res.status(404).send(renderErrorPage("Query not found"));
    }
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditQueryPage(doc, null, appUi, profiles));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Query not found"));
    console.error("Error loading query:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/queries", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    const baseProfileId = typeof body.baseProfileId === "string" ? body.baseProfileId.trim() : "";
    const baseKeyField = typeof body.baseKeyField === "string" ? body.baseKeyField.trim() : "";
    const queryProfileId = typeof body.queryProfileId === "string" ? body.queryProfileId.trim() : "";
    const queryKeyField = typeof body.queryKeyField === "string" ? body.queryKeyField.trim() : "";
    const sortField = typeof body.sortField === "string" ? body.sortField.trim() : "";
    const sortDirection = body.sortDirection === "desc" ? "desc" : "asc";
    const resultFieldsArr = Array.isArray(body.resultFields) ? body.resultFields : [];
    const resultFields = resultFieldsArr
      .map((f) => (typeof f === "string" ? f.trim() : ""))
      .filter((f) => !!f);
    if (!baseProfileId || !baseKeyField || !queryProfileId || !queryKeyField) {
      return res.status(400).json({ error: "Base/query profile and key fields are required." });
    }
    const doc = {
      type: "elenko_query",
      name,
      description: typeof body.description === "string" ? body.description.trim() : "",
      baseProfileId,
      baseKeyField,
      queryProfileId,
      queryKeyField,
      resultFields,
      sortField,
      sortDirection,
    };
    const saved = await configDb.insert(doc);
    res.status(201).json({ ok: true, id: saved.id, rev: saved.rev });
  } catch (err) {
    console.error("Error creating query:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/queries/:id", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const existing = await configDb.get(id);
    if (!existing || existing.type !== "elenko_query") {
      return res.status(404).json({ error: "Query not found" });
    }
    const body = req.body || {};
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) return res.status(400).json({ error: "Name is required." });
    existing.name = name;
    existing.description = typeof body.description === "string" ? body.description.trim() : "";
    existing.baseProfileId = typeof body.baseProfileId === "string" ? body.baseProfileId.trim() : "";
    existing.baseKeyField = typeof body.baseKeyField === "string" ? body.baseKeyField.trim() : "";
    existing.queryProfileId = typeof body.queryProfileId === "string" ? body.queryProfileId.trim() : "";
    existing.queryKeyField = typeof body.queryKeyField === "string" ? body.queryKeyField.trim() : "";
    const resultFieldsArr = Array.isArray(body.resultFields) ? body.resultFields : [];
    existing.resultFields = resultFieldsArr
      .map((f) => (typeof f === "string" ? f.trim() : ""))
      .filter((f) => !!f);
    existing.sortField = typeof body.sortField === "string" ? body.sortField.trim() : "";
    existing.sortDirection = body.sortDirection === "desc" ? "desc" : "asc";
    const saved = await configDb.insert(existing);
    res.json({ ok: true, id: saved.id, rev: saved.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Query not found" });
    console.error("Error updating query:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/queries/:id/delete", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const body = req.body || {};
    const rev = typeof body._rev === "string" ? body._rev : "";
    if (!rev) return res.status(400).json({ error: "Missing revision" });
    const existing = await configDb.get(id);
    if (!existing || existing.type !== "elenko_query") {
      return res.status(404).json({ error: "Query not found" });
    }
    await configDb.destroy(id, rev);
    res.json({ ok: true, redirect: "/queries" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Query not found" });
    console.error("Error deleting query:", err);
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
  let credentialField =
    typeof req.query.credentialField === "string" && req.query.credentialField.trim()
      ? req.query.credentialField.trim()
      : "apiKeyRef";
  if (!new Set(["apiKeyRef", "apiUserRef", "apiPasswordRef"]).has(credentialField)) credentialField = "apiKeyRef";
  res.send(renderEditApiKeyPage(null, null, req.query.returnTo, defaultName, appUi, defaultApiKeyDocId, credentialField));
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
    res.send(renderEditApiKeyPage(doc, null, req.query.returnTo, "", appUi, "", "apiKeyRef"));
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

async function loadFlowsAndProfilesForTimerForms() {
  let flows = [];
  let profiles = [];
  if (configDb) {
    try {
      const fr = await configDb.find({
        selector: { type: "elenko_flow" },
        fields: ["_id", "name"],
        sort: [{ name: "asc" }],
        limit: 500,
      });
      flows = fr.docs || [];
    } catch (_) {}
  }
  if (db) {
    try {
      const pr = await db.find({
        selector: { type: "elenko_profile" },
        fields: ["_id", "name"],
        sort: [{ name: "asc" }],
        limit: 500,
      });
      profiles = pr.docs || [];
    } catch (_) {}
  }
  return { flows, profiles };
}

// —— Timers (scheduled flows; timerWorker schedules, server runs pipeline) ——
app.get("/api/timers", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const result = await configDb.find({
      selector: { type: "elenko_timer" },
      fields: [
        "_id",
        "_rev",
        "name",
        "description",
        "flowId",
        "profileId",
        "entryId",
        "startDate",
        "startTime",
        "intervalKey",
        "active",
      ],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    res.json({ timers: result.docs || [] });
  } catch (err) {
    console.error("Error loading timers:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/timers", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const result = await configDb.find({
      selector: { type: "elenko_timer" },
      fields: [
        "_id",
        "_rev",
        "name",
        "description",
        "flowId",
        "profileId",
        "entryId",
        "startDate",
        "startTime",
        "intervalKey",
        "active",
      ],
      sort: [{ name: "asc" }],
      limit: 500,
    });
    const appUi = await getAppUiConfig();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderTimersListPage(result.docs || [], appUi));
  } catch (err) {
    console.error("Error loading timers:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/timers/create", requireAdmin, async (req, res) => {
  try {
    const appUi = await getAppUiConfig();
    const { flows, profiles } = await loadFlowsAndProfilesForTimerForms();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditTimerPage(null, null, appUi, flows, profiles));
  } catch (err) {
    console.error("Error loading timer create:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/timers/:id/edit", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).send(renderErrorPage("Config store not available"));
    const doc = await configDb.get(req.params.id);
    if (!doc || doc.type !== "elenko_timer") {
      return res.status(404).send(renderErrorPage("Timer not found"));
    }
    const appUi = await getAppUiConfig();
    const { flows, profiles } = await loadFlowsAndProfilesForTimerForms();
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditTimerPage(doc, null, appUi, flows, profiles));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Timer not found"));
    console.error("Error loading timer:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.post("/api/timers", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const fields = normalizeTimerCreateBody(req.body || {});
    if (!fields.name) return res.status(400).json({ error: "Name is required." });
    if (!fields.flowId) return res.status(400).json({ error: "Flow is required." });
    if (!fields.profileId) return res.status(400).json({ error: "Elenko database (profile) is required." });
    if (!Number.isFinite(parseTimerLocalDateTimeMs(fields.startDate, fields.startTime))) {
      return res.status(400).json({ error: "Invalid start date or time (use YYYY-MM-DD and HH:mm)." });
    }
    const doc = {
      type: "elenko_timer",
      name: fields.name,
      description: fields.description,
      flowId: fields.flowId,
      profileId: fields.profileId,
      entryId: fields.entryId,
      param: fields.param,
      startDate: fields.startDate,
      startTime: fields.startTime,
      intervalKey: fields.intervalKey,
      active: fields.active,
    };
    const result = await configDb.insert(doc);
    await syncTimersFromDb();
    sendFlowMessageTimerSaved("created", result.id, fields);
    res.status(201).json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    console.error("Error creating timer:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/timers/:id", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const existing = await configDb.get(id);
    if (!existing || existing.type !== "elenko_timer") {
      return res.status(404).json({ error: "Timer not found" });
    }
    const fields = normalizeTimerCreateBody(req.body || {});
    if (!fields.name) return res.status(400).json({ error: "Name is required." });
    if (!fields.flowId) return res.status(400).json({ error: "Flow is required." });
    if (!fields.profileId) return res.status(400).json({ error: "Elenko database (profile) is required." });
    if (!Number.isFinite(parseTimerLocalDateTimeMs(fields.startDate, fields.startTime))) {
      return res.status(400).json({ error: "Invalid start date or time (use YYYY-MM-DD and HH:mm)." });
    }
    existing.name = fields.name;
    existing.description = fields.description;
    existing.flowId = fields.flowId;
    existing.profileId = fields.profileId;
    existing.entryId = fields.entryId;
    existing.param = fields.param;
    existing.startDate = fields.startDate;
    existing.startTime = fields.startTime;
    existing.intervalKey = fields.intervalKey;
    existing.active = fields.active;
    const result = await configDb.insert(existing);
    await syncTimersFromDb();
    sendFlowMessageTimerSaved("updated", id, fields);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Timer not found" });
    console.error("Error updating timer:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/timers/:id/copy", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    let base = null;
    try {
      base = await configDb.get(id);
    } catch (e) {
      if (e.statusCode === 404) return res.status(404).json({ error: "Timer not found" });
      throw e;
    }
    if (!base || base.type !== "elenko_timer") {
      return res.status(404).json({ error: "Timer not found" });
    }
    const nameResult = await configDb.find({
      selector: { type: "elenko_timer" },
      fields: ["name"],
      limit: 5000,
    });
    const existing = new Set();
    for (const d of nameResult.docs || []) {
      if (d && typeof d.name === "string" && d.name.trim()) existing.add(d.name.trim());
    }
    const newName = makeUniqueTimerCopyName(base.name, existing);
    const newDoc = buildTimerDocFromSource(base, newName);
    const result = await configDb.insert(newDoc);
    await syncTimersFromDb();
    sendFlowMessageTimerSaved("copied", result.id, normalizeTimerCreateBody(newDoc));
    res.status(201).json({ ok: true, id: result.id, rev: result.rev, name: newName });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Timer not found" });
    console.error("Error copying timer:", err);
    res.status(500).json({ error: err.message || "Copy failed" });
  }
});

app.post("/api/timers/:id/delete", requireAdmin, async (req, res) => {
  try {
    if (!configDb) return res.status(503).json({ error: "Config store not available" });
    const id = req.params.id;
    const { _rev } = req.body || {};
    if (!_rev) return res.status(400).json({ error: "Missing _rev" });
    const doc = await configDb.get(id);
    if (!doc || doc.type !== "elenko_timer") {
      return res.status(404).json({ error: "Timer not found" });
    }
    if (doc._rev !== _rev) {
      return res.status(409).json({ error: "Timer was modified; refresh and try again" });
    }
    await configDb.destroy(id, _rev);
    await syncTimersFromDb();
    res.json({ ok: true, redirect: "/timers" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Timer not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict" });
    console.error("Error deleting timer:", err);
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
    const { name, description, fieldNames, fieldDefaultSources, fieldDisplay, fieldKinds, customCss, listFields: rawListFields, entriesPageSize } = req.body || {};
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
    const rawPageSize = Number(entriesPageSize);
    const pageSize =
      Number.isFinite(rawPageSize) && rawPageSize >= ENTRIES_PAGE_SIZE_MIN && rawPageSize <= ENTRIES_PAGE_SIZE_MAX
        ? Math.floor(rawPageSize)
        : ENTRIES_PAGE_SIZE;
    const doc = {
      type: "elenko_profile",
      name: name.trim(),
      description: description != null ? String(description).trim() : "",
      customCss: customCss != null ? String(customCss) : "",
      fieldNames: fields,
      fieldDefaultSources: normalizeFieldDefaultSources(fields, fieldDefaultSources),
      fieldDisplay: normalizeFieldDisplay(fields, fieldDisplay),
      fieldKinds: normalizeFieldKinds(fields, fieldKinds),
      listFields,
      entriesPageSize: pageSize,
      createdAt: new Date().toISOString(),
    };
    doc.dbCode8 = await assignDbCode8(db, doc.name, null);
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
      setEntryAuditOnCreate(entry, req);
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
    const keyFileUsers = await loadUsersWithRegisteredKeyFiles(db);
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditProfilePage(doc, forms, appUi, keyFileUsers));
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
      entriesPageSize,
      splitView,
      guardianFlowId,
      sortKeyFields: rawSortKeyFields,
      sortDirection,
      searchAccentFolding,
      primaryKeyFields: rawPrimaryKeyFields,
      primaryKeySegmentLengths: rawPrimaryKeySegmentLengths,
      primaryKeyImportPolicy: rawPrimaryKeyImportPolicy,
      encryption: rawEncryption,
    } = req.body || {};
    if (!_rev || !name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Name and _rev are required" });
    }
    const doc = await db.get(id);
    if (doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const prevDbCode8 = doc.dbCode8;
    const prevPk = JSON.stringify(doc.primaryKeyFields || []);
    const prevPkLen = JSON.stringify(doc.primaryKeySegmentLengths || []);
    const previousName = doc.name;
    const fields = Array.isArray(fieldNames)
      ? fieldNames.filter((f) => typeof f === "string" && f.trim()).map((f) => f.trim())
      : (Array.isArray(doc.fieldNames) ? doc.fieldNames : []);
    doc.name = name.trim();
    doc.description = description != null ? String(description).trim() : "";
    doc.customCss = customCss != null ? String(customCss) : "";
    doc.fieldNames = fields;
    doc.fieldDefaultSources = normalizeFieldDefaultSources(fields, req.body.fieldDefaultSources);
    doc.fieldDisplay = normalizeFieldDisplay(fields, req.body.fieldDisplay);
    doc.fieldKinds = normalizeFieldKinds(fields, req.body.fieldKinds);
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
    const rawPageSize = Number(entriesPageSize);
    doc.entriesPageSize =
      Number.isFinite(rawPageSize) && rawPageSize >= ENTRIES_PAGE_SIZE_MIN && rawPageSize <= ENTRIES_PAGE_SIZE_MAX
        ? Math.floor(rawPageSize)
        : ENTRIES_PAGE_SIZE;
    const splitCfg = splitView && typeof splitView === "object" ? splitView : {};
    doc.splitView = {
      enabled: !!(splitCfg.enabled === true || splitCfg.enabled === "true"),
      orientation: splitCfg.orientation === "horizontal" ? "horizontal" : "vertical",
    };
    const sortKeyFields = Array.isArray(rawSortKeyFields)
      ? rawSortKeyFields
          .filter((f) => typeof f === "string" && f.trim())
          .slice(0, SORT_KEY_FIELDS_MAX)
          .map((f) => f.trim())
          .filter((f) => fields.includes(f) || SORT_KEY_SPECIAL.includes(f))
      : [];
    doc.sortKeyFields = sortKeyFields;
    doc.sortDirection = sortDirection === "desc" ? "desc" : "asc";
    doc.searchAccentFolding =
      searchAccentFolding === true || searchAccentFolding === "true" ? true : false;
    const pkNorm = normalizePrimaryKeyFieldsFromBody(fields, rawPrimaryKeyFields, rawPrimaryKeySegmentLengths);
    doc.primaryKeyFields = pkNorm.primaryKeyFields;
    doc.primaryKeySegmentLengths = pkNorm.primaryKeySegmentLengths;
    const pip =
      typeof rawPrimaryKeyImportPolicy === "string" && rawPrimaryKeyImportPolicy.trim()
        ? rawPrimaryKeyImportPolicy.trim()
        : "";
    doc.primaryKeyImportPolicy = pip;
    const prevEncEnabled = isProfilePersonalEncryptionEnabled(doc);
    const prevEncOwner = getProfileEncryptionOwnerUsername(doc);
    const encBody = rawEncryption && typeof rawEncryption === "object" ? rawEncryption : {};
    const wantEncEnabled = encBody.enabled === true || encBody.enabled === "true";
    const wantEncOwner =
      typeof encBody.ownerUsername === "string" && encBody.ownerUsername.trim()
        ? encBody.ownerUsername.trim()
        : "";
    if (prevEncEnabled && wantEncEnabled && prevEncOwner && wantEncOwner && wantEncOwner !== prevEncOwner) {
      return res.status(400).json({ error: "Change the encryption owner only after disabling encryption." });
    }
    let migrationProfileKey = null;
    if (wantEncEnabled) {
      if (!wantEncOwner) {
        return res.status(400).json({ error: "Select an encryption owner when enabling personal-use encryption." });
      }
      if (!(await userHasRegisteredKeyFile(db, wantEncOwner))) {
        return res.status(400).json({
          error: `User "${wantEncOwner}" has no registered key file. Register a key file for that user first.`,
        });
      }
      doc.encryption = {
        mode: "personal",
        enabled: true,
        ownerUsername: wantEncOwner,
        version: 1,
      };
      if (!prevEncEnabled) {
        const encAccess = await resolveProfileEncryptionAccess(req, doc);
        if (encAccess.ok && encAccess.profileKey) {
          migrationProfileKey = encAccess.profileKey;
        }
      }
    } else {
      doc.encryption = {
        mode: "personal",
        enabled: false,
        ownerUsername: wantEncOwner || prevEncOwner || "",
        version: 1,
      };
    }
    const nameNormChanged =
      normalizeProfileNameForDbCode(previousName) !== normalizeProfileNameForDbCode(doc.name);
    if (!doc.dbCode8 || nameNormChanged) {
      doc.dbCode8 = await assignDbCode8(db, doc.name, doc._id);
    }
    const result = await db.insert(doc);
    const latest = await db.get(id);
    const encNewlyEnabled = !prevEncEnabled && isProfilePersonalEncryptionEnabled(latest);
    if (encNewlyEnabled && migrationProfileKey) {
      await migrateProfileRecordsToEncryption(db, latest, migrationProfileKey);
    } else if (isProfilePersonalEncryptionEnabled(latest)) {
      const encAccess = await resolveProfileEncryptionAccess(req, latest);
      if (encAccess.ok && encAccess.profileKey && (await profileHasUnencryptedEntries(db, id))) {
        await migrateProfileRecordsToEncryption(db, latest, encAccess.profileKey);
      }
    }
    // primaryKeyImportPolicy affects CSV and picture bulk import; it does not change how keys are computed on entries.
    const pkChanged =
      prevDbCode8 !== latest.dbCode8 ||
      prevPk !== JSON.stringify(latest.primaryKeyFields || []) ||
      prevPkLen !== JSON.stringify(latest.primaryKeySegmentLengths || []);
    if (pkChanged) {
      const profileAfter = await db.get(id);
      if (isProfilePersonalEncryptionEnabled(profileAfter)) {
        const encAccess = await resolveProfileEncryptionAccess(req, profileAfter);
        if (encAccess.ok && encAccess.profileKey) {
          await recomputeEncryptedPrimaryKeysForProfile(db, profileAfter, encAccess.profileKey);
        }
      } else {
        await recomputePrimaryKeysForProfileRecords(db, profileAfter);
      }
    }
    clearProfileListCache(id);
    res.json({
      ok: true,
      id: result.id,
      rev: result.rev,
      encryptionMigrationPending: encNewlyEnabled && !migrationProfileKey,
    });
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
    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    if (isProfilePersonalEncryptionEnabled(doc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "json");
    }
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    const result = await db.find({
      selector: { type: "elenko_record", profileId: id },
      limit: 50000,
    });
    const docs = result.docs || [];
    const now = new Date().toISOString();
    const rebuildAuditUser = getSessionUsername(req);
    let updated = 0;
    for (const rec of docs) {
      if (!rec.createdAt) rec.createdAt = now;
      rec.updatedAt = now;
      if (rebuildAuditUser) rec.updatedBy = rebuildAuditUser;
      if (encAccess.profileKey && rec.encrypted === true) {
        decryptRecordFieldsInPlace(rec, doc, encAccess.profileKey, null);
      }
      rec.sortKey = buildSortKey(rec, sortKeyFields);
      try {
        applyPrimaryKeyToRecord(rec, doc);
      } catch (_) {
        delete rec.primaryKey;
      }
      if (encAccess.profileKey) {
        encryptRecordFieldsForStorage(rec, doc, encAccess.profileKey, null);
      }
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
    const reassignAuditUser = getSessionUsername(req);
    let reassigned = 0;
    for (const rec of docs) {
      rec.profileId = id;
      if (!rec.createdAt) rec.createdAt = now;
      rec.updatedAt = now;
      if (reassignAuditUser) rec.updatedBy = reassignAuditUser;
      rec.sortKey = buildSortKey(rec, sortKeyFields);
      try {
        applyPrimaryKeyToRecord(rec, doc);
      } catch (_) {
        delete rec.primaryKey;
      }
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
    const out = await insertNewEntryDocument(db, doc, req, {}, { discardOnCancel: true });
    if (!out.ok) {
      return res.status(out.status).send(renderErrorPage(out.error));
    }
    res.redirect(
      302,
      "/profile/" + encodeURIComponent(doc._id) + "/entry/" + encodeURIComponent(out.id) + "/edit"
    );
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Profile not found"));
    console.error("Error creating draft entry:", err);
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
    const out = await insertNewEntryDocument(db, doc, req, req.body || {});
    if (!out.ok) {
      return res.status(out.status).json({ error: out.error });
    }
    res.status(201).json({ ok: true, id: out.id, rev: out.rev });
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
      ? (flowConfig.target === "api" || flowConfig.target === "localDb" || flowConfig.target === "response" || flowConfig.target === "log" ? flowConfig.target : "log")
      : (formDoc && (formDoc.flowTarget === "api" || formDoc.flowTarget === "localDb" || formDoc.flowTarget === "response" || formDoc.flowTarget === "log") ? formDoc.flowTarget : "log");
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
            dataset: { ...record },
            param: flowButtonParam,
            req,
          };
          const draftEdits = req.body && req.body.draftRepeatEdits;
          if (draftEdits && typeof draftEdits === "object" && !Array.isArray(draftEdits)) {
            mergeDraftRepeatEditsIntoDataset(context, doc, draftEdits);
          }
          await runPipeline(context, flowDoc);
          return res.json({
            ok: true,
            reloadEntry: !!context.reloadEntry,
            refreshTimedOut: !!context.refreshTimedOut,
          });
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
      // Prevent accidental create/update/response steps from persisting a helper document.
      suppressPipelineCreate: true,
      suppressPipelineEntryWrites: true,
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
    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    if (isProfilePersonalEncryptionEnabled(doc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "html");
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
    if (encAccess.profileKey) {
      decryptRecordFieldsInPlace(record, doc, encAccess.profileKey, formDoc);
    }
    const role = (req.session && req.session.role) || "editor";
    const returnQuery = { q: req.query.q, page: req.query.page, split: req.query.split };
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(await renderViewEntryPage(doc, record, role, formDoc, returnQuery));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Entry not found"));
    console.error("Error loading entry:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/api/profile/:id/entry/:entryId/linked-query", async (req, res) => {
  try {
    const profileId = req.params.id;
    const entryId = req.params.entryId;
    const doc = await db.get(profileId);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    if (isProfilePersonalEncryptionEnabled(doc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "json");
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
      return res.status(404).json({ error: "Entry not found" });
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
      } catch (_) {}
    }
    if (encAccess.profileKey) {
      decryptRecordFieldsInPlace(record, doc, encAccess.profileKey, formDoc);
    }
    const layout = formDoc && (formDoc.layout === "grid" || formDoc.layout === "stack") ? formDoc.layout : "table";
    const html = await buildLinkedQueryHtmlForEntry(doc, record, formDoc, layout, { forceLoad: true });
    return res.json({ ok: true, html: html || "" });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Not found" });
    console.error("Load linked query error:", err);
    return res.status(500).json({ error: err.message || "Load failed" });
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
    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    if (isProfilePersonalEncryptionEnabled(doc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "html");
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
    if (!formDoc && profileFormIds.length > 0) {
      for (const fid of profileFormIds) {
        const t = typeof fid === "string" ? fid.trim() : "";
        if (!t) continue;
        try {
          const loaded = await db.get(t);
          if (loaded && loaded.type === "elenko_entry_form") {
            formDoc = loaded;
            break;
          }
        } catch (_) {}
      }
    }
    if (encAccess.profileKey) {
      decryptRecordFieldsInPlace(record, doc, encAccess.profileKey, formDoc);
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
    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    if (isProfilePersonalEncryptionEnabled(doc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "json");
    }
    let record = await db.get(entryId);
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
    const attachmentBackedFields = getAttachmentBackedFieldNames(doc, formDoc);
    for (const fn of attachmentBackedFields) {
      const newVal = values[fn] != null ? String(values[fn]).trim() : "";
      const oldVal = record[fn] != null ? String(record[fn]).trim() : "";
      if (newVal === "" && oldVal && record._attachments && record._attachments[oldVal]) {
        try {
          await db.attachment.destroy(entryId, oldVal, { rev: record._rev });
          record = await db.get(entryId);
        } catch (e) {
          if (e.statusCode !== 404) throw e;
          record = await db.get(entryId);
        }
      }
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
    setEntryAuditOnUpdate(record, req);
    let profileDoc = doc;
    profileDoc = await ensureProfileDbCode8(db, profileDoc);
    const sortKeyFields = Array.isArray(profileDoc.sortKeyFields) ? profileDoc.sortKeyFields : [];
    record.sortKey = buildSortKey(record, sortKeyFields);
    try {
      applyPrimaryKeyToRecord(record, profileDoc);
    } catch (e) {
      return res.status(400).json({ error: e.message || "Primary key could not be computed." });
    }
    const pkForLookup =
      encAccess.profileKey && record.primaryKey
        ? computePrimaryKeyToken(encAccess.profileKey, record.primaryKey)
        : record.primaryKey;
    if (pkForLookup) {
      const conflict = await findPrimaryKeyConflict(db, pkForLookup, entryId);
      if (conflict) {
        return res.status(409).json({ error: "Duplicate primary key: another entry already uses this composite key." });
      }
    }
    if (encAccess.profileKey) {
      encryptRecordFieldsForStorage(record, profileDoc, encAccess.profileKey, formDoc);
    }
    if (Object.prototype.hasOwnProperty.call(record, ELENKO_DISCARD_ON_CANCEL)) {
      delete record[ELENKO_DISCARD_ON_CANCEL];
    }
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

app.post("/api/profiles/:id/entries/:entryId/abandon-draft", requireEditor, async (req, res) => {
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
    if (!record[ELENKO_DISCARD_ON_CANCEL]) {
      return res.status(400).json({ error: "This entry is not a disposable new draft." });
    }
    await db.destroy(entryId, record._rev);
    clearProfileListCache(profileId);
    const returnParts = [];
    if (req.query.page) returnParts.push("page=" + encodeURIComponent(String(req.query.page)));
    if (req.query.q) returnParts.push("q=" + encodeURIComponent(String(req.query.q)));
    const returnQueryStr = returnParts.length > 0 ? "?" + returnParts.join("&") : "";
    const redirect = "/profile/" + encodeURIComponent(profileId) + returnQueryStr;
    res.json({ ok: true, redirect });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry not found" });
    console.error("Error abandoning draft entry:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/profiles/:profileId/entries/:entryId/attachments",
  requireEditor,
  entryImageUpload.single("file"),
  async (req, res) => {
    try {
      const profileId = req.params.profileId;
      const entryId = req.params.entryId;
      const fieldName =
        req.body && typeof req.body.fieldName === "string" ? req.body.fieldName.trim() : "";
      if (!fieldName) return res.status(400).json({ error: "fieldName is required." });
      if (!req.file || !req.file.buffer) {
        return res.status(400).json({ error: "file is required (multipart field name: file)." });
      }

      const profileDoc = await db.get(profileId);
      if (!profileDoc || profileDoc.type !== "elenko_profile") {
        return res.status(404).json({ error: "Profile not found" });
      }
      const encAccess = await resolveProfileEncryptionAccess(req, profileDoc);
      if (isProfilePersonalEncryptionEnabled(profileDoc) && !encAccess.ok) {
        return respondEncryptionAccessDenied(res, encAccess, "json");
      }
      const profileFieldNames = Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : [];
      if (!profileFieldNames.includes(fieldName)) {
        return res.status(400).json({ error: "Unknown profile field: " + fieldName });
      }

      let record = await db.get(entryId);
      if (!record || record.type !== "elenko_record" || record.profileId !== profileId) {
        return res.status(404).json({ error: "Entry not found" });
      }

      let formDoc = null;
      const profileFormIds = getProfileEntryFormIds(profileDoc);
      const formId =
        record.entryFormId && typeof record.entryFormId === "string" && record.entryFormId.trim()
          ? record.entryFormId.trim()
          : profileFormIds[0] || "";
      if (formId) {
        try {
          const loaded = await db.get(formId);
          if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
        } catch (_) {}
      }
      const formImageField = getImageFieldNamesFromFormLayout(formDoc).has(fieldName);
      const profileFileField = isProfileFileField(profileDoc, fieldName);
      if (!formImageField && !profileFileField) {
        return res.status(400).json({
          error:
            "Field is not configured for file attachments. Set the profile field to “file”, or use an Image field on the Single Entry form.",
        });
      }

      let mime =
        req.file.mimetype && String(req.file.mimetype).split(";")[0]
          ? String(req.file.mimetype).split(";")[0].trim().toLowerCase()
          : "";

      const treatAsImage = formImageField || (profileFileField && ALLOWED_ENTRY_IMAGE_MIMES.has(mime));
      let outBuffer;
      let outMime;
      let baseName;
      let storedExt;

      if (treatAsImage) {
        if (!ALLOWED_ENTRY_IMAGE_MIMES.has(mime)) {
          return res.status(400).json({ error: "Unsupported image type. Use JPEG, PNG, WebP, or GIF." });
        }
        let meta;
        try {
          meta = await sharp(req.file.buffer, { failOn: "truncated" }).metadata();
          if (!meta.width || !meta.height) {
            return res.status(400).json({ error: "Invalid image file." });
          }
        } catch (_) {
          return res.status(400).json({ error: "Invalid image file." });
        }
        const layoutItem = getFieldLayoutItemForFieldName(formDoc, fieldName);
        const layoutWidthStr =
          layoutItem && typeof layoutItem.width === "string" && layoutItem.width.trim()
            ? layoutItem.width.trim()
            : "";
        const uploadMaxEdge = uploadMaxEdgeFromFieldLayoutWidth(layoutWidthStr || undefined);
        const exceedsLayout = meta.width > uploadMaxEdge || meta.height > uploadMaxEdge;
        outBuffer = req.file.buffer;
        outMime = mime;
        if (exceedsLayout) {
          try {
            outBuffer = await sharp(req.file.buffer)
              .rotate()
              .resize(uploadMaxEdge, uploadMaxEdge, { fit: "inside", withoutEnlargement: true })
              .jpeg({ quality: 85, mozjpeg: true })
              .toBuffer();
            outMime = "image/jpeg";
          } catch (e) {
            console.warn("Entry image upload resize failed:", e && e.message);
            return res.status(400).json({ error: "Could not process image." });
          }
        }
        baseName = normalizeEntryAttachmentFilename(req.file.originalname);
        if (!baseName) baseName = "image";
        if (exceedsLayout) {
          const stem = baseName.includes(".") ? baseName.slice(0, baseName.lastIndexOf(".")) : baseName;
          baseName = stem + ".jpg";
        } else {
          const extFromOrig = entryImageMimeToExt(mime);
          if (extFromOrig && !baseName.toLowerCase().endsWith(extFromOrig)) {
            baseName += extFromOrig;
          }
        }
        storedExt = entryImageMimeToExt(outMime);
      } else {
        if (!ALLOWED_PROFILE_FILE_ATTACHMENT_MIMES.has(mime)) {
          return res.status(400).json({
            error:
              "Unsupported file type for a profile “file” field. Use an image (JPEG, PNG, WebP, GIF), PDF, or plain text.",
          });
        }
        outBuffer = req.file.buffer;
        outMime = mime;
        baseName = normalizeEntryAttachmentFilename(req.file.originalname);
        if (!baseName) baseName = "file";
        const extFromMime = attachmentMimeToExt(mime);
        if (extFromMime && !baseName.toLowerCase().endsWith(extFromMime)) {
          baseName += extFromMime;
        }
        storedExt = attachmentMimeToExt(outMime);
      }
      let safeName = baseName;
      let counter = 1;
      while (record._attachments && record._attachments[safeName]) {
        const curField = record[fieldName] != null ? String(record[fieldName]).trim() : "";
        if (curField === safeName) break;
        const stem = baseName.includes(".") ? baseName.slice(0, baseName.lastIndexOf(".")) : baseName;
        const extPart = baseName.includes(".") ? baseName.slice(baseName.lastIndexOf(".")) : storedExt || "";
        safeName = stem + "_" + counter + extPart;
        counter++;
        if (counter > 500) return res.status(400).json({ error: "Could not allocate attachment name." });
      }

      const oldName = record[fieldName] != null ? String(record[fieldName]).trim() : "";
      if (oldName && oldName !== safeName && record._attachments && record._attachments[oldName]) {
        try {
          await db.attachment.destroy(entryId, oldName, { rev: record._rev });
          record = await db.get(entryId);
        } catch (e) {
          if (e.statusCode !== 404) throw e;
          record = await db.get(entryId);
        }
      }

      const attachBytes =
        encAccess.profileKey ? encryptAttachmentBuffer(encAccess.profileKey, outBuffer) : outBuffer;
      const attachMime =
        encAccess.profileKey ? "application/vnd.elenko.encrypted" : outMime;
      await db.attachment.insert(entryId, safeName, attachBytes, attachMime, { rev: record._rev });
      record = await db.get(entryId);
      record[fieldName] = safeName;
      record.updatedAt = new Date().toISOString();
      setEntryAuditOnUpdate(record, req);
      let pdoc = profileDoc;
      pdoc = await ensureProfileDbCode8(db, pdoc);
      const sortKeyFields = Array.isArray(pdoc.sortKeyFields) ? pdoc.sortKeyFields : [];
      if (encAccess.profileKey) {
        decryptRecordFieldsInPlace(record, pdoc, encAccess.profileKey, formDoc);
      }
      record.sortKey = buildSortKey(record, sortKeyFields);
      try {
        applyPrimaryKeyToRecord(record, pdoc);
      } catch (e) {
        return res.status(400).json({ error: e.message || "Primary key could not be computed." });
      }
      const pkForLookup =
        encAccess.profileKey && record.primaryKey
          ? computePrimaryKeyToken(encAccess.profileKey, record.primaryKey)
          : record.primaryKey;
      if (pkForLookup) {
        const conflict = await findPrimaryKeyConflict(db, pkForLookup, entryId);
        if (conflict) {
          return res.status(409).json({ error: "Duplicate primary key after upload." });
        }
      }
      if (encAccess.profileKey) {
        encryptRecordFieldsForStorage(record, pdoc, encAccess.profileKey, formDoc);
      }
      const ins = await db.insert(record);
      clearProfileListCache(profileId);
      res.json({ ok: true, filename: safeName, rev: ins.rev });
    } catch (err) {
      if (err?.statusCode === 404) return res.status(404).json({ error: "Not found" });
      if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict; refresh and try again" });
      console.error("Entry image upload error:", err);
      res.status(500).json({ error: err.message || "Upload failed" });
    }
  }
);

app.get("/api/profiles/:profileId/entries/:entryId/attachments/:filename", requireAuth, async (req, res) => {
  try {
    const profileId = req.params.profileId;
    const entryId = req.params.entryId;
    let filename = req.params.filename != null ? String(req.params.filename) : "";
    try {
      filename = decodeURIComponent(filename);
    } catch (_) {}
    filename = normalizeEntryAttachmentFilename(filename);
    if (!filename) return res.status(400).end();

    const profileDoc = await db.get(profileId);
    if (!profileDoc || profileDoc.type !== "elenko_profile") return res.status(404).end();
    const encAccess = await resolveProfileEncryptionAccess(req, profileDoc);
    if (isProfilePersonalEncryptionEnabled(profileDoc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "empty");
    }
    const record = await db.get(entryId);
    if (!record || record.type !== "elenko_record" || record.profileId !== profileId) return res.status(404).end();

    let referenced = false;
    for (const fn of Array.isArray(profileDoc.fieldNames) ? profileDoc.fieldNames : []) {
      if (String(record[fn] != null ? record[fn] : "").trim() === filename) {
        referenced = true;
        break;
      }
    }
    if (!referenced) return res.status(404).end();
    if (!record._attachments || !record._attachments[filename]) return res.status(404).end();

    const stub = record._attachments[filename];
    const contentType = stub.content_type || "application/octet-stream";
    const maxRaw = Number(req.query.max);
    const wantMax = Number.isFinite(maxRaw) && maxRaw > 0;
    const maxEdge = wantMax ? Math.min(Math.floor(maxRaw), MAX_IMAGE_DISPLAY_EDGE) : 0;

    let buf = await db.attachment.get(entryId, filename);
    const wasEncryptedAttachment =
      encAccess.profileKey &&
      String(contentType).toLowerCase() === "application/vnd.elenko.encrypted";
    if (encAccess.profileKey) {
      buf = decryptAttachmentBuffer(encAccess.profileKey, buf);
    }

    let effectiveCt = contentType;
    if (wasEncryptedAttachment) {
      try {
        const meta = await sharp(buf, { failOn: "truncated" }).metadata();
        if (meta && meta.format) {
          effectiveCt = meta.format === "jpeg" ? "image/jpeg" : `image/${meta.format}`;
        } else {
          effectiveCt = "application/octet-stream";
        }
      } catch (_) {
        effectiveCt = "application/octet-stream";
      }
    }
    const isImageCt = String(effectiveCt).toLowerCase().startsWith("image/");
    if (maxEdge > 0 && isImageCt) {
      try {
        const out = await sharp(buf)
          .rotate()
          .resize(maxEdge, maxEdge, { fit: "inside", withoutEnlargement: true })
          .jpeg({ quality: 85, mozjpeg: true })
          .toBuffer();
        res.set("Cache-Control", "private, max-age=3600");
        res.type("image/jpeg");
        res.send(out);
        return;
      } catch (e) {
        console.warn("Entry image resize failed, sending original:", e && e.message);
      }
    }
    /** @type {string} */
    const ct = effectiveCt;
    res.set("Cache-Control", "private, max-age=86400");
    res.type(ct);
    res.send(buf);
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).end();
    console.error("Entry attachment get error:", err);
    res.status(500).end();
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
    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    if (isProfilePersonalEncryptionEnabled(doc) && !encAccess.ok) {
      return respondEncryptionAccessDenied(res, encAccess, "json");
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
    let created = await db.get(result.id);
    created = await ensureProfileDbCode8(db, created);
    res.status(201).json({ ok: true, id: result.id, rev: created._rev, name: newName });
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
    if (!canUserSeePersonalEncryptedProfile(req, doc)) {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    const profileId = doc._id;
    if (req.query.clearSearch) {
      clearSearchListCache(profileId);
      const profileBase = "/profile/" + encodeURIComponent(profileId);
      return res.redirect(profileBase);
    }
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const profileEntriesPageSizeRaw = Number(doc.entriesPageSize);
    const profileEntriesPageSize =
      Number.isFinite(profileEntriesPageSizeRaw) &&
      profileEntriesPageSizeRaw >= ENTRIES_PAGE_SIZE_MIN &&
      profileEntriesPageSizeRaw <= ENTRIES_PAGE_SIZE_MAX
        ? Math.floor(profileEntriesPageSizeRaw)
        : ENTRIES_PAGE_SIZE;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const searchQuery = (req.query.q || "").trim();
    const useAccentFolding = isProfileSearchAccentFoldingEnabled(doc);
    const normalizedSearch =
      searchQuery && useAccentFolding ? normalizeForSearch(searchQuery) : "";
    const skip = (page - 1) * profileEntriesPageSize;

    const encAccess = await resolveProfileEncryptionAccess(req, doc);
    const profileEncrypted = isProfilePersonalEncryptionEnabled(doc);
    if (profileEncrypted && !encAccess.ok) {
      const role = (req.session && req.session.role) || "editor";
      res.set("Content-Type", "text/html; charset=utf-8");
      res.send(
        renderElenkoDatabasePage(doc, [], role, {
          page: 1,
          totalPages: 0,
          hasNext: false,
          hasPrev: false,
          searchQuery,
          encryptionLock: encAccess,
        })
      );
      return;
    }

    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    const sortDirection = doc.sortDirection === "desc" ? "desc" : "asc";
    if (profileEncrypted && encAccess.profileKey) {
      const encList = await loadEncryptedProfileEntryList(db, doc, encAccess.profileKey, {
        page,
        profileEntriesPageSize,
        searchQuery,
        useAccentFolding,
        normalizedSearch,
        fieldNames,
        sortKeyFields,
        sortDirection,
      });
      const role = (req.session && req.session.role) || "editor";
      res.set("Content-Type", "text/html; charset=utf-8");
      res.send(
        renderElenkoDatabasePage(doc, encList.records, role, {
          page,
          totalPages: encList.pagination.totalPages,
          hasNext: encList.pagination.hasNext,
          hasPrev: encList.pagination.hasPrev,
          searchQuery,
          encryptionEnabled: true,
          encryptionOwner: encAccess.owner,
        })
      );
      return;
    }

    const selector = buildProfileEntrySearchSelector(profileId, fieldNames, searchQuery, useAccentFolding);

    const useSortKey = sortKeyFields.length > 0;
    // Fetch only one utility field used for row icon decoration.
    // It is not rendered as a visible table column.
    const fieldsForFind = fieldNames.length ? ["_id", "_rev", "sortKey", "isResponse", ...fieldNames] : ["_id", "_rev", "sortKey", "isResponse"];
    const SORT_FETCH_LIMIT = 50000;

    let totalPages = null;
    let allDocs = [];
    if (!searchQuery) {
      try {
        const countResult = await db.view("records", "countByProfile", { key: profileId });
        const totalEntries = countResult.rows && countResult.rows[0] ? countResult.rows[0].value : 0;
        totalPages = Math.max(1, Math.ceil(totalEntries / profileEntriesPageSize));
      } catch (e) {
        totalPages = 1;
      }
    }

    if (useSortKey && !searchQuery) {
      const cacheKey = profileId;
      const sortConfig = JSON.stringify({ sortKeyFields, sortDirection });
      const cached = profileListCache.get(cacheKey);
      if (cached && cached.sortConfig === sortConfig && Array.isArray(cached.docs)) {
        totalPages = Math.max(1, Math.ceil(cached.docs.length / profileEntriesPageSize));
        allDocs = cached.docs.slice(skip, skip + profileEntriesPageSize + 1);
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
        totalPages = Math.max(1, Math.ceil(fullDocs.length / profileEntriesPageSize));
        allDocs = fullDocs.slice(skip, skip + profileEntriesPageSize + 1);
      }
    } else if (useSortKey && searchQuery) {
      // Search with sort-key profile: use cached sorted docs or fetch, sort, cache, then paginate
      const sortConfig = JSON.stringify({ sortKeyFields, sortDirection });
      const acfKey = useAccentFolding ? "acf1" : "acf0";
      const searchCacheKey =
        profileId + SEARCH_CACHE_KEY_SEP + sortConfig + SEARCH_CACHE_KEY_SEP + acfKey + SEARCH_CACHE_KEY_SEP + searchQuery;
      const cached = searchListCache.get(searchCacheKey);
      if (cached && Array.isArray(cached.docs)) {
        totalPages = Math.max(1, Math.ceil(cached.docs.length / profileEntriesPageSize));
        allDocs = cached.docs.slice(skip, skip + profileEntriesPageSize + 1);
      } else {
        const sortResult = await db.find({
          selector,
          fields: fieldsForFind,
          limit: SORT_FETCH_LIMIT,
        });
        let fullDocs = sortResult.docs || [];
        if (useAccentFolding) {
          if (searchQuery && !normalizedSearch) {
            fullDocs = [];
          } else if (normalizedSearch) {
            fullDocs = fullDocs.filter((d) => entryMatchesSearchQuery(d, fieldNames, normalizedSearch));
          }
        }
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
        totalPages = Math.max(1, Math.ceil(fullDocs.length / profileEntriesPageSize));
        allDocs = fullDocs.slice(skip, skip + profileEntriesPageSize + 1);
      }
    } else {
      if (searchQuery && fieldNames.length > 0) {
        if (useAccentFolding) {
          const recordsResult = await db.find({
            selector: { type: "elenko_record", profileId },
            fields: fieldsForFind,
            sort: [{ _id: "asc" }],
            limit: SORT_FETCH_LIMIT,
          });
          let filtered;
          if (searchQuery && !normalizedSearch) {
            filtered = [];
          } else {
            filtered = (recordsResult.docs || []).filter((d) =>
              entryMatchesSearchQuery(d, fieldNames, normalizedSearch)
            );
          }
          totalPages = Math.max(1, Math.ceil(filtered.length / profileEntriesPageSize));
          allDocs = filtered.slice(skip, skip + profileEntriesPageSize + 1);
        } else {
          const recordsResult = await db.find({
            selector,
            fields: fieldsForFind,
            sort: [{ _id: "asc" }],
            limit: profileEntriesPageSize + 1,
            skip,
          });
          allDocs = recordsResult.docs || [];
          if (searchQuery && allDocs.length > 0) totalPages = null; // unknown total for search without sort key
        }
      } else {
        const recordsResult = await db.find({
          selector,
          fields: fieldsForFind,
          sort: [{ _id: "asc" }],
          limit: profileEntriesPageSize + 1,
          skip,
        });
        allDocs = recordsResult.docs || [];
        if (searchQuery && allDocs.length > 0) totalPages = null; // unknown total for search without sort key
      }
    }
    const records = allDocs.slice(0, profileEntriesPageSize);
    const hasNext = allDocs.length > profileEntriesPageSize;
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

function getFieldNamesFromFormLayout(formDoc) {
  if (!formDoc || !Array.isArray(formDoc.fieldLayout)) return [];
  const names = [];
  const seen = new Set();
  for (const item of formDoc.fieldLayout) {
    if (!item) continue;
    if (isRepeatGroupLayoutItem(item)) {
      for (const c of normalizeRepeatColumns(item.repeatColumns)) {
        if (c && c.key && !seen.has(c.key)) {
          seen.add(c.key);
          names.push(c.key);
        }
      }
      continue;
    }
    const fn = typeof item.fieldName === "string" ? item.fieldName.trim() : "";
    if (fn && !seen.has(fn)) {
      seen.add(fn);
      names.push(fn);
    }
  }
  return names;
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
    .filter((item) => item && (item.fieldName || item.labelId || isRepeatGroupLayoutItem(item)))
    .sort((a, b) => (a.order != null ? Number(a.order) : 0) - (b.order != null ? Number(b.order) : 0));

  for (const item of sorted) {
    if (isRepeatGroupLayoutItem(item)) {
      const cols = normalizeRepeatColumns(item.repeatColumns);
      ordered.push({
        type: "repeatGroup",
        width: item.width || "100%",
        x: item.x,
        y: item.y,
        height: item.height,
        repeatMode: normalizeRepeatMode(item.repeatMode),
        repeatColumns: cols,
        repeatAddLabel:
          typeof item.repeatAddLabel === "string" && item.repeatAddLabel.trim()
            ? item.repeatAddLabel.trim()
            : "Add row",
      });
      for (const c of cols) {
        if (c && c.key) seenFields.add(c.key);
      }
      continue;
    }
    const fn = item && typeof item.fieldName === "string" ? item.fieldName.trim() : "";
    if (fn && !seenFields.has(fn)) {
      seenFields.add(fn);
      const fieldType = normalizeEntryFieldType(item.fieldType);
      const orderedItem = {
        type: "field",
        fieldName: fn,
        width: item.width || "100%",
        x: item.x,
        y: item.y,
        height: item.height,
        fieldType,
      };
      if (fieldType === "repeat") {
        orderedItem.repeatMode = normalizeRepeatMode(item.repeatMode);
        const cols = normalizeRepeatColumns(item.repeatColumns);
        orderedItem.repeatColumns = cols.length > 0 ? cols : defaultRepeatColumnsForField(fn);
        orderedItem.repeatAddLabel =
          typeof item.repeatAddLabel === "string" && item.repeatAddLabel.trim()
            ? item.repeatAddLabel.trim()
            : "Add row";
      }
      ordered.push(orderedItem);
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

function collectOrderedFieldNamesFromItems(orderedItems) {
  const names = [];
  const seen = new Set();
  for (const o of Array.isArray(orderedItems) ? orderedItems : []) {
    if (o && o.type === "field" && o.fieldName) {
      const fn = String(o.fieldName);
      if (!seen.has(fn)) {
        seen.add(fn);
        names.push(fn);
      }
    } else if (o && o.type === "repeatGroup") {
      for (const c of normalizeRepeatColumns(o.repeatColumns)) {
        if (c && c.key && !seen.has(c.key)) {
          seen.add(c.key);
          names.push(c.key);
        }
      }
    }
  }
  return names;
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

/**
 * Stack outer `.entry-field-block`: x/y/width, and min-height only when height is not moved to the inner `.value`
 * (image / file-preview fields — see fieldLayoutImageValueHeightConstraints).
 */
function blockOrCellStyleStackOuter(o, innerImageHeightHandled) {
  const parts = [];
  if (o.x != null) parts.push("left:" + o.x + "ch");
  if (o.y != null) parts.push("top:" + o.y + "em");
  const useOuterMinHeight = o.height != null && !innerImageHeightHandled;
  if (useOuterMinHeight) parts.push("min-height:" + o.height + "em");
  if (o.width && typeof o.width === "string" && o.width.trim()) parts.push("width:" + o.width.trim());
  if (parts.length === 0) return "";
  const needsAbsolute = o.x != null || o.y != null || useOuterMinHeight;
  if (needsAbsolute) parts.unshift("position:absolute");
  return parts.join(";");
}

function gridCellStyle(o) {
  if (o.width && typeof o.width === "string" && o.width.trim()) return "width:" + o.width.trim();
  return "";
}

/**
 * Grid / stack: Height (em) on an image-capable field constrains the `.value` box so the image scales inside it.
 * View: Single Entry image fields only. Edit: image fields + profile "file" fields (preview).
 */
function fieldLayoutImageValueHeightConstraints(o, profileDoc, forEdit) {
  if (!o || o.type !== "field") return { className: "", style: "" };
  let match = o.fieldType === "image";
  if (forEdit && profileDoc && isProfileFileField(profileDoc, o.fieldName)) match = true;
  if (!match) return { className: "", style: "" };
  if (o.height == null || o.height === "") return { className: "", style: "" };
  const n = Number(o.height);
  if (!Number.isFinite(n) || n <= 0) return { className: "", style: "" };
  return {
    className: " entry-grid-image-height",
    style:
      "box-sizing:border-box;height:" +
      n +
      "em;max-height:" +
      n +
      "em;min-height:0;overflow:auto;display:flex;flex-direction:column;align-items:flex-start;justify-content:flex-start;",
  };
}

/**
 * Stack layout (single-entry view): `.entry-view-stack .value` is capped at 12rem by default CSS.
 * When the form sets Height (em) on a non-image field, apply that as max-height so markdown/text matches the designer setting.
 */
function stackLayoutViewValueMaxHeightStyle(o, gImg) {
  if (gImg && gImg.style) return "";
  if (!o || o.type !== "field") return "";
  if (o.height == null || o.height === "") return "";
  const n = Number(o.height);
  if (!Number.isFinite(n) || n <= 0) return "";
  return "max-height:" + n + "em;";
}

function linkedQueryBlockStyleForLayout(layout, cfg) {
  if (!cfg || typeof cfg !== "object") return "";
  const parts = [];
  if (layout === "grid") {
    // In grid layout, always place the linked query block directly after the fields,
    // spanning all columns. X/Y are ignored here to avoid large vertical gaps.
    parts.push("grid-column:1 / -1");
  }
  if (cfg.width && typeof cfg.width === "string" && cfg.width.trim()) parts.push("width:" + cfg.width.trim());
  if (layout !== "grid" && cfg.height != null) {
    parts.push("max-height:" + cfg.height + "em");
    parts.push("overflow-y:auto");
  }
  return parts.join(";");
}

async function buildLinkedQueryHtmlForEntry(doc, record, formDoc, layout, opts = {}) {
  const options = opts && typeof opts === "object" ? opts : {};
  const forceLoad = !!options.forceLoad;
  const linkedQueryCfg = formDoc && formDoc.linkedQuery && typeof formDoc.linkedQuery === "object" ? formDoc.linkedQuery : null;
  const lqId = linkedQueryCfg && typeof linkedQueryCfg.id === "string" ? linkedQueryCfg.id.trim() : "";
  if (!lqId || !configDb || !db) return "";
  const stackHasPos = !!(
    layout === "stack" &&
    linkedQueryCfg &&
    (linkedQueryCfg.x != null || linkedQueryCfg.y != null || linkedQueryCfg.height != null)
  );
  const stackPosStyle =
    stackHasPos && linkedQueryCfg
      ? (() => {
          const parts = ["position:absolute"];
          if (linkedQueryCfg.x != null) parts.push("left:calc(" + linkedQueryCfg.x + "ch + 4ch)");
          if (linkedQueryCfg.y != null) parts.push("top:" + linkedQueryCfg.y + "em");
          if (linkedQueryCfg.height != null) parts.push("min-height:" + linkedQueryCfg.height + "em");
          return parts.join(";");
        })()
      : "";
  const stackWrapStart = stackHasPos ? `<div class="linked-query-stack-pos"${stackPosStyle ? ' style="' + escapeHtml(stackPosStyle) + '"' : ""}>` : "";
  const stackWrapEnd = stackHasPos ? `</div>` : "";

  if (linkedQueryCfg && linkedQueryCfg.loadOnDemand && !forceLoad) {
    let qDoc = null;
    try {
      const byId = await configDb.get(lqId);
      if (byId && byId.type === "elenko_query") qDoc = byId;
    } catch (e) {
      if (!e || e.statusCode !== 404) throw e;
    }
    if (!qDoc) {
      const byName = await configDb.find({ selector: { type: "elenko_query", name: lqId }, limit: 1 });
      const first = byName.docs && byName.docs[0];
      if (first && first.type === "elenko_query") qDoc = first;
    }
    const blockStyle = linkedQueryBlockStyleForLayout(layout, linkedQueryCfg);
    const styleAttr = blockStyle ? ' style="' + escapeHtml(blockStyle) + '"' : "";
    const buttonLabelRaw =
      linkedQueryCfg && typeof linkedQueryCfg.buttonLabel === "string" && linkedQueryCfg.buttonLabel.trim()
        ? linkedQueryCfg.buttonLabel.trim()
        : "Load linked data";
    const titleRaw = qDoc && (qDoc.name || qDoc._id) ? String(qDoc.name || qDoc._id) : "Linked query";
    const desc = qDoc && typeof qDoc.description === "string" && qDoc.description.trim() ? qDoc.description.trim() : "";
    const url =
      "/api/profile/" +
      encodeURIComponent(doc._id) +
      "/entry/" +
      encodeURIComponent(record._id) +
      "/linked-query";
    const blockHtml = (
      `<div class="linked-query-block"${styleAttr}>` +
      `<div class="linked-query-title">${escapeHtml(titleRaw)}</div>` +
      (desc ? `<div class="linked-query-desc">${escapeHtml(desc)}</div>` : "") +
      `<div class="linked-query-actions"><button type="button" class="btn-flow btn-flow-secondary linked-query-load-btn" data-url="${escapeHtml(url)}">${escapeHtml(buttonLabelRaw)}</button></div>` +
      `<div class="linked-query-content"><div class="empty">Table is empty. Click "${escapeHtml(buttonLabelRaw)}".</div></div>` +
      `</div>`
    );
    return stackWrapStart + blockHtml + stackWrapEnd;
  }

  const normalizeSortDirection = (raw) => (raw === "desc" ? "desc" : "asc");
  const resolveProfileDocByIdOrName = async (ref) => {
    const tid = (ref != null ? String(ref) : "").trim();
    if (!tid || !db) return null;
    try {
      const d = await db.get(tid);
      if (d && d.type === "elenko_profile") return d;
    } catch (e) {
      if (e && e.statusCode !== 404) throw e;
    }
    const byName = await db.find({ selector: { type: "elenko_profile", name: tid }, limit: 1 });
    const d2 = byName.docs && byName.docs[0];
    if (d2 && d2.type === "elenko_profile") return d2;
    return null;
  };
  const resolveConfigDocByIdOrName = async (ref, type) => {
    const tid = (ref != null ? String(ref) : "").trim();
    if (!tid || !configDb) return null;
    try {
      const d = await configDb.get(tid);
      if (d && d.type === type) return d;
    } catch (e) {
      if (e && e.statusCode !== 404) throw e;
    }
    const byName = await configDb.find({ selector: { type, name: tid }, limit: 1 });
    const d2 = byName.docs && byName.docs[0];
    if (d2 && d2.type === type) return d2;
    return null;
  };

  try {
    const qDoc = await resolveConfigDocByIdOrName(lqId, "elenko_query");
    if (!qDoc) return "";
    const baseKeyField = typeof qDoc.baseKeyField === "string" ? qDoc.baseKeyField.trim() : "";
    const queryKeyField = typeof qDoc.queryKeyField === "string" ? qDoc.queryKeyField.trim() : "";
    const baseKeyVal = baseKeyField ? record[baseKeyField] : "";
    const baseKeyStr = baseKeyVal != null ? String(baseKeyVal).trim() : "";
    if (!baseKeyField || !queryKeyField || !baseKeyStr) return "";

    const queryProfileDoc = await resolveProfileDocByIdOrName(qDoc.queryProfileId);
    const queryProfileId = queryProfileDoc && queryProfileDoc._id;
    const resultFieldsRaw = Array.isArray(qDoc.resultFields) ? qDoc.resultFields : [];
    const resultFields = resultFieldsRaw.map((f) => (typeof f === "string" ? f.trim() : "")).filter((f) => !!f);
    const fieldsToShow =
      resultFields.length > 0
        ? resultFields
        : queryProfileDoc && Array.isArray(queryProfileDoc.fieldNames) && queryProfileDoc.fieldNames.length > 0
        ? queryProfileDoc.fieldNames
        : [];
    if (!queryProfileId || fieldsToShow.length === 0) return "";

    const selector = { type: "elenko_record", profileId: queryProfileId, [queryKeyField]: baseKeyStr };
    const findRes = await db.find({
      selector,
      fields: ["_id", ...fieldsToShow],
      limit: 5000,
    });
    let rows = findRes.docs || [];
    const sortField = typeof qDoc.sortField === "string" ? qDoc.sortField.trim() : "";
    const sortDirection = normalizeSortDirection(qDoc.sortDirection);
    if (sortField) {
      rows = rows.slice().sort((a, b) => {
        const avRaw = a && a[sortField] != null ? String(a[sortField]) : "";
        const bvRaw = b && b[sortField] != null ? String(b[sortField]) : "";
        const an = Number(avRaw);
        const bn = Number(bvRaw);
        let c = 0;
        if (Number.isFinite(an) && Number.isFinite(bn)) c = an - bn;
        else c = avRaw.localeCompare(bvRaw, undefined, { sensitivity: "base", numeric: true });
        return sortDirection === "desc" ? -c : c;
      });
    }
    const headerCells = fieldsToShow.map((f) => `<th>${escapeHtml(f)}</th>`).join("");
    const bodyRows =
      rows.length > 0
        ? rows
            .map((r) => {
              const rowId = r && r._id ? String(r._id) : "";
              const tds = fieldsToShow
                .map((f) => {
                  const v = r && r[f] != null ? String(r[f]) : "";
                  if (f === fieldsToShow[0] && rowId) {
                    const href = "/profile/" + encodeURIComponent(queryProfileId) + "/entry/" + encodeURIComponent(rowId);
                    return `<td><a class="linked-query-firstcol" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(v)}</a></td>`;
                  }
                  return `<td>${escapeHtml(v)}</td>`;
                })
                .join("");
              return `<tr>${tds}</tr>`;
            })
            .join("")
        : `<tr><td colspan="${fieldsToShow.length}" class="empty">No results.</td></tr>`;

    const blockStyle = linkedQueryBlockStyleForLayout(layout, linkedQueryCfg);
    const styleAttr =
      blockStyle
        ? ' style="' + escapeHtml(blockStyle) + '"'
        : linkedQueryCfg && linkedQueryCfg.height != null
        ? ' style="max-height:' + escapeHtml(String(linkedQueryCfg.height)) + 'em;overflow-y:auto;"'
        : "";
    const desc = typeof qDoc.description === "string" && qDoc.description.trim() ? qDoc.description.trim() : "";
    const blockHtml = (
      `<div class="linked-query-block"${styleAttr}>` +
      `<div class="linked-query-title">${escapeHtml(qDoc.name || "Linked query")}</div>` +
      (desc ? `<div class="linked-query-desc">${escapeHtml(desc)}</div>` : "") +
      `<div class="linked-query-content"><table class="linked-query-table"><thead><tr>${headerCells}</tr></thead><tbody>${bodyRows}</tbody></table></div>` +
      `</div>`
    );
    return stackWrapStart + blockHtml + stackWrapEnd;
  } catch (e) {
    const errorHtml = `<div class="linked-query-block"><div class="linked-query-title">Linked query</div><div class="linked-query-content"><div class="empty">Query failed: ${escapeHtml(e && e.message ? e.message : String(e))}</div></div></div>`;
    return stackWrapStart + errorHtml + stackWrapEnd;
  }
}

async function renderViewEntryPage(doc, record, role, formDoc, returnQuery) {
  const canEdit = role === "admin" || role === "editor" || role === "user";
  const title = escapeHtml(doc.name || "Elenko database");
  const profileFieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const orderedItems = buildOrderedItems(profileFieldNames, formDoc);
  const profileId = doc._id;
  const entryId = record._id;
  const returnParts = [];
  if (returnQuery && returnQuery.page) returnParts.push("page=" + encodeURIComponent(String(returnQuery.page)));
  if (returnQuery && returnQuery.q) returnParts.push("q=" + encodeURIComponent(returnQuery.q));
  const isSplitEmbed = !!(returnQuery && String(returnQuery.split || "") === "1");
  const returnQueryStr = returnParts.length > 0 ? "?" + returnParts.join("&") : "";
  const backUrl = "/profile/" + encodeURIComponent(profileId) + returnQueryStr;
  const editUrl = "/profile/" + encodeURIComponent(profileId) + "/entry/" + encodeURIComponent(entryId) + "/edit" + returnQueryStr;

  const entryNavEnabled =
    formDoc &&
    (formDoc.entryNavForwardBackEnabled === true || formDoc.entryNavForwardBackEnabled === "true");
  let entryNavPrevId = null;
  let entryNavNextId = null;
  if (entryNavEnabled) {
    const adj = await getAdjacentEntryIdsForProfile(db, doc, entryId);
    entryNavPrevId = adj.prevId;
    entryNavNextId = adj.nextId;
  }
  function entryViewUrlForId(targetId) {
    return (
      "/profile/" +
      encodeURIComponent(profileId) +
      "/entry/" +
      encodeURIComponent(targetId) +
      returnQueryStr
    );
  }
  let entryNavHtml = "";
  if (entryNavEnabled) {
    const prevEl = entryNavPrevId
      ? `<a href="${escapeHtml(entryViewUrlForId(entryNavPrevId))}" class="entry-nav-pag" title="Previous entry" aria-label="Previous entry">◀</a>`
      : `<span class="entry-nav-pag entry-nav-disabled" title="No previous entry" aria-disabled="true" aria-label="No previous entry">◀</span>`;
    const nextEl = entryNavNextId
      ? `<a href="${escapeHtml(entryViewUrlForId(entryNavNextId))}" class="entry-nav-pag" title="Next entry" aria-label="Next entry">▶</a>`
      : `<span class="entry-nav-pag entry-nav-disabled" title="No next entry" aria-disabled="true" aria-label="No next entry">▶</span>`;
    entryNavHtml = `<span class="entry-nav-wrap">` + prevEl + nextEl + `</span>`;
  }

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
  const linkedQueryCfg = formDoc && formDoc.linkedQuery && typeof formDoc.linkedQuery === "object" ? formDoc.linkedQuery : null;
  const linkedQueryHasPos = !!(linkedQueryCfg && (linkedQueryCfg.x != null || linkedQueryCfg.y != null || linkedQueryCfg.height != null));
  const containerPositionStyle =
    layout === "grid"
      ? "" // let the grid flow naturally; no large min-height that could push the linked table far down
      : hasPositioning || linkedQueryHasPos
      ? "position:relative;min-height:40em;"
      : "";
  const linkedQueryHtml = await buildLinkedQueryHtmlForEntry(doc, record, formDoc, layout, { forceLoad: false });
  const viewHasChartField = orderedItems.some((o) => o.type === "field" && o.fieldType === "chart");

  function itemLabel(o) {
    if (o.type === "label") return o.text;
    if (o.type === "repeatGroup") return "";
    return o.fieldName;
  }
  function labelClass(o) {
    return o.type === "label" ? "label static-label" : "label field-label";
  }
  function itemValue(o) {
    if (o.type === "label" || o.type === "repeatGroup") return "";
    const val = record[o.fieldName];
    return val != null ? String(val) : "";
  }
  function formatValueHtml(o, value, attachmentEntryId) {
    if (o.type === "label") return "";
    if (o.type === "repeatGroup") return formatRepeatGroupHtml(record, o);
    const attEntry = attachmentEntryId != null ? String(attachmentEntryId) : entryId;
    if (o.fieldType === "markdown" && value) {
      return parseMarkdownToDisplayHtml(value);
    }
    if (o.fieldType === "url" && value) {
      const raw = String(value).trim();
      const escapedText = escapeHtml(raw);
      const hrefRaw = /^(https?:\/\/|mailto:|tel:)/i.test(raw) ? raw : "https://" + raw;
      const escapedHref = escapeHtml(hrefRaw);
      return `<a href="${escapedHref}" target="_blank" rel="noopener noreferrer">${escapedText}</a>`;
    }
    if (o.fieldType === "image" && value) {
      const raw = String(value).trim();
      if (!raw) return "";
      const src =
        "/api/profiles/" +
        encodeURIComponent(profileId) +
        "/entries/" +
        encodeURIComponent(attEntry) +
        "/attachments/" +
        encodeURIComponent(raw) +
        "?max=" +
        MAX_IMAGE_DISPLAY_EDGE;
      return `<img class="entry-inline-image" src="${escapeHtml(src)}" alt="${escapeHtml(o.fieldName || "Image")}" loading="lazy">`;
    }
    if (o.fieldType === "chart") {
      return formatEntryChartFieldHtml(o.fieldName, value);
    }
    if (o.fieldType === "repeat") {
      return formatRepeatFieldHtml(value, o);
    }
    if (isProfileRepeatField(doc, o.fieldName) || isProfileRepeatScalarJson(value)) {
      return escapeHtml(summarizeProfileRepeatScalarForList(value));
    }
    if (isProfileFileField(doc, o.fieldName) && value) {
      const raw = String(value).trim();
      if (!raw) return "";
      const href =
        "/api/profiles/" +
        encodeURIComponent(profileId) +
        "/entries/" +
        encodeURIComponent(attEntry) +
        "/attachments/" +
        encodeURIComponent(raw);
      return `<a class="entry-attachment-link" href="${escapeHtml(href)}" download>${escapeHtml(raw)}</a>`;
    }
    return escapeHtml(value);
  }

  async function loadResponsesForEntry() {
    if (!db || !entryId || !profileId) return [];
    const byIdMap = new Map();
    const listedIds = Array.isArray(record && record.responseDocIds) ? record.responseDocIds.map((x) => String(x).trim()).filter(Boolean) : [];
    for (const rid of listedIds) {
      try {
        const d = await db.get(rid);
        if (d && d.type === "elenko_record" && d.profileId === profileId && d.isResponse === true && d.responseToDocId === entryId) {
          byIdMap.set(d._id, d);
        }
      } catch (_) {}
    }
    try {
      const byRef = await db.find({
        selector: {
          type: "elenko_record",
          profileId,
          isResponse: true,
          responseToDocId: entryId,
        },
        limit: 5000,
      });
      for (const d of byRef.docs || []) {
        if (d && d._id) byIdMap.set(String(d._id), d);
      }
    } catch (_) {}
    const out = [...byIdMap.values()];
    out.sort((a, b) => {
      const av = a && a.createdAt ? String(a.createdAt) : "";
      const bv = b && b.createdAt ? String(b.createdAt) : "";
      return av.localeCompare(bv);
    });
    return out;
  }

  const responseFieldTypeByName = new Map();
  for (const o of orderedItems) {
    if (!o || o.type !== "field") continue;
    if (!responseFieldTypeByName.has(o.fieldName)) responseFieldTypeByName.set(o.fieldName, o.fieldType || "text");
  }
  const responseRecords = await loadResponsesForEntry();
  const responsesHtml =
    responseRecords.length > 0
      ? `<div class="entry-responses">` +
        responseRecords
          .map((resp) => {
            const rows = profileFieldNames
              .map((fn) => {
                const rawVal = resp && resp[fn] != null ? String(resp[fn]) : "";
                const fieldType = responseFieldTypeByName.get(fn) || "text";
                const valueHtml = formatValueHtml({ type: "field", fieldType, fieldName: fn }, rawVal, resp._id);
                return `<tr><td class="label">${escapeHtml(fn)}</td><td class="value">${valueHtml}</td></tr>`;
              })
              .join("");
            return (
              `<div class="entry-response-block">` +
              `<div class="entry-response-marker">↳ Response</div>` +
              `<table class="elenko-entry-fields-table"><tbody>${rows}</tbody></table>` +
              `</div>`
            );
          })
          .join("") +
        `</div>`
      : "";

  let contentHtml;
  if (orderedItems.length === 0) {
    contentHtml = '<div class="empty">No fields defined.</div>';
  } else if (layout === "stack") {
    contentHtml =
      '<div class="entry-view-stack" style="' + escapeHtml(containerPositionStyle) + '">' +
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const isRepeatGroup = o.type === "repeatGroup";
          const value = itemValue(o);
          const gImg = fieldLayoutImageValueHeightConstraints(o, doc, false);
          const innerImgHeight = !!gImg.style;
          const blockStyle = blockOrCellStyleStackOuter(o, innerImgHeight);
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
            (isRepeatGroup
              ? " value entry-repeat-group-value"
              : o.fieldType === "markdown"
              ? " value entry-value-markdown"
              : o.fieldType === "url"
              ? " value entry-value-url"
              : o.fieldType === "image"
              ? " value entry-value-image"
              : o.fieldType === "chart"
              ? " value entry-value-chart"
              : " value") + gImg.className;
          const stackMaxH = stackLayoutViewValueMaxHeightStyle(o, gImg);
          const valueBoxStyleStr = (gImg.style || "") + stackMaxH;
          const valueBoxStyle = valueBoxStyleStr ? ' style="' + escapeHtml(valueBoxStyleStr) + '"' : "";
          if (isRepeatGroup) {
            return `
        <div class="entry-field-block entry-repeat-group-block"${styleAttr}>
          <div class="${valueClass}"${valueBoxStyle}>${valueHtml}</div>
        </div>`;
          }
          return `
        <div class="entry-field-block"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="${valueClass}"${valueBoxStyle}>${valueHtml}</div>
        </div>`;
        })
        .join("") +
      "</div>";
    if (linkedQueryHtml) contentHtml += linkedQueryHtml;
  } else if (layout === "grid") {
    const widths = orderedItems.map((o) => o.width || "1fr").join(" ");
    contentHtml =
      `<div class="entry-view-grid" style="grid-template-columns: ${escapeHtml(widths)};${escapeHtml(containerPositionStyle)}">` +
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const isRepeatGroup = o.type === "repeatGroup";
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
          const gImg = fieldLayoutImageValueHeightConstraints(o, doc, false);
          const valueClass =
            (isRepeatGroup
              ? " value entry-repeat-group-value"
              : o.fieldType === "markdown"
              ? " value entry-value-markdown"
              : o.fieldType === "url"
              ? " value entry-value-url"
              : o.fieldType === "image"
              ? " value entry-value-image"
              : o.fieldType === "chart"
              ? " value entry-value-chart"
              : " value") + gImg.className;
          const valueBoxStyle = gImg.style ? ' style="' + escapeHtml(gImg.style) + '"' : "";
          if (isRepeatGroup) {
            return `
        <div class="entry-grid-cell entry-repeat-group-block"${styleAttr}>
          <div class="${valueClass}"${valueBoxStyle}>${valueHtml}</div>
        </div>`;
          }
          return `
        <div class="entry-grid-cell"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="${valueClass}"${valueBoxStyle}>${valueHtml}</div>
        </div>`;
        })
        .join("") +
      (linkedQueryHtml ? linkedQueryHtml : "") +
      "</div>";
  } else {
    const rows =
      orderedItems
        .map((o) => {
          const isLabel = o.type === "label";
          const isRepeatGroup = o.type === "repeatGroup";
          const value = itemValue(o);
          const lc = labelClass(o);
          if (isLabel) {
            const w = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
            return `
        <tr class="entry-label-row">
          <td class="${lc}" colspan="2"${w}>${escapeHtml(itemLabel(o))}</td>
        </tr>`;
          }
          if (isRepeatGroup) {
            const w = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
            const valueHtml = formatValueHtml(o, value);
            return `
        <tr class="entry-repeat-group-row">
          <td class="value entry-repeat-group-value" colspan="2"${w}>${valueHtml}</td>
        </tr>`;
          }
          const valueHtml = formatValueHtml(o, value);
          const valueClass =
            o.fieldType === "markdown"
              ? " value entry-value-markdown"
              : o.fieldType === "url"
              ? " value entry-value-url"
              : o.fieldType === "image"
              ? " value entry-value-image"
              : o.fieldType === "chart"
              ? " value entry-value-chart"
              : " value";
          return `
        <tr>
          <td class="${lc}">${escapeHtml(itemLabel(o))}</td>
          <td class="${valueClass}">${valueHtml}</td>
        </tr>`;
        })
        .join("");
    contentHtml = `<table class="elenko-entry-fields-table"><tbody>${rows}</tbody></table>`;
    if (linkedQueryHtml) contentHtml += linkedQueryHtml;
  }
  if (responsesHtml) contentHtml += responsesHtml;

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
    body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem 1.25rem; background: var(--entry-bg, #0f1419); color: var(--entry-text, #e6edf3); max-width: 48rem; }
    h1 { font-weight: 600; margin: 0; font-size: 1.25rem; line-height: 1.2; }
    .sub { color: var(--entry-label, #8b949e); margin: 0; }
    .topbar { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.75rem; }
    .topbar-main { min-width: 0; flex: 1 1 auto; display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; }
    .topbar-links { margin: 0; display: inline-flex; align-items: baseline; gap: 0.75rem; flex-wrap: wrap; }
    .topbar-links a { color: var(--entry-link, #58a6ff); text-decoration: none; }
    .topbar-links a:hover { text-decoration: underline; }
    .entry-nav-wrap { display: inline-flex; align-items: center; gap: 0.35rem; }
    /* Match database list row navigation (◀ / ▶) — same filled triangles as .pagination .btn-pag-row */
    .entry-nav-pag {
      display: inline-block;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      line-height: 1;
      border: 1px solid var(--entry-field-border, #21262d);
      background: var(--entry-field-bg, #161b22);
      color: var(--entry-link, #58a6ff);
      text-decoration: none;
      box-sizing: border-box;
    }
    a.entry-nav-pag:hover {
      text-decoration: none;
      background: color-mix(in srgb, var(--entry-field-bg, #161b22) 78%, var(--entry-link, #58a6ff) 22%);
      color: var(--entry-link, #58a6ff);
    }
    .entry-nav-pag.entry-nav-disabled {
      color: var(--entry-label, #8b949e);
      pointer-events: none;
      cursor: default;
      background: var(--entry-field-bg, #161b22);
      opacity: 0.65;
    }
    /* Same button look as .entry-nav-pag / pagination; ◀ is widely supported (unlike U+2B9C). */
    .topbar-links a.topbar-icon-btn {
      display: inline-block;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      line-height: 1;
      border: 1px solid var(--entry-field-border, #21262d);
      background: var(--entry-field-bg, #161b22);
      color: var(--entry-link, #58a6ff);
      text-decoration: none;
      box-sizing: border-box;
    }
    .topbar-links a.topbar-icon-btn:hover {
      text-decoration: none;
      background: color-mix(in srgb, var(--entry-field-bg, #161b22) 78%, var(--entry-link, #58a6ff) 22%);
      color: var(--entry-link, #58a6ff);
    }
    @media (max-width: 768px) {
      .topbar-links a.topbar-icon-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.25rem -0.45rem -0.5rem;
      }
    }
    .topbar-titleline { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; min-width: 0; }
    .topbar-actions { flex: 0 0 auto; display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 0.5rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.75rem 1rem; text-align: left; }
    .label { color: var(--entry-label, #8b949e); width: 40%; }
    td.value { background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 6px; }
    @media (max-width: 768px) {
      table.elenko-entry-fields-table,
      table.elenko-entry-fields-table tbody {
        display: block;
        width: 100%;
      }
      table.elenko-entry-fields-table tr {
        display: block;
        width: 100%;
        margin-bottom: 1.1rem;
      }
      table.elenko-entry-fields-table tr:last-child {
        margin-bottom: 0;
      }
      table.elenko-entry-fields-table td {
        display: block;
        width: 100% !important;
        max-width: 100%;
        box-sizing: border-box;
        border: none;
        padding-left: 0;
        padding-right: 0;
      }
      table.elenko-entry-fields-table td.label {
        width: 100% !important;
        padding-top: 0;
        padding-bottom: 0.3rem;
      }
      table.elenko-entry-fields-table td.value {
        padding: 0.75rem 1rem;
      }
      table.elenko-entry-fields-table tr.entry-label-row td {
        padding: 0.6rem 0;
        margin-bottom: 0.35rem;
        border-bottom: 1px solid var(--entry-field-border, #21262d);
      }
    }
    .empty { color: var(--entry-label, #8b949e); font-style: italic; }
    /* Default scroll cap for long values; overridden by inline max-height when the form sets Stack Height (em). */
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
    .entry-value-markdown, .entry-repeat-col-markdown { line-height: 1.4; }
    .entry-value-markdown > :first-child, .entry-repeat-col-markdown > :first-child { margin-top: 0; }
    .entry-value-markdown > :last-child, .entry-repeat-col-markdown > :last-child { margin-bottom: 0; }
    .entry-value-markdown p, .entry-repeat-col-markdown p { margin: 0 0 0.35rem 0; }
    .entry-value-markdown p:empty, .entry-repeat-col-markdown p:empty { display: none; }
    .entry-value-markdown ul, .entry-value-markdown ol, .entry-repeat-col-markdown ul, .entry-repeat-col-markdown ol { margin: 0.2rem 0 0.35rem 0; padding-left: 1.25rem; }
    .entry-value-markdown li, .entry-repeat-col-markdown li { margin: 0.08rem 0; }
    .entry-value-markdown li p, .entry-repeat-col-markdown li p { margin: 0; }
    .entry-value-markdown h1, .entry-value-markdown h2, .entry-value-markdown h3, .entry-repeat-col-markdown h1, .entry-repeat-col-markdown h2, .entry-repeat-col-markdown h3 { margin: 0.45rem 0 0.2rem 0; font-weight: 600; line-height: 1.3; }
    .entry-value-markdown h1:first-child, .entry-value-markdown h2:first-child, .entry-value-markdown h3:first-child, .entry-repeat-col-markdown h1:first-child, .entry-repeat-col-markdown h2:first-child, .entry-repeat-col-markdown h3:first-child { margin-top: 0; }
    .entry-value-markdown h1:not(:first-child), .entry-value-markdown h2:not(:first-child), .entry-value-markdown h3:not(:first-child), .entry-repeat-col-markdown h1:not(:first-child), .entry-repeat-col-markdown h2:not(:first-child), .entry-repeat-col-markdown h3:not(:first-child) { margin-top: 1rem; }
    .entry-value-markdown h1, .entry-repeat-col-markdown h1 { font-size: 1.2rem; }
    .entry-value-markdown h2, .entry-repeat-col-markdown h2 { font-size: 1.05rem; }
    .entry-value-markdown h3, .entry-repeat-col-markdown h3 { font-size: 0.95rem; }
    .entry-value-markdown a, .entry-repeat-col-markdown a { color: var(--entry-link, #58a6ff); }
    .entry-value-markdown ul + ul, .entry-repeat-col-markdown ul + ul { margin-top: 0; }
    .entry-value-markdown ol + ol, .entry-repeat-col-markdown ol + ol { margin-top: 0; }
    .entry-value-markdown h1 + ul, .entry-value-markdown h2 + ul, .entry-value-markdown h3 + ul, .entry-repeat-col-markdown h1 + ul, .entry-repeat-col-markdown h2 + ul, .entry-repeat-col-markdown h3 + ul { margin-top: 0.1rem; }
    .value:not(.entry-value-markdown):not(.entry-value-chart):not(.entry-value-image):not(.entry-repeat-group-value) { white-space: pre-wrap; overflow-wrap: break-word; }
    .entry-value-url a { color: var(--entry-link, #58a6ff); word-break: break-all; }
    .entry-profile-file-dl a { color: var(--entry-link, #58a6ff); word-break: break-all; }
    .entry-value-image { min-height: 0; }
    .entry-inline-image { max-width: 100%; height: auto; max-height: 24rem; display: block; border-radius: 6px; }
    .entry-repeat-table { width: 100%; border-collapse: collapse; margin-top: 0.25rem; }
    .entry-repeat-table th, .entry-repeat-table td { border: 1px solid var(--entry-field-border, #21262d); padding: 0.5rem 0.65rem; text-align: left; vertical-align: top; }
    .entry-repeat-col-value:not(.entry-repeat-col-markdown), .entry-repeat-table td:not(.entry-repeat-col-markdown) { white-space: pre-wrap; overflow-wrap: break-word; }
    .entry-repeat-table th { background: var(--entry-field-bg, #161b22); color: var(--entry-label, #8b949e); font-weight: 600; }
    .entry-repeat-stack { display: flex; flex-direction: column; gap: 0.75rem; }
    .entry-repeat-stack-block { border: 1px solid var(--entry-field-border, #21262d); border-radius: 6px; padding: 0.65rem 0.75rem; background: var(--entry-field-bg, #161b22); }
    .entry-repeat-stack-head { font-size: 0.8rem; color: var(--entry-label, #8b949e); margin-bottom: 0.35rem; }
    .entry-repeat-stack-field { margin-top: 0.35rem; }
    .entry-repeat-col-label { font-size: 0.8rem; color: var(--entry-label, #8b949e); margin-bottom: 0.15rem; }
    .entry-repeat-empty, .entry-repeat-error { color: var(--entry-label, #8b949e); font-style: italic; }
    .entry-repeat-error { color: #f85149; font-style: normal; }
    .entry-repeat-draft-row { outline: 1px solid color-mix(in srgb, var(--entry-link, #58a6ff) 55%, transparent); outline-offset: -1px; }
    .entry-repeat-draft-badge { font-size: 0.72rem; font-weight: 600; color: var(--entry-link, #58a6ff); text-transform: uppercase; letter-spacing: 0.03em; }
    .entry-repeat-col-draft .entry-repeat-cell, .entry-repeat-col-draft .entry-repeat-cell-textarea { width: 100%; min-width: 6rem; box-sizing: border-box; padding: 0.35rem 0.5rem; background: var(--entry-field-bg, #0d1117); border: 1px solid #30363d; border-radius: 4px; color: var(--entry-text, #e6edf3); font: inherit; }
    .entry-repeat-col-draft .entry-repeat-cell-textarea { min-height: 2.5rem; resize: vertical; white-space: pre-wrap; }
    .entry-repeat-col-draft .entry-repeat-cell-markdown { min-height: 6rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.875rem; line-height: 1.4; }
    .entry-view-grid .entry-grid-cell .value.entry-grid-image-height .entry-inline-image {
      max-height: 100%;
      width: auto;
      height: auto;
      object-fit: contain;
      object-position: left top;
    }
    .entry-view-stack .entry-field-block:not(.entry-label-only) .value.entry-grid-image-height .entry-inline-image {
      max-height: 100%;
      width: auto;
      height: auto;
      object-fit: contain;
      object-position: left top;
    }
    .entry-grid-cell.entry-label-only .label { white-space: nowrap; }
    .entry-label-row .label { white-space: nowrap; }
    .linked-query-block { margin-top: 1rem; background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 8px; padding: 0.75rem; }
    .linked-query-stack-pos > .linked-query-block { margin-top: 0; }
    .linked-query-title { color: var(--entry-label, #8b949e); font-weight: 600; margin-bottom: 0.5rem; }
    .linked-query-desc { color: var(--entry-label, #8b949e); margin: -0.25rem 0 0.75rem 0; font-size: 0.9rem; }
    .linked-query-actions { margin-bottom: 0.5rem; }
    .linked-query-content { min-height: 1.5rem; }
    .linked-query-table { width: 100%; border-collapse: collapse; }
    .linked-query-table th { color: var(--entry-label, #8b949e); font-weight: 600; background: transparent; border-bottom: 1px solid var(--entry-field-border, #21262d); padding: 0.5rem 0.5rem; }
    .linked-query-table td { border-bottom: 1px solid rgba(48, 54, 61, 0.6); padding: 0.5rem 0.5rem; vertical-align: top; }
    .linked-query-table tr:last-child td { border-bottom: none; }
    .linked-query-firstcol { color: var(--entry-link, #58a6ff); text-decoration: none; }
    .linked-query-firstcol:hover { text-decoration: underline; }
    .entry-responses { margin-top: 1rem; display: flex; flex-direction: column; gap: 0.75rem; }
    .entry-response-block { background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 8px; padding: 0.5rem 0.75rem; }
    .entry-response-block table { margin-top: 0.25rem; }
    .entry-response-marker { color: var(--entry-label, #8b949e); font-weight: 600; }
    .entry-value-chart { max-height: none !important; overflow: visible !important; }
    .entry-chart-error { color: #f85149; margin: 0; font-size: 0.9rem; }
    .entry-chart-mount { box-sizing: border-box; }
  </style>
  ${formCustomCss ? `<style>${formCustomCss}</style>` : ""}
</head>
<body>
  <div class="topbar">
    <div class="topbar-main">
      <div class="topbar-links">${isSplitEmbed ? "" : `<a href="${escapeHtml(backUrl)}" class="topbar-icon-btn" title="Back to database" aria-label="Back to database">◀</a>`}${canEdit ? `<a href="${editUrl}">Edit</a>` : ""}${entryNavHtml}</div>
      <div class="topbar-titleline">
        <h1>${title}</h1>
        ${formLabel ? `<span class="sub">Form: ${escapeHtml(formLabel)}</span>` : ""}
      </div>
    </div>
    <div class="topbar-actions entry-flow-actions">
      ${flowButtonsHtml}
      <button type="button" id="refresh-entry-btn" class="btn-flow btn-flow-secondary">Refresh</button>
    </div>
  </div>
  ${hasFlowButtons ? '<div id="flow-msg" class="flow-msg" style="margin-bottom:0.5rem;"></div>' : ""}
  ${contentHtml}
  ${hasFlowButtons ? "\n  <style>.btn-flow { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; background: #238636; color: #fff; }.btn-flow:hover { background: #2ea043; }.btn-flow:disabled { opacity: 0.6; cursor: not-allowed; }.btn-flow-secondary { background: #21262d; }.btn-flow-secondary:hover { background: #30363d; }.flow-msg { margin-top: 0.5rem; font-size: 0.875rem; }.flow-msg.ok { color: #3fb950; }.flow-msg.err { color: #f85149; }</style>\n  <script>\n    (function() {\n      var msgEl = document.getElementById(\"flow-msg\");\n      document.querySelectorAll(\".entry-flow-actions .btn-flow[data-entry-id]\").forEach(function(btn) {\n        if (btn.id === \"refresh-entry-btn\") return;\n        btn.onclick = function() {\n          var pid = btn.getAttribute(\"data-profile-id\");\n          var eid = btn.getAttribute(\"data-entry-id\");\n          if (!pid || !eid) return;\n          btn.disabled = true;\n          if (msgEl) { msgEl.textContent = \"\"; msgEl.className = \"flow-msg\"; }\n          var body = {};\n          var idx = btn.getAttribute(\"data-flow-index\");\n          if (idx !== null && idx !== \"\") body.flowIndex = parseInt(idx, 10);\n          var draftRow = document.querySelector(\".entry-repeat-draft-row\");\n          if (draftRow) {\n            var edits = {};\n            draftRow.querySelectorAll(\".entry-repeat-cell\").forEach(function(el) {\n              var k = el.getAttribute(\"data-col-key\");\n              if (k) edits[k] = el.value != null ? el.value : \"\";\n            });\n            if (Object.keys(edits).length) body.draftRepeatEdits = edits;\n          }\n          var url = \"/api/profile/\" + encodeURIComponent(pid) + \"/entry/\" + encodeURIComponent(eid) + \"/send-to-flow\";\n          fetch(url, { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify(body) })\n            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })\n            .then(function(o) {\n              if (o.ok && o.data && o.data.reloadEntry) {\n                if (msgEl) { msgEl.textContent = \"Updated — refreshing…\"; msgEl.className = \"flow-msg ok\"; }\n                window.location.reload();\n                return;\n              }\n              if (o.ok && msgEl) {\n                msgEl.textContent = (o.data && o.data.refreshTimedOut)\n                  ? \"Flow finished; entry did not update in time (see flow log).\"\n                  : \"Sent to Flow.\";\n                msgEl.className = (o.data && o.data.refreshTimedOut) ? \"flow-msg err\" : \"flow-msg ok\";\n              } else if (msgEl) { msgEl.textContent = o.data.error || \"Failed\"; msgEl.className = \"flow-msg err\"; }\n              btn.disabled = false;\n            })\n            .catch(function(e) { if (msgEl) { msgEl.textContent = e.message || \"Request failed\"; msgEl.className = \"flow-msg err\"; } btn.disabled = false; });\n        };\n      });\n      var refreshBtn = document.getElementById(\"refresh-entry-btn\");\n      if (refreshBtn) refreshBtn.onclick = function() { window.location.reload(); };\n    })();\n  </script>" : "\n  <style>.btn-flow { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }.btn-flow-secondary { background: #21262d; color: #e6edf3; }.btn-flow-secondary:hover { background: #30363d; }</style>\n  <script>\n    (function() {\n      var refreshBtn = document.getElementById(\"refresh-entry-btn\");\n      if (refreshBtn) refreshBtn.onclick = function() { window.location.reload(); };\n    })();\n  </script>"}
  <script>
    (function() {
      document.querySelectorAll('.linked-query-load-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var block = btn.closest('.linked-query-block');
          var stackWrap = btn.closest('.linked-query-stack-pos');
          var content = block ? block.querySelector('.linked-query-content') : null;
          var url = btn.getAttribute('data-url');
          if (!content || !url) return;
          btn.disabled = true;
          content.innerHTML = '<div class="empty">Loading…</div>';
          fetch(url, { method: 'GET', headers: { 'Content-Type': 'application/json' } })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (!o.ok || !o.data || !o.data.ok) {
                content.innerHTML = '<div class="empty">' + ((o.data && o.data.error) ? String(o.data.error) : 'Load failed') + '</div>';
                return;
              }
              if (o.data.html) {
                // Keep Stack layout positioning stable by replacing the positioned wrapper
                // when present; otherwise replace the regular linked query block.
                if (stackWrap) stackWrap.outerHTML = o.data.html;
                else if (block) block.outerHTML = o.data.html;
              } else {
                content.innerHTML = '<div class="empty">No linked query content.</div>';
              }
            })
            .catch(function(e) {
              btn.disabled = false;
              content.innerHTML = '<div class="empty">' + (e && e.message ? String(e.message) : 'Load failed') + '</div>';
            });
        });
      });
    })();
  </script>${
    viewHasChartField
      ? `
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" crossorigin="anonymous"></script>
  <script>
    ${entryViewChartInitScript()}
  </script>`
      : ""
  }
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
  const viewUrl = "/profile/" + encodeURIComponent(profileId) + "/entry/" + encodeURIComponent(entryId) + returnQueryStr;
  const discardOnCancel = record[ELENKO_DISCARD_ON_CANCEL] === true;
  const cancelHref = discardOnCancel ? backUrl : viewUrl;
  const formCustomCss = formDoc && formDoc.customCss ? formDoc.customCss : "";

  const theme = formDoc && formDoc.theme ? formDoc.theme : DEFAULT_ENTRY_VIEW_THEME;
  const bg = theme.background || DEFAULT_ENTRY_VIEW_THEME.background;
  const text = theme.text || DEFAULT_ENTRY_VIEW_THEME.text;
  const labelColor = theme.label || DEFAULT_ENTRY_VIEW_THEME.label;
  const linkColor = theme.link || DEFAULT_ENTRY_VIEW_THEME.link;
  const fieldBgEdit = theme.fieldBackgroundEdit != null ? theme.fieldBackgroundEdit : DEFAULT_ENTRY_VIEW_THEME.fieldBackgroundEdit;
  const fieldBorder =
    theme.fieldBorder != null && String(theme.fieldBorder).trim()
      ? String(theme.fieldBorder).trim()
      : DEFAULT_ENTRY_VIEW_THEME.fieldBorder;
  const textEdit = theme.textEdit != null ? theme.textEdit : DEFAULT_ENTRY_VIEW_THEME.textEdit;
  const layout = formDoc && (formDoc.layout === "grid" || formDoc.layout === "stack") ? formDoc.layout : "table";

  const orderedItems = buildOrderedItems(profileFieldNames, formDoc || {});
  const orderedFieldNames = collectOrderedFieldNamesFromItems(orderedItems);

  const themeVars = `
    :root {
      --entry-bg: ${escapeHtml(bg)};
      --entry-text: ${escapeHtml(text)};
      --entry-label: ${escapeHtml(labelColor)};
      --entry-link: ${escapeHtml(linkColor)};
      --entry-field-border: ${escapeHtml(fieldBorder)};
      --entry-field-bg-edit: ${escapeHtml(fieldBgEdit)};
      --entry-text-edit: ${escapeHtml(textEdit)};
    }`;

  const hasPositioning = orderedItems.some((o) => o.x != null || o.y != null || o.height != null);
  const containerPositionStyle = layout === "grid" ? "" : (hasPositioning ? "position:relative;min-height:40em;" : "");

  function itemLabel(o) {
    if (o.type === "label") return o.text;
    if (o.type === "repeatGroup") return "";
    return o.fieldName;
  }
  function labelClass(o) {
    return o.type === "label" ? "label static-label" : "label field-label";
  }
  function entryFieldIsImage(o) {
    if (!o || o.type !== "field") return false;
    if (normalizeEntryFieldType(o.fieldType) === "image") return true;
    const item = getFieldLayoutItemForFieldName(formDoc, o.fieldName);
    return !!(item && normalizeEntryFieldType(item.fieldType) === "image");
  }
  function entryFieldIsAttachmentBacked(o) {
    if (!o || o.type !== "field") return false;
    return entryFieldIsImage(o) || isProfileFileField(doc, o.fieldName);
  }
  function entryFieldIsProfileFileNotFormImage(o) {
    return entryFieldIsAttachmentBacked(o) && !entryFieldIsImage(o);
  }
  function editFieldLabelHtml(o) {
    const lc = labelClass(o);
    const text = escapeHtml(itemLabel(o));
    if (!entryFieldIsAttachmentBacked(o)) {
      if (layout === "table") return text;
      return `<span class="${lc}">${text}</span>`;
    }
    const pickTitle = entryFieldIsProfileFileNotFormImage(o) ? "Attach file" : "Attach image file";
    if (layout === "table") {
      return `<button type="button" class="entry-image-import-btn" title="${escapeHtml(pickTitle)}">${text}</button>`;
    }
    return `<button type="button" class="${lc} entry-image-import-btn" title="${escapeHtml(pickTitle)}">${text}</button>`;
  }
  function editControlHtml(o, value) {
    if (o.type === "repeatGroup") {
      return buildRepeatGroupEditControlHtml(record, o);
    }
    const escapedName = escapeHtml(o.fieldName);
    const escapedValue = escapeHtml(value);
    if (entryFieldIsImage(o)) {
      const v = value != null ? String(value).trim() : "";
      const previewUrl = v
        ? "/api/profiles/" +
          encodeURIComponent(profileId) +
          "/entries/" +
          encodeURIComponent(entryId) +
          "/attachments/" +
          encodeURIComponent(v) +
          "?max=" +
          MAX_IMAGE_DISPLAY_EDGE
        : "";
      const imgTag = v
        ? `<img class="entry-image-preview" src="${escapeHtml(previewUrl)}" alt="" loading="lazy">`
        : `<img class="entry-image-preview" alt="" loading="lazy" style="display:none">`;
      const noneVis = v ? ' style="display:none"' : "";
      return (
        `<div class="entry-image-edit-wrap">` +
        imgTag +
        `<span class="entry-image-none"${noneVis}>No image</span>` +
        `<input type="hidden" class="entry-field entry-image-filename" name="${escapedName}" value="${escapedValue}">` +
        `<div class="entry-image-actions">` +
        `<input type="file" class="entry-image-file" accept="image/*" aria-label="Upload image for ${escapedName}" tabindex="-1">` +
        `<button type="button" class="btn btn-secondary entry-image-clear">Clear</button>` +
        `</div>` +
        `<span class="entry-image-upload-status" aria-live="polite"></span>` +
        `</div>`
      );
    }
    if (isProfileFileField(doc, o.fieldName)) {
      const v = value != null ? String(value).trim() : "";
      const dlHref = v
        ? "/api/profiles/" +
          encodeURIComponent(profileId) +
          "/entries/" +
          encodeURIComponent(entryId) +
          "/attachments/" +
          encodeURIComponent(v)
        : "";
      const noneVis = v ? ' style="display:none"' : "";
      const dlStyle = v ? "" : ' style="display:none"';
      return (
        `<div class="entry-image-edit-wrap" data-profile-file="1">` +
        `<img class="entry-image-preview" alt="" loading="lazy" style="display:none">` +
        `<span class="entry-image-none"${noneVis}>No file</span>` +
        `<a class="entry-profile-file-dl" href="${v ? escapeHtml(dlHref) : "#"}"${dlStyle}>${escapedValue}</a> ` +
        `<input type="hidden" class="entry-field entry-image-filename" name="${escapedName}" value="${escapedValue}">` +
        `<div class="entry-image-actions">` +
        `<input type="file" class="entry-image-file" aria-label="Upload file for ${escapedName}" tabindex="-1">` +
        `<button type="button" class="btn btn-secondary entry-image-clear">Clear</button>` +
        `</div>` +
        `<span class="entry-image-upload-status" aria-live="polite"></span>` +
        `</div>`
      );
    }
    if (o.fieldType === "url") {
      return `<input type="url" class="entry-field" name="${escapedName}" placeholder="${escapedName}" value="${escapedValue}">`;
    }
    if (o.fieldType === "chart") {
      return `<textarea class="entry-field entry-field-textarea entry-field-chart-json" name="${escapedName}" placeholder='{"version":1,"chartType":"line","xAxis":{"title":"X","values":[]},"yAxis":{"title":"Y","values":[]}}' rows="12" spellcheck="false">${escapedValue}</textarea>`;
    }
    if (o.fieldType === "repeat") {
      return buildRepeatEditControlHtml(o, value);
    }
    return `<textarea class="entry-field entry-field-textarea" name="${escapedName}" placeholder="${escapedName}" rows="3">${escapedValue}</textarea>`;
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
          const isRepeatGroup = o.type === "repeatGroup";
          const gImg = fieldLayoutImageValueHeightConstraints(o, doc, true);
          const innerImgHeight = !!gImg.style;
          const blockStyle = blockOrCellStyleStackOuter(o, innerImgHeight);
          const styleAttr = blockStyle ? ' style="' + escapeHtml(blockStyle) + '"' : "";
          const labelOnlyClass = isLabel ? " entry-label-only" : "";
          const lc = labelClass(o);
          if (isLabel) {
            return `
        <div class="entry-field-block${labelOnlyClass}"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
        </div>`;
          }
          const value = o.type === "field" && o.fieldName ? (record[o.fieldName] != null ? String(record[o.fieldName]) : "") : "";
          const valueBoxStyle = gImg.style ? ' style="' + escapeHtml(gImg.style) + '"' : "";
          if (isRepeatGroup) {
            return `
        <div class="entry-field-block entry-repeat-group-block"${styleAttr}>
          <div class="value entry-repeat-group-value${gImg.className}"${valueBoxStyle}>${editControlHtml(o, value)}</div>
        </div>`;
          }
          return `
        <div class="entry-field-block"${styleAttr}>
          ${editFieldLabelHtml(o)}
          <div class="value${gImg.className}"${valueBoxStyle}>${editControlHtml(o, value)}</div>
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
          const isRepeatGroup = o.type === "repeatGroup";
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
          const value = o.type === "field" && o.fieldName ? (record[o.fieldName] != null ? String(record[o.fieldName]) : "") : "";
          const gImg = fieldLayoutImageValueHeightConstraints(o, doc, true);
          const valueBoxStyle = gImg.style ? ' style="' + escapeHtml(gImg.style) + '"' : "";
          if (isRepeatGroup) {
            return `
        <div class="entry-grid-cell entry-repeat-group-block"${styleAttr}>
          <div class="value entry-repeat-group-value${gImg.className}"${valueBoxStyle}>${editControlHtml(o, value)}</div>
        </div>`;
          }
          return `
        <div class="entry-grid-cell"${styleAttr}>
          ${editFieldLabelHtml(o)}
          <div class="value${gImg.className}"${valueBoxStyle}>${editControlHtml(o, value)}</div>
        </div>`;
        })
        .join("") +
      "</div>";
  } else {
    const rows = orderedItems
      .map((o) => {
        const isLabel = o.type === "label";
        const isRepeatGroup = o.type === "repeatGroup";
        const lc = labelClass(o);
        if (isLabel) {
          const w = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
          return `
        <tr class="entry-label-row">
          <td class="${lc}" colspan="2"${w}>${escapeHtml(itemLabel(o))}</td>
        </tr>`;
        }
        if (isRepeatGroup) {
          const valueCellWidth = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
          return `
        <tr class="entry-repeat-group-row">
          <td class="value entry-repeat-group-value" colspan="2"${valueCellWidth}>${editControlHtml(o, "")}</td>
        </tr>`;
        }
        const value = record[o.fieldName] != null ? String(record[o.fieldName]) : "";
        const valueCellWidth = o.width && typeof o.width === "string" && o.width.trim() ? ' style="width:' + escapeHtml(o.width.trim()) + '"' : "";
        return `
        <tr>
          <td class="${lc}">${editFieldLabelHtml(o)}</td>
          <td class="value"${valueCellWidth}>${editControlHtml(o, value)}</td>
        </tr>`;
      })
      .join("");
    contentHtml = `<table class="elenko-entry-fields-table"><tbody>${rows}</tbody></table>`;
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
    body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem 1.25rem; background: var(--entry-bg, #0f1419); color: var(--entry-text, #e6edf3); max-width: 48rem; }
    h1 { font-weight: 600; margin: 0; font-size: 1.2rem; line-height: 1.2; }
    .sub { color: var(--entry-label, #8b949e); margin: 0; }
    .topbar { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.75rem; }
    .topbar-main { min-width: 0; flex: 1 1 auto; display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; }
    .topbar-links { display: inline-flex; align-items: baseline; gap: 0.75rem; }
    .topbar-links a { color: var(--entry-link, #58a6ff); text-decoration: none; }
    .topbar-links a:hover { text-decoration: underline; }
    .topbar-links a.topbar-icon-btn {
      display: inline-block;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      line-height: 1;
      border: 1px solid var(--entry-field-border, #21262d);
      background: var(--entry-field-bg-edit, #161b22);
      color: var(--entry-link, #58a6ff);
      text-decoration: none;
      box-sizing: border-box;
    }
    .topbar-links a.topbar-icon-btn:hover {
      text-decoration: none;
      background: color-mix(in srgb, var(--entry-field-bg-edit, #161b22) 78%, var(--entry-link, #58a6ff) 22%);
      color: var(--entry-link, #58a6ff);
    }
    @media (max-width: 768px) {
      .topbar-links a.topbar-icon-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.25rem -0.45rem -0.5rem;
      }
    }
    .topbar-titleline { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; min-width: 0; }
    .topbar-actions { flex: 0 0 auto; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.4rem 0.6rem; text-align: left; }
    .label { color: var(--entry-label, #8b949e); width: 40%; }
    td.value { background: var(--entry-field-bg-edit, #161b22); border-radius: 6px; }
    @media (max-width: 768px) {
      table.elenko-entry-fields-table,
      table.elenko-entry-fields-table tbody {
        display: block;
        width: 100%;
      }
      table.elenko-entry-fields-table tr {
        display: block;
        width: 100%;
        margin-bottom: 1.1rem;
      }
      table.elenko-entry-fields-table tr:last-child {
        margin-bottom: 0;
      }
      table.elenko-entry-fields-table td {
        display: block;
        width: 100% !important;
        max-width: 100%;
        box-sizing: border-box;
        border: none;
        padding-left: 0;
        padding-right: 0;
      }
      table.elenko-entry-fields-table td.label {
        width: 100% !important;
        padding-top: 0;
        padding-bottom: 0.3rem;
      }
      table.elenko-entry-fields-table td.value {
        padding: 0.5rem 0.65rem;
      }
      table.elenko-entry-fields-table tr.entry-label-row td {
        padding: 0.55rem 0;
        margin-bottom: 0.35rem;
        border-bottom: 1px solid #30363d;
      }
    }
    .entry-view-stack { --entry-stack-field-max-height: 12rem; }
    .entry-view-stack .entry-field-block { margin-bottom: 1rem; min-width: 0; max-width: 100%; }
    .entry-view-stack .entry-field-block .value {
      min-width: 0;
      background: var(--entry-field-bg-edit, #161b22);
      border-radius: 6px;
      padding: 0.4rem 0.6rem;
    }
    .entry-view-stack .label { display: block; margin-bottom: 0.25rem; }
    .entry-view-stack .entry-label-only .label { white-space: nowrap; }
    .entry-view-stack textarea.entry-field-textarea {
      min-height: 1.75rem;
      height: 1.75rem;
      max-height: none;
      resize: vertical;
      overflow-y: auto;
      box-sizing: border-box;
    }
    textarea.entry-field-chart-json { font-family: ui-monospace, "Cascadia Code", "Consolas", monospace; font-size: 0.8rem; line-height: 1.35; min-height: 8rem; }
    .entry-repeat-wrap { width: 100%; min-width: 0; }
    .entry-repeat-edit-table { width: 100%; border-collapse: collapse; }
    .entry-repeat-edit-table th, .entry-repeat-edit-table td { border: 1px solid #30363d; padding: 0.35rem; vertical-align: top; }
    .entry-repeat-edit-table th { color: var(--entry-label, #8b949e); font-size: 0.8rem; font-weight: 600; }
    .entry-repeat-cell, .entry-repeat-cell-textarea { width: 100%; min-width: 6rem; box-sizing: border-box; padding: 0.35rem 0.5rem; background: var(--entry-field-bg-edit, #0d1117); border: 1px solid #30363d; border-radius: 4px; color: var(--entry-text-edit, #e6edf3); font: inherit; }
    .entry-repeat-cell-textarea { min-height: 2.5rem; resize: vertical; }
    .entry-repeat-cell-markdown { min-height: 6rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.875rem; line-height: 1.4; }
    .entry-repeat-stack-row { border: 1px solid #30363d; border-radius: 6px; padding: 0.5rem 0.65rem; margin-bottom: 0.5rem; }
    .entry-repeat-stack-row-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem; color: var(--entry-label, #8b949e); font-size: 0.8rem; }
    .entry-repeat-stack-edit-field { display: block; margin-top: 0.35rem; }
    .entry-repeat-actions { margin-top: 0.5rem; }
    .entry-view-grid { display: grid; gap: 1rem; }
    .entry-grid-cell { min-width: 0; }
    .entry-grid-cell .label { display: block; margin-bottom: 0.25rem; color: var(--entry-label, #8b949e); }
    .entry-grid-cell .value { min-width: 0; overflow: hidden; background: var(--entry-field-bg-edit, #161b22); border-radius: 6px; padding: 0.4rem 0.6rem; }
    .entry-grid-cell.entry-label-only .label { white-space: nowrap; }
    .entry-label-row .label { white-space: nowrap; }
    td.value { min-width: 0; overflow: hidden; }
    /* Image preview: avoid flex stretch + overflow clipping that distorts aspect ratio (view page does not use this flex wrapper). */
    .entry-image-edit-wrap {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      min-width: 0;
      width: 100%;
      align-items: flex-start;
      box-sizing: border-box;
    }
    .entry-image-preview {
      max-width: 100%;
      width: auto;
      height: auto;
      max-height: 24rem;
      object-fit: contain;
      object-position: left top;
      border-radius: 6px;
      display: block;
      flex-shrink: 0;
    }
    .entry-grid-cell .value.entry-grid-image-height .entry-image-edit-wrap {
      flex: 1 1 auto;
      min-height: 0;
      max-height: 100%;
      width: 100%;
      overflow: auto;
    }
    .entry-grid-cell .value.entry-grid-image-height .entry-image-preview {
      max-height: 100%;
      flex-shrink: 1;
    }
    .entry-view-stack .entry-field-block .value.entry-grid-image-height .entry-image-edit-wrap {
      flex: 1 1 auto;
      min-height: 0;
      max-height: 100%;
      width: 100%;
      overflow: auto;
    }
    .entry-view-stack .entry-field-block .value.entry-grid-image-height .entry-image-preview {
      max-height: 100%;
      flex-shrink: 1;
    }
    .entry-view-stack .entry-field-block .value:has(.entry-image-edit-wrap),
    .entry-grid-cell .value:has(.entry-image-edit-wrap),
    td.value:has(.entry-image-edit-wrap) {
      overflow: visible;
    }
    .entry-image-none { color: var(--entry-label, #8b949e); font-size: 0.875rem; }
    .entry-image-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
    .entry-image-file {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
    /* Scoped + !important so entry form customCss cannot strip button chrome */
    form#entry-form button.entry-image-import-btn {
      appearance: auto;
      -webkit-appearance: button;
      font: inherit;
      display: inline-block;
      max-width: 100%;
      text-align: inherit;
      padding: 0.35rem 0.5rem;
      margin: 0;
      background: var(--entry-field-bg-edit, #161b22) !important;
      color: var(--entry-link, #58a6ff) !important;
      border: 1px solid #30363d !important;
      border-radius: 4px;
      cursor: pointer;
      box-sizing: border-box;
    }
    form#entry-form button.entry-image-import-btn:hover {
      border-color: var(--entry-link, #58a6ff) !important;
    }
    form#entry-form .entry-view-stack button.entry-image-import-btn,
    form#entry-form .entry-view-grid button.entry-image-import-btn {
      width: 100%;
    }
    .entry-image-upload-status { font-size: 0.8rem; color: var(--entry-label, #8b949e); min-height: 1em; }
    input.entry-field, textarea.entry-field { width: 100%; min-width: 0; max-width: 100%; padding: 0.35rem 0.45rem; background: var(--entry-field-bg-edit, #161b22); color: var(--entry-text-edit, #e6edf3); border: 1px solid transparent; border-radius: 4px; font-size: 0.95rem; box-sizing: border-box; }
    input.entry-field:focus, textarea.entry-field:focus { outline: none; border-color: var(--entry-link, #58a6ff); }
    textarea.entry-field-textarea { resize: vertical; min-height: 1.75rem; line-height: 1.25; white-space: pre-wrap; overflow-wrap: break-word; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.45rem 0.8rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
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
  <div class="topbar">
    <div class="topbar-main">
      <div class="topbar-links"><a href="${escapeHtml(viewUrl)}" class="topbar-icon-btn" title="Back to entry" aria-label="Back to entry">◀</a></div>
      <div class="topbar-titleline">
        <h1>${title}</h1>
        <span class="sub">Edit entry</span>
      </div>
      ${formChoicesHtml}
    </div>
    <div class="topbar-actions">
      <button type="submit" form="entry-form" class="btn">Save</button>
      <button type="button" class="btn btn-delete" id="delete-entry-btn">Delete</button>
      <a href="${escapeHtml(cancelHref)}" class="btn btn-secondary" id="edit-cancel-btn"${discardOnCancel ? " data-abandon-draft=\"1\"" : ""}>Cancel</a>
    </div>
  </div>
  <form id="entry-form">
    <input type="hidden" id="rev" value="${rev}">
    ${contentHtml}
  <div id="msg"></div>
  <script>
    const profileId = ${JSON.stringify(profileId)};
    const entryId = ${JSON.stringify(entryId)};
    const abandonDraftQs = ${JSON.stringify(returnQueryStr)};
    const maxImageEdge = ${MAX_IMAGE_DISPLAY_EDGE};
    const orderedFieldNames = ${orderedFieldNamesJson};
    const entryFormSelect = document.getElementById('entryFormSelect');
    const form = document.getElementById('entry-form');
    const msgEl = document.getElementById('msg');
    function syncEntryImagePreview(wrap) {
      if (!wrap) return;
      const hidden = wrap.querySelector('.entry-image-filename');
      const v = hidden && hidden.value ? String(hidden.value).trim() : '';
      if (wrap.getAttribute('data-profile-file') === '1') {
        const none = wrap.querySelector('.entry-image-none');
        const dl = wrap.querySelector('.entry-profile-file-dl');
        if (dl) {
          if (v) {
            dl.href = '/api/profiles/' + encodeURIComponent(profileId) + '/entries/' + encodeURIComponent(entryId) + '/attachments/' + encodeURIComponent(v);
            dl.textContent = v;
            dl.style.display = '';
          } else {
            dl.removeAttribute('href');
            dl.textContent = '';
            dl.style.display = 'none';
          }
        }
        if (none) none.style.display = v ? 'none' : '';
        return;
      }
      const img = wrap.querySelector('.entry-image-preview');
      const none = wrap.querySelector('.entry-image-none');
      if (v && img) {
        img.src = '/api/profiles/' + encodeURIComponent(profileId) + '/entries/' + encodeURIComponent(entryId) + '/attachments/' + encodeURIComponent(v) + '?max=' + maxImageEdge + '&t=' + Date.now();
        img.style.display = '';
        if (none) none.style.display = 'none';
      } else {
        if (img) { img.removeAttribute('src'); img.style.display = 'none'; }
        if (none) none.style.display = '';
      }
    }
    form.querySelectorAll('.entry-image-edit-wrap').forEach((w) => syncEntryImagePreview(w));
    form.querySelectorAll('.entry-image-import-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const row = btn.closest('tr, .entry-field-block, .entry-grid-cell');
        const file = row && row.querySelector('.entry-image-file');
        if (file) file.click();
      });
    });
    form.querySelectorAll('.entry-image-file').forEach((fileEl) => {
      fileEl.addEventListener('change', async () => {
        const f = fileEl.files && fileEl.files[0];
        const wrap = fileEl.closest('.entry-image-edit-wrap');
        const hidden = wrap && wrap.querySelector('.entry-image-filename');
        const status = wrap && wrap.querySelector('.entry-image-upload-status');
        if (!wrap || !hidden || !hidden.name) { if (fileEl) fileEl.value = ''; return; }
        if (!f) return;
        if (status) { status.textContent = 'Uploading…'; status.style.color = ''; }
        const fd = new FormData();
        fd.append('file', f);
        fd.append('fieldName', hidden.name);
        try {
          const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/entries/' + encodeURIComponent(entryId) + '/attachments', {
            method: 'POST',
            body: fd,
            credentials: 'same-origin',
          });
          const ct = (r.headers.get('content-type') || '').toLowerCase();
          let result = {};
          if (ct.includes('application/json')) {
            try {
              result = await r.json();
            } catch (parseErr) {
              if (status) { status.textContent = 'Invalid JSON response (HTTP ' + r.status + ')'; status.style.color = '#f85149'; }
              fileEl.value = '';
              return;
            }
          } else {
            const text = await r.text();
            if (status) {
              status.textContent = !r.ok
                ? ('HTTP ' + r.status + ': ' + (text.slice(0, 120) || 'non-JSON response'))
                : text.slice(0, 120);
              status.style.color = '#f85149';
            }
            fileEl.value = '';
            return;
          }
          if (!r.ok) {
            if (status) { status.textContent = result.error || 'Upload failed'; status.style.color = '#f85149'; }
            fileEl.value = '';
            return;
          }
          if (result.filename) hidden.value = result.filename;
          if (result.rev) document.getElementById('rev').value = result.rev;
          syncEntryImagePreview(wrap);
          if (status) { status.textContent = 'Uploaded.'; status.style.color = '#3fb950'; }
        } catch (e) {
          if (status) { status.textContent = e.message || 'Upload failed'; status.style.color = '#f85149'; }
        }
        fileEl.value = '';
      });
    });
    form.querySelectorAll('.entry-image-clear').forEach((btn) => {
      btn.addEventListener('click', () => {
        const wrap = btn.closest('.entry-image-edit-wrap');
        const hidden = wrap && wrap.querySelector('.entry-image-filename');
        const fileEl = wrap && wrap.querySelector('.entry-image-file');
        const status = wrap && wrap.querySelector('.entry-image-upload-status');
        if (hidden) hidden.value = '';
        if (fileEl) fileEl.value = '';
        syncEntryImagePreview(wrap);
        if (status) { status.textContent = ''; status.style.color = ''; }
      });
    });
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

    function parseRepeatColumnsJson(raw) {
      try {
        const cols = JSON.parse(String(raw || '[]'));
        return Array.isArray(cols) ? cols : [];
      } catch (_) {
        return [];
      }
    }

    function syncRepeatWrap(wrap) {
      if (!wrap) return;
      const columns = parseRepeatColumnsJson(wrap.getAttribute('data-repeat-columns') || '[]');
      const rows = [];
      wrap.querySelectorAll('.entry-repeat-row').forEach((rowEl) => {
        const row = {};
        rowEl.querySelectorAll('.entry-repeat-cell').forEach((cell) => {
          const key = cell.getAttribute('data-col-key');
          if (!key) return;
          row[key] = cell && typeof cell.value === 'string' ? cell.value : '';
        });
        columns.forEach((c) => {
          const key = c && c.key ? String(c.key) : '';
          if (key && row[key] == null) row[key] = '';
        });
        rows.push(row);
      });
      const isGroup = wrap.getAttribute('data-repeat-group') === '1';
      if (isGroup) {
        columns.forEach(function(c) {
          const key = c && c.key ? String(c.key) : '';
          if (!key) return;
          const hidden = wrap.querySelector('.entry-repeat-field-json[data-repeat-field="' + key + '"]');
          if (!hidden) return;
          const colRows = rows.map(function(r) { return r[key] != null ? String(r[key]) : ''; });
          hidden.value = JSON.stringify({ version: 1, rows: colRows });
        });
        return;
      }
      const hidden = wrap.querySelector('.entry-repeat-json');
      if (!hidden) return;
      hidden.value = JSON.stringify({ version: 1, rows: rows });
    }

    function bindRepeatRow(wrap, rowEl) {
      if (!wrap || !rowEl) return;
      rowEl.querySelectorAll('.entry-repeat-cell').forEach((cell) => {
        autoResizeRepeatCell(cell);
        cell.addEventListener('input', function() {
          autoResizeRepeatCell(cell);
          syncRepeatWrap(wrap);
        });
      });
      const removeBtn = rowEl.querySelector('.entry-repeat-remove');
      if (removeBtn) {
        removeBtn.addEventListener('click', function() {
          rowEl.remove();
          syncRepeatWrap(wrap);
        });
      }
    }

    function repeatCellInputHtml(c, val) {
      const key = c && c.key ? String(c.key) : '';
      const safeVal = String(val != null ? val : '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
      if (c && c.fieldType === 'url') {
        return '<input type="url" class="entry-repeat-cell" data-col-key="' + key + '" data-col-type="url" value="' + safeVal + '">';
      }
      if (c && c.fieldType === 'markdown') {
        return '<textarea class="entry-repeat-cell entry-repeat-cell-textarea entry-repeat-cell-markdown" data-col-key="' + key + '" data-col-type="markdown" rows="6" spellcheck="false">' + safeVal + '</textarea>';
      }
      return '<textarea class="entry-repeat-cell entry-repeat-cell-textarea" data-col-key="' + key + '" data-col-type="text" rows="2">' + safeVal + '</textarea>';
    }

    function autoResizeRepeatCell(el) {
      if (!el || el.tagName !== 'TEXTAREA') return;
      el.style.height = 'auto';
      el.style.height = Math.max(el.scrollHeight, el.classList.contains('entry-repeat-cell-markdown') ? 96 : 40) + 'px';
    }

    function buildRepeatRowHtml(wrap, rowData) {
      const mode = wrap.getAttribute('data-repeat-mode') || 'table';
      const columns = parseRepeatColumnsJson(wrap.getAttribute('data-repeat-columns') || '[]');
      const row = rowData && typeof rowData === 'object' ? rowData : {};
      const idx = wrap.querySelectorAll('.entry-repeat-row').length;
      if (mode === 'stack') {
        const fields = columns.map(function(c) {
          const key = c && c.key ? String(c.key) : '';
          const label = c && c.label ? String(c.label) : key;
          const val = row[key] != null ? String(row[key]) : '';
          return '<label class="entry-repeat-stack-edit-field"><span class="entry-repeat-col-label">' + label + '</span>' + repeatCellInputHtml(c, val) + '</label>';
        }).join('');
        const div = document.createElement('div');
        div.className = 'entry-repeat-row entry-repeat-stack-row';
        div.setAttribute('data-row-index', String(idx));
        div.innerHTML = '<div class="entry-repeat-stack-row-head"><span>#' + (idx + 1) + '</span><button type="button" class="btn btn-secondary entry-repeat-remove">Remove</button></div>' + fields;
        return div;
      }
      const tds = columns.map(function(c) {
        const key = c && c.key ? String(c.key) : '';
        const val = row[key] != null ? String(row[key]) : '';
        return '<td>' + repeatCellInputHtml(c, val) + '</td>';
      }).join('');
      const tr = document.createElement('tr');
      tr.className = 'entry-repeat-row';
      tr.setAttribute('data-row-index', String(idx));
      tr.innerHTML = tds + '<td><button type="button" class="btn btn-secondary entry-repeat-remove">Remove</button></td>';
      return tr;
    }

    function initRepeatFields() {
      form.querySelectorAll('.entry-repeat-wrap').forEach(function(wrap) {
        wrap.querySelectorAll('.entry-repeat-row').forEach(function(rowEl) { bindRepeatRow(wrap, rowEl); });
        const addBtn = wrap.querySelector('.entry-repeat-add');
        if (addBtn) {
          addBtn.addEventListener('click', function() {
            const mode = wrap.getAttribute('data-repeat-mode') || 'table';
            const rowEl = buildRepeatRowHtml(wrap, {});
            if (mode === 'stack') {
              const body = wrap.querySelector('.entry-repeat-body');
              if (body) body.appendChild(rowEl);
            } else {
              const tbody = wrap.querySelector('.entry-repeat-tbody');
              if (tbody) tbody.appendChild(rowEl);
            }
            bindRepeatRow(wrap, rowEl);
            syncRepeatWrap(wrap);
          });
        }
        syncRepeatWrap(wrap);
      });
    }
    initRepeatFields();

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const data = { _rev: document.getElementById('rev').value };
      if (entryFormSelect) {
        data.entryFormId = entryFormSelect.value;
      }
      form.querySelectorAll('.entry-repeat-wrap').forEach(function(wrap) { syncRepeatWrap(wrap); });
      orderedFieldNames.forEach((fn) => {
        const el = form.elements.namedItem(fn);
        const raw = el && typeof el.value === 'string' ? el.value : (el && el.value != null ? String(el.value) : '');
        data[fn] = raw.trim();
      });
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
        setTimeout(() => { window.location.href = ${JSON.stringify(viewUrl)}; }, 800);
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

    const cancelBtn = document.getElementById('edit-cancel-btn');
    if (cancelBtn && cancelBtn.getAttribute('data-abandon-draft') === '1') {
      cancelBtn.addEventListener('click', async function (e) {
        e.preventDefault();
        try {
          const u =
            '/api/profiles/' +
            encodeURIComponent(profileId) +
            '/entries/' +
            encodeURIComponent(entryId) +
            '/abandon-draft' +
            (abandonDraftQs || '');
          const r = await fetch(u, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: '{}',
          });
          const result = await r.json().catch(function () {
            return {};
          });
          if (r.ok && result.redirect) {
            window.location.href = result.redirect;
            return;
          }
          if (r.status === 400) {
            window.location.href = ${JSON.stringify(backUrl)};
            return;
          }
          msgEl.textContent = result.error || 'Could not discard draft';
          msgEl.className = 'msg err';
        } catch (err) {
          msgEl.textContent = err.message || 'Request failed';
          msgEl.className = 'msg err';
        }
      });
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
  const {
    page = 1,
    totalPages = null,
    hasNext = false,
    hasPrev = false,
    searchQuery = "",
    encryptionLock = null,
    encryptionEnabled = false,
    encryptionOwner = "",
  } = pagination;
  const profileBase = "/profile/" + encodeURIComponent(doc._id);
  const encryptionBanner = encryptionLock
    ? `<div class="encryption-notice" style="margin:0.75rem 0;padding:0.75rem 1rem;border:1px solid var(--profile-table-border, #30363d);border-radius:8px;background:var(--profile-table-header-bg, #21262d);color:var(--profile-text, #e6edf3);">
        <strong>Encrypted database.</strong> ${escapeHtml(encryptionLock.error || "Access denied.")}
        ${encryptionLock.needKeyUnlock ? ' <a href="/account/unlock-keyfile">Unlock key file</a>' : ""}
      </div>`
    : encryptionEnabled
      ? `<div class="encryption-notice" style="margin:0.75rem 0;padding:0.5rem 0.75rem;border:1px solid var(--profile-table-border, #30363d);border-radius:8px;color:var(--profile-label, #8b949e);font-size:0.875rem;">
          Encrypted for personal use${encryptionOwner ? ` (${escapeHtml(encryptionOwner)})` : ""}. Search and sort run in memory after decryption.
        </div>`
      : "";
  const qParam = searchQuery ? "&q=" + encodeURIComponent(searchQuery) : "";
  const prevUrl = hasPrev ? profileBase + "?page=" + (page - 1) + qParam : null;
  const nextUrl = hasNext ? profileBase + "?page=" + (page + 1) + qParam : null;
  const firstUrl = page > 1 ? profileBase + "?page=1" + qParam : null;
  const lastUrl = totalPages != null && page < totalPages ? profileBase + "?page=" + totalPages + qParam : null;
  const pageOfTotal = totalPages != null ? " of " + totalPages : "";
  const infoImportFlowId =
    typeof doc.infoImportFlowId === "string" && doc.infoImportFlowId.trim()
      ? doc.infoImportFlowId.trim()
      : (typeof doc.guardianFlowId === "string" && doc.guardianFlowId.trim() ? doc.guardianFlowId.trim() : "");
  const infoImportButtonTitle =
    typeof doc.infoImportButtonTitle === "string" && doc.infoImportButtonTitle.trim()
      ? doc.infoImportButtonTitle.trim()
      : "Import from Guardian";
  const splitViewCfg = doc && doc.splitView && typeof doc.splitView === "object" ? doc.splitView : null;
  const splitViewEnabled = !!(splitViewCfg && splitViewCfg.enabled);
  const splitViewOrientation = splitViewCfg && splitViewCfg.orientation === "horizontal" ? "horizontal" : "vertical";

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
            let text = summarizeRepeatFieldValueForList(doc, fn, val);
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
            const responseMarker =
              colIdx === 0 && rec && rec.isResponse === true
                ? '<span class="response-row-marker" title="Response" aria-label="Response">↳</span>'
                : "";

            if (isDesktopLink && isMobileLink) {
              return `<td class="entry-link-cell${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp">${responseMarker}<a class="entry-open-link" data-entry-id="${escapeHtml(rec._id || "")}" href="${entryUrl}">${linkText}</a></span></td>`;
            }
            if (isDesktopLink && !isMobileLink) {
              return `<td class="entry-link-cell${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp">${responseMarker}<span class="entry-link-desktop-only"><a class="entry-open-link" data-entry-id="${escapeHtml(rec._id || "")}" href="${entryUrl}">${linkText}</a></span><span class="entry-plain-mobile-only">${escaped}</span></span></td>`;
            }
            if (!isDesktopLink && isMobileLink) {
              return `<td class="entry-link-cell${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp">${responseMarker}<span class="entry-plain-desktop-only">${escaped}</span><span class="entry-link-mobile-only"><a class="entry-open-link" data-entry-id="${escapeHtml(rec._id || "")}" href="${entryUrl}">${linkText}</a></span></span></td>`;
            }
            return `<td class="${mobileCls}${deskCls}${dispCls}"${styleAttr}><span class="entry-cell-clamp">${responseMarker}${escaped}</span></td>`;
          });
          return `\n        <tr class="entry-row" data-entry-id="${escapeHtml(rec._id || "")}">${cells.join("")}</tr>`;
        })
      : [];

  const emptyRow =
    fieldNames.length > 0 && records.length === 0
      ? '\n        <tr><td colspan="' +
        fieldNames.length +
        '" class="empty">' +
        (encryptionLock
          ? escapeHtml(encryptionLock.error || "This encrypted database is locked.")
          : searchQuery
            ? "No entries match your search."
            : "No entries yet.") +
        "</td></tr>"
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
    body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem 1.25rem; background: var(--profile-bg, #0f1419); color: var(--profile-text, #e6edf3); min-height: 100vh; }
    h1 { font-weight: 600; margin: 0; font-size: 1.25rem; line-height: 1.2; }
    .sub { color: var(--profile-label, #8b949e); margin: 0; }
    .topbar { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.75rem; }
    .topbar-main { min-width: 0; flex: 1 1 auto; display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; }
    .topbar-links { margin: 0; display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; }
    .topbar-links a { color: var(--profile-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .topbar-links a:hover { text-decoration: underline; }
    .topbar-links a.topbar-icon-btn {
      display: inline-block;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      line-height: 1;
      border: 1px solid var(--profile-table-border, #21262d);
      background: var(--profile-table-header-bg, #21262d);
      color: var(--profile-link, #58a6ff);
      text-decoration: none;
      box-sizing: border-box;
      margin-right: 0.75rem;
    }
    .topbar-links a.topbar-icon-btn:hover { text-decoration: none; background: #30363d; color: var(--profile-link, #58a6ff); }
    .topbar-titleline { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem; min-width: 0; }
    .topbar-actions { flex: 0 0 auto; display: flex; align-items: flex-start; justify-content: flex-end; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.35rem 0.75rem; border-radius: 6px; text-decoration: none; font-size: 0.9rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    table.elenko-db-table { width: 100%; border-collapse: collapse; background: var(--profile-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.35rem 1rem; text-align: left; border-bottom: 1px solid var(--profile-table-border, #21262d); line-height: 1.35; }
    th { background: var(--profile-table-header-bg, #21262d); color: var(--profile-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .entry-cell-clamp { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; word-break: break-word; }
    .response-row-marker { display: inline-block; color: var(--profile-label, #8b949e); margin-right: 0.35rem; font-weight: 600; }
    .entry-link-cell a { color: var(--profile-link, #58a6ff); text-decoration: none; }
    .entry-link-cell a:hover { text-decoration: underline; }
    .empty { color: var(--profile-label, #8b949e); font-style: italic; }
    .top-tools { margin-bottom: 0.75rem; display: flex; flex-wrap: nowrap; gap: 0.75rem; align-items: center; }
    .search-bar { margin: 0; display: flex; flex-wrap: nowrap; gap: 0.5rem; align-items: center; flex: 1 1 45%; min-width: 0; }
    .search-bar input[type="search"] { padding: 0.5rem 0.75rem; background: var(--profile-table-bg, #161b22); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; color: var(--profile-text, #e6edf3); font-size: 1rem; min-width: 10rem; flex: 1 1 auto; }
    .search-bar input[type="search"]:focus { outline: none; border-color: var(--profile-link, #58a6ff); }
    .search-bar .btn-search { padding: 0.5rem 0.75rem; background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
    .search-bar .btn-search:hover { background: #30363d; }
    .search-bar .btn-clear { padding: 0.5rem 0.75rem; background: transparent; color: var(--profile-label, #8b949e); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .search-bar .btn-clear:hover { background: #30363d; color: var(--profile-text, #e6edf3); }
    .pagination { margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
    .pagination .btn-pag { display: inline-block; padding: 0.5rem 0.75rem; border-radius: 6px; text-decoration: none; font-size: 0.875rem; }
    .pagination .btn-pag-prev, .pagination .btn-pag-next { background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); }
    .pagination .btn-pag-first, .pagination .btn-pag-last, .pagination .btn-pag-row { background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); border: 1px solid var(--profile-table-border, #21262d); cursor: pointer; }
    .pagination .btn-pag-prev:hover, .pagination .btn-pag-next:hover { background: #30363d; }
    .pagination .btn-pag-first:hover, .pagination .btn-pag-last:hover, .pagination .btn-pag-row:hover { background: #30363d; }
    .pagination .btn-pag-row:disabled { color: #484f58; cursor: not-allowed; background: var(--profile-table-header-bg, #21262d); }
    .pagination .btn-pag.disabled { color: #484f58; pointer-events: none; }
    .pagination .page-num { color: var(--profile-label, #8b949e); font-size: 0.875rem; }
    th.col-bodytext, td.col-bodytext { max-width: 50vw; width: 50%; }
    th.col-bodytext.col-disp-pct, td.col-bodytext.col-disp-pct { max-width: none; }
    .guardian-import { margin: 0; display: flex; gap: 0.5rem; align-items: center; flex-wrap: nowrap; flex: 1 1 55%; min-width: 0; }
    .guardian-import input[type="text"] { padding: 0.5rem 0.75rem; background: var(--profile-table-bg, #161b22); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; color: var(--profile-text, #e6edf3); font-size: 1rem; min-width: 10rem; max-width: 100%; box-sizing: border-box; flex: 1 1 auto; }
    @media (min-width: 769px) {
      .top-tools { flex-wrap: nowrap; }
      .guardian-import label { white-space: nowrap; }
    }
    .guardian-import button { padding: 0.4rem 0.75rem; background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
    .guardian-import button:hover { background: #30363d; }
    .guardian-import .guardian-msg { font-size: 0.875rem; color: var(--profile-label, #8b949e); }
    .guardian-import .guardian-msg.err { color: #f85149; }
    .guardian-import .guardian-msg.ok { color: #3fb950; }
    .split-view-wrap { display: flex; gap: 0.75rem; min-height: 65vh; align-items: stretch; }
    .split-view-wrap.split-vertical { flex-direction: row; }
    .split-view-wrap.split-horizontal { flex-direction: column; height: 68vh; min-height: 28rem; }
    .split-list-pane { background: transparent; min-width: 0; min-height: 0; flex: 1 1 50%; }
    .split-entry-pane { border: 1px solid var(--profile-table-border, #21262d); border-radius: 8px; background: var(--profile-table-bg, #161b22); min-width: 0; min-height: 0; flex: 1 1 50%; overflow: hidden; }
    .split-entry-frame { width: 100%; height: 100%; min-height: 18rem; border: 0; background: #fff; }
    .split-entry-empty { color: var(--profile-label, #8b949e); padding: 1rem; }
    .split-divider { border-radius: 6px; background: var(--profile-table-border, #21262d); opacity: 0.9; user-select: none; touch-action: none; }
    .split-view-wrap.split-vertical .split-divider { width: 0.45rem; cursor: col-resize; }
    .split-view-wrap.split-horizontal .split-divider { height: 0.45rem; cursor: row-resize; }
    .split-view-wrap.split-vertical .split-list-pane, .split-view-wrap.split-vertical .split-entry-pane { min-height: 65vh; }
    .split-view-wrap.split-horizontal .split-list-pane, .split-view-wrap.split-horizontal .split-entry-pane { min-height: 0; }
    .split-view-wrap.split-horizontal .split-list-pane { overflow: auto; }
    .entry-row.selected td { background: rgba(88, 166, 255, 0.12); }
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
      .top-tools { flex-direction: column; align-items: stretch; gap: 0.5rem; }
      .search-bar, .guardian-import { flex: 1 1 auto; width: 100%; }
      .search-bar { flex-wrap: wrap; }
      .guardian-import { flex-wrap: wrap; }
      /* On phones, always fall back to plain list mode even if split is configured. */
      .split-view-wrap { display: block; height: auto !important; min-height: 0; }
      .split-entry-pane, .split-divider { display: none !important; }
      .split-list-pane { flex: 0 0 auto; min-height: 0; overflow: visible !important; }
      /* Row prev/next tie into split single-entry navigation; hide on phones. */
      .pagination .btn-pag-row { display: none !important; }
      .topbar-links a.topbar-icon-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem -0.5rem;
      }
      th.col-mobile-hidden,
      td.col-mobile-hidden { display: none; }
      .entry-link-desktop-only { display: none; }
      .entry-plain-mobile-only { display: inline; }
      .entry-plain-desktop-only { display: none; }
      .entry-link-mobile-only { display: inline; }
      /* Show desktop-hidden columns on narrow screens only when they are in the mobile list (not col-mobile-hidden). */
      th.col-desktop-hidden:not(.col-mobile-hidden),
      td.col-desktop-hidden:not(.col-mobile-hidden) { display: table-cell !important; }
    }
  </style>
  ${customCss ? `<style>${customCss}</style>` : ""}
</head>
<body>
  <div class="topbar">
    <div class="topbar-main">
      <div class="topbar-links"><a href="/" class="topbar-icon-btn" title="Profiles" aria-label="Profiles">◀</a>${canEdit && isAdmin ? `<a href="/profile/${encodeURIComponent(doc._id)}/edit">Edit profile</a>` : ""}</div>
      <div class="topbar-titleline">
        <h1>${title}</h1>
        ${description ? `<span class="sub">${description}</span>` : ""}
      </div>
    </div>
    <div class="topbar-actions">${canEdit && !encryptionLock ? `<a href="/profile/${encodeURIComponent(doc._id)}/entry/new" class="btn">Create entry</a>` : ""}</div>
  </div>
  ${encryptionBanner}
  ${splitViewEnabled && splitViewOrientation !== "horizontal" ? `<div class="split-view-wrap split-${splitViewOrientation}" data-orientation="${splitViewOrientation}"><div class="split-list-pane">` : ""}
  <div class="top-tools">
    <form method="get" action="${profileBase}" class="search-bar">
      <input type="search" name="q" value="${escapeHtml(searchQuery)}" placeholder="Search entries…" aria-label="Search entries">
      <input type="hidden" name="page" value="1">
      <button type="submit" class="btn-search">Search</button>
      ${searchQuery ? `<a href="${profileBase}?clearSearch=1" class="btn-clear">Clear</a>` : ""}
    </form>
    ${canEdit && infoImportFlowId ? `<form id="info-import-form" class="guardian-import"><label for="info-import-query" style="margin:0;color:var(--profile-label, #8b949e);">Query:</label><input type="text" id="info-import-query" placeholder="e.g. renewable energy"><button type="submit">${escapeHtml(infoImportButtonTitle)}</button><span id="info-import-msg" class="guardian-msg"></span></form>` : ""}
  </div>
  <div class="pagination">
    ${firstUrl ? `<a href="${firstUrl}" class="btn-pag btn-pag-first">|◀</a>` : `<span class="btn-pag btn-pag-first disabled">|◀</span>`}
    ${hasPrev ? `<a href="${prevUrl}" class="btn-pag btn-pag-prev">◀◀</a>` : `<span class="btn-pag btn-pag-prev disabled">◀◀</span>`}
    <button type="button" class="btn-pag btn-pag-row" id="btn-prev-row">◀</button>
    <span class="page-num">Page ${escapeHtml(String(page))}${escapeHtml(pageOfTotal)}</span>
    <button type="button" class="btn-pag btn-pag-row" id="btn-next-row">▶</button>
    ${hasNext ? `<a href="${nextUrl}" class="btn-pag btn-pag-next">▶▶</a>` : `<span class="btn-pag btn-pag-next disabled">▶▶</span>`}
    ${lastUrl ? `<a href="${lastUrl}" class="btn-pag btn-pag-last">▶|</a>` : `<span class="btn-pag btn-pag-last disabled">▶|</span>`}
  </div>
  ${
    splitViewEnabled && splitViewOrientation === "horizontal"
      ? `<div class="split-view-wrap split-horizontal" data-orientation="horizontal"><div class="split-entry-pane"><iframe id="split-entry-frame" class="split-entry-frame" title="Selected entry view"></iframe><div id="split-entry-empty" class="split-entry-empty">Select an entry from the first-column link to open it here.</div></div><div class="split-divider" id="split-divider" aria-hidden="true"></div><div class="split-list-pane">`
      : ""
  }
  <table class="elenko-db-table">
    <thead>${headerRow}</thead>
    <tbody>${dataRows.join("")}${emptyRow}
    </tbody>
  </table>
  ${
    splitViewEnabled
      ? splitViewOrientation === "horizontal"
        ? `</div></div>`
        : `</div><div class="split-divider" id="split-divider" aria-hidden="true"></div><div class="split-entry-pane"><iframe id="split-entry-frame" class="split-entry-frame" title="Selected entry view"></iframe><div id="split-entry-empty" class="split-entry-empty">Select an entry from the first-column link to open it here.</div></div></div>`
      : ""
  }
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
  ${splitViewEnabled ? `<script>
    (function() {
      var wrap = document.querySelector('.split-view-wrap');
      var listPane = wrap ? wrap.querySelector('.split-list-pane') : null;
      var entryPane = wrap ? wrap.querySelector('.split-entry-pane') : null;
      var divider = document.getElementById('split-divider');
      var orientation = wrap ? (wrap.getAttribute('data-orientation') || 'vertical') : 'vertical';
      var ratioKey = 'elenko:splitRatio:' + ${JSON.stringify(String(doc._id || ""))} + ':' + orientation;
      var frame = document.getElementById('split-entry-frame');
      var empty = document.getElementById('split-entry-empty');
      if (!frame || !wrap || !listPane || !entryPane || !divider) return;
      if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return;
      function applyRatio(rawRatio) {
        var ratio = Number(rawRatio);
        if (!Number.isFinite(ratio)) ratio = 50;
        ratio = Math.max(20, Math.min(80, ratio));
        if (orientation === 'horizontal') {
          // Horizontal layout renders entry pane first (top), list pane second (bottom).
          // So the drag ratio maps directly to entryPane size.
          entryPane.style.flex = '0 0 ' + ratio + '%';
          listPane.style.flex = '1 1 ' + (100 - ratio) + '%';
        } else {
          listPane.style.flex = '0 0 ' + ratio + '%';
          entryPane.style.flex = '1 1 ' + (100 - ratio) + '%';
        }
        return ratio;
      }
      function loadStoredRatio() {
        try {
          var v = window.localStorage.getItem(ratioKey);
          if (v == null || v === '') return 50;
          return Number(v);
        } catch (_) {
          return 50;
        }
      }
      function saveRatio(ratio) {
        try { window.localStorage.setItem(ratioKey, String(ratio)); } catch (_) {}
      }
      function applyHorizontalViewportHeight() {
        if (orientation !== 'horizontal') return;
        var top = wrap.getBoundingClientRect().top;
        var bodyStyle = window.getComputedStyle(document.body);
        var padBottom = parseFloat(bodyStyle.paddingBottom || '0') || 0;
        var available = window.innerHeight - top - padBottom;
        var minHeightPx = 28 * 16;
        if (!Number.isFinite(available) || available <= 0) return;
        wrap.style.height = Math.max(minHeightPx, Math.floor(available)) + 'px';
      }
      applyHorizontalViewportHeight();
      var currentRatio = applyRatio(loadStoredRatio());
      function setSelected(entryId) {
        document.querySelectorAll('tr.entry-row.selected').forEach(function(tr) { tr.classList.remove('selected'); });
        if (!entryId) return;
        var rows = document.querySelectorAll('tr.entry-row');
        for (var i = 0; i < rows.length; i++) {
          if ((rows[i].getAttribute('data-entry-id') || '') === entryId) {
            rows[i].classList.add('selected');
            break;
          }
        }
      }
      function openInSplit(url, entryId) {
        if (!url) return;
        var splitUrl = url;
        if (splitUrl.indexOf('split=1') < 0) {
          splitUrl += (splitUrl.indexOf('?') >= 0 ? '&' : '?') + 'split=1';
        }
        frame.src = splitUrl;
        if (empty) empty.style.display = 'none';
        setSelected(entryId || '');
      }
      var dragging = false;
      function updateFromPointer(clientX, clientY) {
        if (!wrap) return;
        var rect = wrap.getBoundingClientRect();
        if (!rect || rect.width <= 0 || rect.height <= 0) return;
        var ratio = orientation === 'horizontal'
          ? ((clientY - rect.top) / rect.height) * 100
          : ((clientX - rect.left) / rect.width) * 100;
        currentRatio = applyRatio(ratio);
      }
      divider.addEventListener('pointerdown', function(ev) {
        dragging = true;
        divider.setPointerCapture(ev.pointerId);
        ev.preventDefault();
      });
      divider.addEventListener('pointermove', function(ev) {
        if (!dragging) return;
        updateFromPointer(ev.clientX, ev.clientY);
      });
      divider.addEventListener('pointerup', function() {
        if (!dragging) return;
        dragging = false;
        saveRatio(currentRatio);
      });
      divider.addEventListener('pointercancel', function() {
        if (!dragging) return;
        dragging = false;
        saveRatio(currentRatio);
      });
      window.addEventListener('resize', function() {
        applyHorizontalViewportHeight();
        applyRatio(currentRatio);
      });
      document.querySelectorAll('a.entry-open-link').forEach(function(a) {
        a.addEventListener('click', function(ev) {
          ev.preventDefault();
          openInSplit(a.getAttribute('href'), a.getAttribute('data-entry-id') || '');
        });
      });
      var first = document.querySelector('a.entry-open-link');
      if (first) openInSplit(first.getAttribute('href'), first.getAttribute('data-entry-id') || '');
    })();
  </script>` : ""}
  <script>
    (function() {
      var prevBtn = document.getElementById('btn-prev-row');
      var nextBtn = document.getElementById('btn-next-row');
      if (!prevBtn || !nextBtn) return;
      function getRows() {
        return Array.prototype.slice.call(document.querySelectorAll('tr.entry-row'));
      }
      function selectedRowIndex(rows) {
        for (var i = 0; i < rows.length; i++) {
          if (rows[i].classList.contains('selected')) return i;
        }
        return rows.length > 0 ? 0 : -1;
      }
      function refreshButtons() {
        var rows = getRows();
        var idx = selectedRowIndex(rows);
        prevBtn.disabled = !(rows.length > 0 && idx > 0);
        nextBtn.disabled = !(rows.length > 0 && idx >= 0 && idx < rows.length - 1);
      }
      function activateRowAt(index) {
        var rows = getRows();
        if (!rows.length) return;
        var idx = Math.max(0, Math.min(rows.length - 1, index));
        var row = rows[idx];
        var link = row ? row.querySelector('a.entry-open-link') : null;
        if (!link) return;
        link.click();
        setTimeout(refreshButtons, 0);
      }
      prevBtn.addEventListener('click', function() {
        var rows = getRows();
        var idx = selectedRowIndex(rows);
        if (idx > 0) activateRowAt(idx - 1);
      });
      nextBtn.addEventListener('click', function() {
        var rows = getRows();
        var idx = selectedRowIndex(rows);
        if (idx >= 0 && idx < rows.length - 1) activateRowAt(idx + 1);
      });
      document.querySelectorAll('a.entry-open-link').forEach(function(a) {
        a.addEventListener('click', function() { setTimeout(refreshButtons, 0); });
      });
      refreshButtons();
    })();
  </script>
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
          <td><a class="form-name-link" href="/entry-forms/${encodeURIComponent(f._id)}/edit">${escapeHtml(f.name || f._id)}</a></td>
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: var(--app-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--app-table-border, #21262d); }
    th { background: var(--app-table-header-bg, #21262d); color: var(--app-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .form-name-link { color: var(--app-link, #58a6ff); text-decoration: none; }
    .form-name-link:hover { text-decoration: underline; }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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

function renderTimersListPage(timers, appUi) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const truncate = (s, max) => (s && s.length > max ? s.slice(0, max) + "…" : s || "");
  const intervalLabel = (key) => TIMER_INTERVAL_LABEL[key] || key || "—";
  const activeLabel = (a) => (a === true || a === "true" ? "Active" : "Inactive");
  const rows =
    timers.length > 0
      ? timers
          .map(
            (t) => `
        <tr>
          <td><a href="/timers/${encodeURIComponent(t._id)}/edit">${escapeHtml(t.name || t._id)}</a></td>
          <td><code class="id-cell">${escapeHtml(truncate(t.flowId || "", 36))}</code></td>
          <td><code class="id-cell">${escapeHtml(truncate(t.profileId || "", 28))}</code></td>
          <td>${escapeHtml([t.startDate, t.startTime].filter(Boolean).join(" ") || "—")}</td>
          <td>${escapeHtml(intervalLabel(t.intervalKey))}</td>
          <td>${escapeHtml(activeLabel(t.active))}</td>
          <td class="row-actions"><a href="/timers/${encodeURIComponent(t._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="copy-btn icon-action timer-copy-btn" data-id="${escapeHtml(t._id)}" aria-label="Copy" title="Copy">⧉</button><button type="button" class="delete-btn icon-action delete-timer-btn" data-id="${escapeHtml(t._id)}" data-rev="${escapeHtml(t._rev || "")}" aria-label="Delete" title="Delete">✕</button></td>
        </tr>`
          )
          .join("")
      : `
        <tr>
          <td colspan="7" class="empty">No timers yet. Schedule a flow to run on a repeating interval.</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Timers</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 64rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .actions > a:first-of-type { font-size: 1.35rem; line-height: 1; }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
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
    .copy-btn { border: none; background: none; color: var(--app-label, #8b949e); font: inherit; cursor: pointer; }
    .copy-btn:hover { color: var(--app-link, #58a6ff); background: rgba(88, 166, 255, 0.08); }
    .copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .delete-btn { border: none; background: none; color: #f85149; font: inherit; cursor: pointer; padding: 0.2rem 0.35rem; }
    .delete-btn:hover { color: #ff7b72; background: rgba(248, 81, 73, 0.12); }
    .delete-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .empty { color: var(--app-label, #8b949e); font-style: italic; }
    .id-cell { font-size: 0.85em; color: var(--app-label, #8b949e); word-break: break-all; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Start</a><a href="/timers/create" class="btn">Create timer</a></div>
  <h1>Timers</h1>
  <p class="sub">Run a flow on a schedule. Start date and time use the server&apos;s local timezone. Toggle off to pause without deleting.</p>
  <table>
    <thead><tr><th>Name</th><th>Flow</th><th>Profile</th><th>Starts</th><th>Repeat</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="timer-list-msg" style="display:none;margin-top:0.75rem;font-size:0.875rem;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('timer-list-msg');
      function showErr(t) {
        if (!msgEl) return;
        msgEl.style.display = 'block';
        msgEl.style.color = '#f85149';
        msgEl.textContent = t || 'Request failed';
      }
      document.querySelectorAll('.timer-copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          if (!id) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/timers/' + encodeURIComponent(id) + '/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok && o.data.id) {
                window.location.href = '/timers/' + encodeURIComponent(o.data.id) + '/edit';
                return;
              }
              showErr(o.data && o.data.error ? o.data.error : 'Copy failed');
            })
            .catch(function(e) { btn.disabled = false; showErr(e.message || 'Copy failed'); });
        });
      });
      document.querySelectorAll('.delete-timer-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          var rev = btn.getAttribute('data-rev');
          if (!id || !rev) { showErr('Missing revision; refresh the page.'); return; }
          if (!confirm('Delete this timer?')) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/timers/' + encodeURIComponent(id) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev: rev })
          })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok) { window.location.href = o.data.redirect || '/timers'; return; }
              showErr(o.data && o.data.error ? o.data.error : 'Delete failed');
            })
            .catch(function(e) { btn.disabled = false; showErr(e.message || 'Delete failed'); });
        });
      });
    })();
  </script>
</body>
</html>`;
}

function renderEditTimerPage(doc, err, appUi, flows, profiles) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const nameVal =
    doc && typeof doc.name === "string" ? escapeHtml(doc.name) : "";
  const descVal =
    doc && typeof doc.description === "string" ? escapeHtml(doc.description) : "";
  const startDateVal = escapeHtml(
    (doc && doc.startDate && String(doc.startDate).trim()) || defaultTimerStartDateLocal()
  );
  const startTimeVal = escapeHtml(
    (doc && doc.startTime && String(doc.startTime).trim()) || defaultTimerStartTimeNextHourLocal()
  );
  const entryVal =
    doc && typeof doc.entryId === "string" ? escapeHtml(doc.entryId) : "";
  const paramVal =
    doc && typeof doc.param === "string" ? escapeHtml(doc.param) : "";
  const intervalKey = normalizeTimerIntervalKeyString(doc && doc.intervalKey);
  const activeChecked =
    doc == null || doc.active === true || doc.active === "true";
  const revInput = doc && doc._rev ? `<input type="hidden" id="rev" value="${escapeHtml(doc._rev)}">` : "";
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit timer" : "Create timer";
  const submitLabel = isEdit ? "Save" : "Create";

  const flowResolved = (fid) =>
    flows.some((f) => f._id === fid || f.name === fid);
  const profileResolved = (pid) =>
    profiles.some((p) => p._id === pid || p.name === pid);

  let flowOpts = "";
  if (doc && doc.flowId) {
    const raw = String(doc.flowId).trim();
    if (raw && !flowResolved(raw)) {
      flowOpts += `<option value="${escapeHtml(raw)}" selected>${escapeHtml(raw)}</option>`;
    }
  }
  for (const f of flows) {
    const fid = f._id;
    const sel =
      doc &&
      (doc.flowId === fid ||
        (typeof doc.flowId === "string" && doc.flowId.trim() === f.name))
        ? " selected"
        : "";
    flowOpts += `<option value="${escapeHtml(fid)}"${sel}>${escapeHtml(f.name || fid)}</option>`;
  }

  let profileOpts = "";
  if (doc && doc.profileId) {
    const raw = String(doc.profileId).trim();
    if (raw && !profileResolved(raw)) {
      profileOpts += `<option value="${escapeHtml(raw)}" selected>${escapeHtml(raw)}</option>`;
    }
  }
  for (const p of profiles) {
    const pid = p._id;
    const sel =
      doc &&
      (doc.profileId === pid ||
        (typeof doc.profileId === "string" && doc.profileId.trim() === p.name))
        ? " selected"
        : "";
    profileOpts += `<option value="${escapeHtml(pid)}"${sel}>${escapeHtml(p.name || pid)}</option>`;
  }

  const intervalOpts = TIMER_INTERVAL_ORDER.map((key) => {
    const lab = TIMER_INTERVAL_LABEL[key] || key;
    const sel = intervalKey === key ? " selected" : "";
    return `<option value="${escapeHtml(key)}"${sel}>${escapeHtml(lab)}</option>`;
  }).join("");

  const activeSwitch = `
    <div class="toggle-row">
      <span class="toggle-label">Active</span>
      <label class="switch" title="When off, this timer does not run">
        <input type="checkbox" id="active" name="active" value="true" ${activeChecked ? "checked" : ""}>
        <span class="slider"></span>
      </label>
    </div>`;

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
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 40rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="date"], input[type="time"] {
      width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d);
      border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem;
    }
    select { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    .actions-top { margin-bottom: 1rem; }
    .actions-top a { color: var(--app-link, #58a6ff); }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; display: inline-block; }
    .msg.err { background: #3d1f1f; color: #f85149; padding: 0.5rem; border-radius: 6px; margin: 1rem 0; }
    .toggle-row { display: flex; align-items: center; gap: 0.75rem; margin-top: 1.25rem; }
    .toggle-label { color: var(--app-label, #8b949e); }
    .switch { position: relative; display: inline-block; width: 2.75rem; height: 1.5rem; flex-shrink: 0; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; inset: 0; background: var(--app-table-border, #30363d);
      border-radius: 1.5rem; transition: background 0.2s;
    }
    .slider:before {
      position: absolute; content: ""; height: 1.15rem; width: 1.15rem; left: 0.2rem; bottom: 0.175rem;
      background: var(--app-text, #e6edf3); border-radius: 50%; transition: transform 0.2s;
    }
    .switch input:checked + .slider { background: #238636; }
    .switch input:checked + .slider:before { transform: translateX(1.2rem); }
    .switch input:focus + .slider { outline: 2px solid var(--app-link, #58a6ff); outline-offset: 2px; }
  </style>
</head>
<body>
  <div class="actions-top">
    <a href="/timers">← Timers</a>
    <button type="submit" form="timer-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/timers" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
  </div>
  <h1>${title}</h1>
  <p class="sub">Optional entry: when set, the flow runs with that document; otherwise a minimal dataset (<code>_timerFiredAt</code>) is used and single-step persistence is suppressed unless the flow saves explicitly.</p>
  ${errHtml}
  <form id="timer-form">
    ${revInput}
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="e.g. nightly export" value="${nameVal}">
    <label for="description">Description</label>
    <input type="text" id="description" name="description" placeholder="Optional" value="${descVal}">
    <label for="flowId">Flow</label>
    <select id="flowId" name="flowId" required>${flowOpts}</select>
    <label for="profileId">Elenko database (profile)</label>
    <select id="profileId" name="profileId" required>${profileOpts}</select>
    <label for="entryId">Entry document ID (optional)</label>
    <input type="text" id="entryId" name="entryId" placeholder="Leave empty for timer-only dataset" value="${entryVal}">
    <label for="param">Param (optional)</label>
    <input type="text" id="param" name="param" placeholder="Passed to the flow context" value="${paramVal}">
    <label for="startDate">Start date</label>
    <input type="date" id="startDate" name="startDate" required value="${startDateVal}">
    <label for="startTime">Start time</label>
    <input type="time" id="startTime" name="startTime" required value="${startTimeVal}">
    <label for="intervalKey">Repeat every</label>
    <select id="intervalKey" name="intervalKey">${intervalOpts}</select>
    ${activeSwitch}
  </form>
  <script>
    var formEl = document.getElementById('timer-form');
    if (formEl) formEl.onsubmit = async function(e) {
      e.preventDefault();
      var name = document.getElementById('name').value.trim();
      if (!name) { alert('Name is required.'); return; }
      var body = {
        name: name,
        description: document.getElementById('description').value.trim(),
        flowId: document.getElementById('flowId').value.trim(),
        profileId: document.getElementById('profileId').value.trim(),
        entryId: document.getElementById('entryId').value.trim(),
        param: document.getElementById('param').value.trim(),
        startDate: document.getElementById('startDate').value,
        startTime: document.getElementById('startTime').value,
        intervalKey: document.getElementById('intervalKey').value,
        active: document.getElementById('active').checked
      };
      var url = ${isEdit ? JSON.stringify("/api/timers/" + encodeURIComponent(doc._id)) : "\"/api/timers\""};
      var method = ${isEdit ? '"PUT"' : '"POST"'};
      if (${isEdit ? "true" : "false"}) body._rev = document.getElementById('rev').value;
      try {
        var r = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await r.json();
        if (!r.ok) { alert(data.error || 'Failed'); return; }
        window.location.href = '/timers';
      } catch (err) {
        alert(err.message || 'Request failed');
      }
    };
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
  <p class="sub" style="margin-top:0.5rem; padding:0.5rem; background:var(--app-table-bg, #161b22); border-radius:6px; border-left:3px solid var(--app-link, #58a6ff);"><strong>Persistence:</strong> The flow writes or deletes in the database when it includes one of: <em>Send to Local DB</em>, <em>Update current document</em>, <em>Create new document in this profile</em>, <em>Append repeat row</em> (when a current entry exists), or <em>Delete old entries in this profile</em> (Param e.g. <code>7d</code> or <code>2w</code> — rows with <code>createdAt</code> older than that age, capped per run). If none of these are present, the result is not saved (&quot;fire and forget&quot;). Log steps are neutral. <em>Append repeat row</em> marks the new row as an editable draft in entry view. <em>Update current document</em> saves draft edits from view and clears draft mode. <em>Refresh</em> waits for the entry to update (default 15s, poll every 5s; Param overrides timeout in seconds) and reloads the entry view when run from a form button.</p>
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
          : (step && step.target === 'response')
          ? 'response'
          : (step && step.target === 'script')
          ? 'script'
          : (step && step.target === 'update')
          ? 'update'
          : (step && step.target === 'create')
          ? 'create'
          : (step && step.target === 'purgeOld')
          ? 'purgeOld'
          : (step && step.target === 'appendRepeat')
          ? 'appendRepeat'
          : (step && step.target === 'refresh')
          ? 'refresh'
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
          : target === 'response'
          ? 'Not used'
          : target === 'update'
          ? 'Not used'
          : target === 'create'
          ? 'Not used'
          : target === 'purgeOld'
          ? 'Age: 7d or 2w (days/weeks)'
          : target === 'appendRepeat'
          ? 'Profile repeat fields (e.g. PROMPT,RESPONSE)'
          : target === 'refresh'
          ? 'Timeout seconds (default 15)'
          : '—';
      tr.innerHTML =
        '<td class="step-num"></td>' +
        '<td><select class="step-target">' +
        '<option value="log"' + (target === 'log' ? ' selected' : '') + '>Log (passthrough)</option>' +
        '<option value="api"' + (target === 'api' ? ' selected' : '') + '>Call API</option>' +
        '<option value="localDb"' + (target === 'localDb' ? ' selected' : '') + '>Send to Local DB</option>' +
        '<option value="response"' + (target === 'response' ? ' selected' : '') + '>Save as response (same profile)</option>' +
        '<option value="script"' + (target === 'script' ? ' selected' : '') + '>Run script (JS Processing)</option>' +
        '<option value="update"' + (target === 'update' ? ' selected' : '') + '>Update current document</option>' +
        '<option value="create"' + (target === 'create' ? ' selected' : '') + '>Create new document in this profile</option>' +
        '<option value="purgeOld"' + (target === 'purgeOld' ? ' selected' : '') + '>Delete old entries in this profile</option>' +
        '<option value="appendRepeat"' + (target === 'appendRepeat' ? ' selected' : '') + '>Append repeat row</option>' +
        '<option value="refresh"' + (target === 'refresh' ? ' selected' : '') + '>Refresh entry view</option>' +
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
          } else if (this.value === 'response') {
            stepParam.placeholder = 'Not used';
          } else if (this.value === 'update') {
            stepParam.placeholder = 'Not used';
          } else if (this.value === 'create') {
            stepParam.placeholder = 'Not used';
          } else if (this.value === 'purgeOld') {
            stepParam.placeholder = 'Age: 7d or 2w (days/weeks)';
          } else if (this.value === 'appendRepeat') {
            stepParam.placeholder = 'Profile repeat fields (e.g. PROMPT,RESPONSE)';
          } else if (this.value === 'refresh') {
            stepParam.placeholder = 'Timeout seconds (default 15)';
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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

function renderQueriesListPage(queries, appUi, profiles) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const truncate = (s, max) => (s && s.length > max ? s.slice(0, max) + "…" : s || "");
  const profilesArr = Array.isArray(profiles) ? profiles : [];
  const profileNameById = new Map(
    profilesArr
      .filter((p) => p && p._id)
      .map((p) => {
        const id = String(p._id);
        const name = typeof p.name === "string" && p.name.trim() ? p.name.trim() : id;
        return [id, name];
      })
  );
  const displayProfile = (idOrName) => {
    const s = idOrName != null ? String(idOrName).trim() : "";
    if (!s) return "";
    return profileNameById.get(s) || s;
  };
  const rows =
    queries.length > 0
      ? queries
          .map(
            (q) => `
        <tr>
          <td><a href="/queries/${encodeURIComponent(q._id)}/edit">${escapeHtml(q.name || q._id)}</a></td>
          <td>${escapeHtml(truncate(q.description || "", 60))}</td>
          <td>${escapeHtml(displayProfile(q.baseProfileId || ""))}</td>
          <td>${escapeHtml(displayProfile(q.queryProfileId || ""))}</td>
          <td class="row-actions"><a href="/queries/${encodeURIComponent(q._id)}/edit" class="edit-link icon-action" aria-label="Edit" title="Edit">✎</a><button type="button" class="delete-btn icon-action delete-query-btn" data-id="${escapeHtml(q._id)}" data-rev="${escapeHtml(q._rev || "")}" aria-label="Delete" title="Delete">✕</button></td>
        </tr>`
          )
          .join("")
      : `
        <tr>
          <td colspan="5" class="empty">No linked queries yet. Create one to show related records from another Elenko database on the single-entry view.</td>
        </tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Linked queries</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 56rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    #query-list-msg { margin-top: 0.75rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Start</a><a href="/queries/create" class="btn">Create linked query</a></div>
  <h1>Linked queries</h1>
  <p class="sub">Configure lookups from one Elenko database (base) into another (query) to show related rows in the single-entry view.</p>
  <table>
    <thead><tr><th>Name</th><th>Description</th><th>Base profile</th><th>Query profile</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
  <div id="query-list-msg" style="display:none;"></div>
  <script>
    (function() {
      var msgEl = document.getElementById('query-list-msg');
      function showErr(t) {
        if (!msgEl) return;
        msgEl.style.display = 'block';
        msgEl.style.color = '#f85149';
        msgEl.textContent = t || 'Request failed';
      }
      document.querySelectorAll('.delete-query-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var id = btn.getAttribute('data-id');
          var rev = btn.getAttribute('data-rev');
          if (!id || !rev) { showErr('Missing revision; refresh the page.'); return; }
          if (!confirm('Delete this linked query? Single Entry forms that reference it may need to be updated.')) return;
          btn.disabled = true;
          if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
          fetch('/api/queries/' + encodeURIComponent(id) + '/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _rev: rev })
          })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(o) {
              btn.disabled = false;
              if (o.ok) {
                window.location.href = o.data.redirect || '/queries';
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

function renderEditQueryPage(doc, err, appUi, profiles) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const id = doc && doc._id;
  const rev = doc && doc._rev;
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : "";
  const descVal = doc && typeof doc.description === "string" ? escapeHtml(doc.description) : "";
  const baseProfileVal = doc && typeof doc.baseProfileId === "string" ? doc.baseProfileId : "";
  const baseKeyFieldVal = doc && typeof doc.baseKeyField === "string" ? escapeHtml(doc.baseKeyField) : "";
  const queryProfileVal = doc && typeof doc.queryProfileId === "string" ? doc.queryProfileId : "";
  const queryKeyFieldVal = doc && typeof doc.queryKeyField === "string" ? escapeHtml(doc.queryKeyField) : "";
  const sortFieldVal = doc && typeof doc.sortField === "string" ? escapeHtml(doc.sortField) : "";
  const sortDirectionVal = doc && doc.sortDirection === "desc" ? "desc" : "asc";
  const resultFieldsArr = doc && Array.isArray(doc.resultFields) ? doc.resultFields : [];
  const resultFieldsVal = resultFieldsArr.join(", ");
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit linked query" : "Create linked query";
  const submitLabel = isEdit ? "Save" : "Create";
  const revInput = rev ? `<input type="hidden" id="rev" value="${escapeHtml(rev)}">` : "";

  const profileOptions =
    Array.isArray(profiles) && profiles.length
      ? '<option value="">— Select profile —</option>' +
        profiles
          .map((p) => {
            const idVal = String(p._id || "").trim();
            const nameVal2 = typeof p.name === "string" && p.name.trim() ? p.name.trim() : idVal;
            return `<option value="${escapeHtml(idVal)}"${idVal === baseProfileVal ? " data-role=\"base\" selected" : ""}>${escapeHtml(nameVal2)}</option>`;
          })
          .join("")
      : '<option value="">No profiles</option>';

  const queryProfileOptions =
    Array.isArray(profiles) && profiles.length
      ? '<option value="">— Select profile —</option>' +
        profiles
          .map((p) => {
            const idVal = String(p._id || "").trim();
            const nameVal2 = typeof p.name === "string" && p.name.trim() ? p.name.trim() : idVal;
            return `<option value="${escapeHtml(idVal)}"${idVal === queryProfileVal ? " data-role=\"query\" selected" : ""}>${escapeHtml(nameVal2)}</option>`;
          })
          .join("")
      : '<option value="">No profiles</option>';

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
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 46rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .actions { margin-bottom: 1rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
    label { display: block; margin-top: 0.75rem; color: var(--app-label, #8b949e); }
    input, select, textarea { width: 100%; max-width: 32rem; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); }
    textarea { min-height: 4rem; resize: vertical; }
    .btn { margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; border: none; }
    .btn-primary { background: #238636; color: #fff; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; display: inline-block; margin-left: 0.5rem; }
    .actions a.btn:not(.btn-secondary), a.btn:not(.btn-secondary) { color: #fff; }
    .actions a.btn:hover:not(.btn-secondary), a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    .msg { margin-top: 1rem; }
    .msg.err { color: #f85149; }
    .msg.ok { color: #3fb950; }
    .sub { color: var(--app-label, #8b949e); font-size: 0.9rem; margin-top: 0.25rem; max-width: 36rem; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/queries">← Linked queries</a>
    <button type="submit" form="query-form" class="btn btn-primary" style="margin-left:1rem;">${submitLabel}</button>
    <a href="/queries" class="btn btn-secondary">Cancel</a>
  </div>
  <h1>${title}</h1>
  <p class="sub">Link a base Elenko database (e.g. media) to a query database (e.g. songs) by matching a key field. The query results can be shown in the Single Entry view.</p>
  ${errHtml}
  <form id="query-form">
    ${revInput}
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="e.g. Songs on medium" value="${nameVal}">
    <label for="description">Description</label>
    <textarea id="description" name="description" placeholder="Optional description">${descVal}</textarea>

    <label for="baseProfileId">Base profile</label>
    <select id="baseProfileId" name="baseProfileId" required>${profileOptions}</select>
    <p class="sub">The Elenko database whose Single Entry form will use this query (e.g. media).</p>

    <label for="baseKeyField">Base key field</label>
    <input type="text" id="baseKeyField" name="baseKeyField" required placeholder="Field name on base profile (e.g. mediumId)" value="${baseKeyFieldVal}">
    <p class="sub">Field on the base profile whose value will be used as the lookup key (e.g. mediumId on the media entry).</p>

    <label for="queryProfileId">Query profile</label>
    <select id="queryProfileId" name="queryProfileId" required>${queryProfileOptions}</select>
    <p class="sub">The Elenko database that will be queried for matching rows (e.g. songs).</p>

    <label for="queryKeyField">Query key field</label>
    <input type="text" id="queryKeyField" name="queryKeyField" required placeholder="Field name on query profile (e.g. mediumId)" value="${queryKeyFieldVal}">
    <p class="sub">Field on the query profile that must equal the base key field value (1:1 field mapping for now).</p>

    <label for="resultFields">Result fields (comma-separated)</label>
    <input type="text" id="resultFields" name="resultFields" placeholder="e.g. trackNo, title, duration" value="${resultFieldsVal}">
    <p class="sub">Fields from the query profile to include in the result list (order defines display order). Leave empty to use all profile fields.</p>

    <label for="sortField">Sort field (optional)</label>
    <input type="text" id="sortField" name="sortField" placeholder="e.g. trackNo" value="${sortFieldVal}">
    <p class="sub">Field on the query profile used to sort matching rows (e.g. track number). If empty, query results will not be explicitly sorted.</p>

    <label for="sortDirection">Sort direction</label>
    <select id="sortDirection" name="sortDirection">
      <option value="asc"${sortDirectionVal === "asc" ? " selected" : ""}>Ascending</option>
      <option value="desc"${sortDirectionVal === "desc" ? " selected" : ""}>Descending</option>
    </select>
  </form>
  <div id="msg"></div>
  <script>
    (function() {
      var form = document.getElementById('query-form');
      var msgEl = document.getElementById('msg');
      if (!form) return;
      form.addEventListener('submit', function(ev) {
        ev.preventDefault();
        if (!msgEl) return;
        msgEl.style.display = 'none';
        msgEl.textContent = '';
        msgEl.className = 'msg';

        var name = (document.getElementById('name') || {}).value || '';
        var baseProfileId = (document.getElementById('baseProfileId') || {}).value || '';
        var baseKeyField = (document.getElementById('baseKeyField') || {}).value || '';
        var queryProfileId = (document.getElementById('queryProfileId') || {}).value || '';
        var queryKeyField = (document.getElementById('queryKeyField') || {}).value || '';
        if (!name.trim() || !baseProfileId.trim() || !baseKeyField.trim() || !queryProfileId.trim() || !queryKeyField.trim()) {
          msgEl.textContent = 'Name, base/query profile and key fields are required.';
          msgEl.className = 'msg err';
          msgEl.style.display = 'block';
          return;
        }

        var resultFieldsRaw = (document.getElementById('resultFields') || {}).value || '';
        var resultFields = resultFieldsRaw
          .split(',')
          .map(function(f) { return f.trim(); })
          .filter(function(f) { return !!f; });

        var payload = {
          name: name,
          description: (document.getElementById('description') || {}).value || '',
          baseProfileId: baseProfileId,
          baseKeyField: baseKeyField,
          queryProfileId: queryProfileId,
          queryKeyField: queryKeyField,
          resultFields: resultFields,
          sortField: (document.getElementById('sortField') || {}).value || '',
          sortDirection: (document.getElementById('sortDirection') || {}).value === 'desc' ? 'desc' : 'asc'
        };

        var id = ${isEdit ? JSON.stringify(id || "") : "''"};
        var revInput = document.getElementById('rev');
        if (revInput && revInput.value) payload._rev = revInput.value;

        var url = id ? '/api/queries/' + encodeURIComponent(id) : '/api/queries';
        var method = id ? 'PUT' : 'POST';

        fetch(url, {
          method: method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
          .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
          .then(function(o) {
            if (o.ok) {
              msgEl.textContent = 'Saved.';
              msgEl.className = 'msg ok';
              msgEl.style.display = 'block';
              if (!id && o.data && o.data.id) {
                window.location.href = '/queries/' + encodeURIComponent(o.data.id) + '/edit';
              }
            } else {
              msgEl.textContent = (o.data && o.data.error) ? o.data.error : 'Save failed';
              msgEl.className = 'msg err';
              msgEl.style.display = 'block';
            }
          })
          .catch(function(e) {
            msgEl.textContent = e.message || 'Save failed';
            msgEl.className = 'msg err';
            msgEl.style.display = 'block';
          });
      });
    })();
  </script>
</body>
</html>`;
}

function renderEditApiPage(doc, err, returnTo, appUi, prefillApiKeyRef, prefillUserRef, prefillPasswordRef) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const id = doc && doc._id;
  const rev = doc && doc._rev;
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : "";
  const descVal = doc && typeof doc.description === "string" ? escapeHtml(doc.description) : "";
  const urlVal = doc && typeof doc.url === "string" ? escapeHtml(doc.url) : "";
  const methodVal = doc && doc.method === "POST" ? "POST" : doc && doc.method === "PUT" ? "PUT" : doc && doc.method === "PATCH" ? "PATCH" : "GET";
  const authTypeStored = doc ? normalizeElenkoApiAuthType(doc) : "none";
  const apiKeyRefRaw =
    doc && typeof doc.apiKeyRef === "string" && doc.apiKeyRef.trim()
      ? doc.apiKeyRef.trim()
      : (typeof prefillApiKeyRef === "string" && prefillApiKeyRef.trim() ? prefillApiKeyRef.trim() : "");
  const apiKeyRefVal = apiKeyRefRaw ? escapeHtml(apiKeyRefRaw) : "";
  const apiUserRefRaw =
    doc && typeof doc.apiUserRef === "string" && doc.apiUserRef.trim()
      ? doc.apiUserRef.trim()
      : (typeof prefillUserRef === "string" && prefillUserRef.trim() ? prefillUserRef.trim() : "");
  const apiUserRefVal = apiUserRefRaw ? escapeHtml(apiUserRefRaw) : "";
  const apiPasswordRefRaw =
    doc && typeof doc.apiPasswordRef === "string" && doc.apiPasswordRef.trim()
      ? doc.apiPasswordRef.trim()
      : (typeof prefillPasswordRef === "string" && prefillPasswordRef.trim() ? prefillPasswordRef.trim() : "");
  const apiPasswordRefVal = apiPasswordRefRaw ? escapeHtml(apiPasswordRefRaw) : "";
  const responseTargetVal = doc && doc.responseTarget === "create" ? "create" : doc && doc.responseTarget === "forward" ? "forward" : "update";
  const templateVal = doc && typeof doc.template === "string" ? escapeHtml(doc.template) : "";
  const responseFieldVal = doc && typeof doc.responseField === "string" ? escapeHtml(doc.responseField) : "";
  const responseStartVal = doc && typeof doc.responseStart === "string" ? escapeHtml(doc.responseStart) : "";
  const responseEndVal = doc && typeof doc.responseEnd === "string" ? escapeHtml(doc.responseEnd) : "";
  const getQueryFromEntryChecked = isEdit && doc ? doc.getQueryFromEntry !== false : false;
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    <label for="apiAuthType">Authentication</label>
    <select id="apiAuthType" name="apiAuthType">
      <option value="none"${authTypeStored === "none" ? " selected" : ""}>None</option>
      <option value="bearer"${authTypeStored === "bearer" ? " selected" : ""}>Bearer or API key (Authorization + api-key headers)</option>
      <option value="basic"${authTypeStored === "basic" ? " selected" : ""}>HTTP Basic (username + password documents)</option>
      <option value="digest"${authTypeStored === "digest" ? " selected" : ""}>HTTP Digest (username + password documents)</option>
      <option value="fritz"${authTypeStored === "fritz" ? " selected" : ""}>FRITZ!Box session (login_sid.lua + sid — use for /api/v0/smarthome)</option>
    </select>
    <p class="sub" id="apiAuthHint" style="margin-top:0.25rem;"></p>
    <div id="authBearerBlock">
    <label for="apiKeyRef">Secret key document ID <span class="sub">(bearer token or API key)</span></label>
    <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
      <input type="text" id="apiKeyRef" name="apiKeyRef" placeholder="key_..." value="${apiKeyRefVal}" style="max-width:20rem;">
      <a href="#" id="createEditKeyLink" class="btn btn-secondary" style="margin-top:0;">Create / Edit secret document</a>
    </div>
    <div id="apiKeyRefNotice" class="msg" style="margin-top:0.25rem;" aria-live="polite"></div>
    </div>
    <div id="authUserPassBlock" style="display:none;">
    <label for="apiUserRef">Username key document ID</label>
    <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
      <input type="text" id="apiUserRef" name="apiUserRef" placeholder="key_...-user" value="${apiUserRefVal}" style="max-width:20rem;">
      <a href="#" id="createEditUserKeyLink" class="btn btn-secondary" style="margin-top:0;">Create / Edit username document</a>
    </div>
    <label for="apiPasswordRef" style="margin-top:0.75rem;">Password key document ID</label>
    <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
      <input type="text" id="apiPasswordRef" name="apiPasswordRef" placeholder="key_...-pass" value="${apiPasswordRefVal}" style="max-width:20rem;">
      <a href="#" id="createEditPasswordKeyLink" class="btn btn-secondary" style="margin-top:0;">Create / Edit password document</a>
    </div>
    <div id="apiUserPassRefNotice" class="msg" style="margin-top:0.25rem;" aria-live="polite"></div>
    </div>
    <label for="template">Template <span class="sub">(optional) For POST/PUT/PATCH: request body with #fieldName# placeholders. Repeat fields: #fieldName(FIRST|LAST|ALL|n)# (n is 1-based row). Dialog history: wrap prior turns in <code>#REPEAT(N)# … #END REPEAT(N)#</code> using <code>#PROMPT(N)#</code> / <code>#RESPONSE(N)#</code> inside (loops rows 1 .. last−1), then <code>#PROMPT(LAST)#</code> for the current question. For GET: use only if you need a dynamic URL or body-like URL; otherwise leave empty and set the URL above.</span></label>
    <textarea id="template" name="template" placeholder='e.g. {"query":"#customer#"}' rows="4" style="width:100%;max-width:28rem;font-family:monospace;">${templateVal}</textarea>
    <label class="checkbox-row" for="getQueryFromEntry" style="display:flex;align-items:flex-start;gap:0.5rem;margin-top:0.75rem;max-width:32rem;color:var(--app-label, #8b949e);cursor:pointer;">
      <input type="checkbox" id="getQueryFromEntry" name="getQueryFromEntry" style="width:auto;max-width:none;margin-top:0.2rem;flex-shrink:0;"${getQueryFromEntryChecked ? " checked" : ""}>
      <span>Append entry fields as GET query parameters when Template is empty <span class="sub">(older behaviour; off for fixed URLs such as FRITZ!Box <code>/api/v0/...</code> to avoid very long URLs)</span></span>
    </label>
    <label for="responseField">Response field <span class="sub">(optional) Elenko document field name where the raw API response body will be stored when updating the same entry. For profile fields of type Repeat, the value is written into the last dialog row (same index as the longest repeat field, e.g. matching the last PROMPT).</span></label>
    <input type="text" id="responseField" name="responseField" placeholder="e.g. apiResponse" value="${responseFieldVal}">
    <label for="responseStart">Response start <span class="sub">(optional) Character sequence that marks the start of the useful text; everything before and including it is removed)</span></label>
    <input type="text" id="responseStart" name="responseStart" placeholder='e.g. "content":"' value="${responseStartVal}" style="font-family:monospace;">
    <label for="responseEnd">Response end <span class="sub">(optional) Character sequence that marks the end of the useful text; it and everything after it is removed)</span></label>
    <input type="text" id="responseEnd" name="responseEnd" placeholder='e.g. "}}]}' value="${responseEndVal}" style="font-family:monospace;">
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
    var apiUserRefManuallyEdited = false;
    var apiPasswordRefManuallyEdited = false;
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
    function syncUserPassRefsFromName() {
      var nameEl = document.getElementById('name');
      var userEl = document.getElementById('apiUserRef');
      var passEl = document.getElementById('apiPasswordRef');
      if (!nameEl || !userEl || !passEl) return;
      var n = (nameEl.value || '').trim();
      if (!n) return;
      var base = slugifyForKeyId(n);
      if (!apiUserRefManuallyEdited && !(userEl.value || '').trim()) userEl.value = base + '-user';
      if (!apiPasswordRefManuallyEdited && !(passEl.value || '').trim()) passEl.value = base + '-pass';
    }
    function updateAuthUi() {
      var sel = document.getElementById('apiAuthType');
      var hint = document.getElementById('apiAuthHint');
      var bBlock = document.getElementById('authBearerBlock');
      var upBlock = document.getElementById('authUserPassBlock');
      if (!sel || !hint || !bBlock || !upBlock) return;
      var v = sel.value || 'none';
      if (v === 'none') {
        hint.textContent = 'No Authorization headers are sent.';
        bBlock.style.display = 'none';
        upBlock.style.display = 'none';
      } else if (v === 'bearer') {
        hint.textContent = 'The secret document value is sent as Bearer token and as the api-key header.';
        bBlock.style.display = 'block';
        upBlock.style.display = 'none';
      } else if (v === 'fritz') {
        hint.textContent = 'Same username/password key documents as Digest. Logs in via login_sid.lua and adds sid= to the request URL (needed for FRITZ! JSON Smart Home API, not plain HTTP Digest).';
        bBlock.style.display = 'none';
        upBlock.style.display = 'block';
      } else {
        hint.textContent = 'Use two key documents: one stores the username, one the password (FRITZ!Box and similar).';
        bBlock.style.display = 'none';
        upBlock.style.display = 'block';
      }
    }
    function openKeyCreateUrl(credentialField) {
      var name = (document.getElementById('name').value || '').trim();
      var refEl = credentialField === 'apiUserRef' ? document.getElementById('apiUserRef')
        : credentialField === 'apiPasswordRef' ? document.getElementById('apiPasswordRef')
        : document.getElementById('apiKeyRef');
      var docId = refEl ? (refEl.value || '').trim() : '';
      var returnTo = window.location.pathname + window.location.search;
      var q = new URLSearchParams();
      if (returnTo) q.set('returnTo', returnTo);
      q.set('credentialField', credentialField);
      if (docId) q.set('apiKeyDocId', docId);
      if (name) q.set('defaultName', name);
      window.location.href = '/apis/keys/create?' + q.toString();
    }
    var form = document.getElementById('api-form');
    var formId = document.getElementById('apiId').value;
    syncApiKeyRefFromName();
    syncUserPassRefsFromName();
    updateAuthUi();
    var apiKeyRefEl = document.getElementById('apiKeyRef');
    if (apiKeyRefEl) {
      apiKeyRefEl.addEventListener('input', function() {
        apiKeyRefManuallyEdited = true;
      });
    }
    var apiUserRefEl = document.getElementById('apiUserRef');
    if (apiUserRefEl) {
      apiUserRefEl.addEventListener('input', function() { apiUserRefManuallyEdited = true; });
    }
    var apiPasswordRefEl = document.getElementById('apiPasswordRef');
    if (apiPasswordRefEl) {
      apiPasswordRefEl.addEventListener('input', function() { apiPasswordRefManuallyEdited = true; });
    }
    document.getElementById('name').addEventListener('input', function() {
      syncApiKeyRefFromName();
      syncUserPassRefsFromName();
    });
    document.getElementById('name').addEventListener('blur', function() {
      syncApiKeyRefFromName();
      syncUserPassRefsFromName();
    });
    var apiAuthTypeEl = document.getElementById('apiAuthType');
    if (apiAuthTypeEl) apiAuthTypeEl.addEventListener('change', updateAuthUi);
    var createEditKeyLink = document.getElementById('createEditKeyLink');
    if (createEditKeyLink) {
      createEditKeyLink.addEventListener('click', function(e) {
        e.preventDefault();
        openKeyCreateUrl('apiKeyRef');
      });
    }
    var createEditUserKeyLink = document.getElementById('createEditUserKeyLink');
    if (createEditUserKeyLink) {
      createEditUserKeyLink.addEventListener('click', function(e) {
        e.preventDefault();
        openKeyCreateUrl('apiUserRef');
      });
    }
    var createEditPasswordKeyLink = document.getElementById('createEditPasswordKeyLink');
    if (createEditPasswordKeyLink) {
      createEditPasswordKeyLink.addEventListener('click', function(e) {
        e.preventDefault();
        openKeyCreateUrl('apiPasswordRef');
      });
    }
    form.onsubmit = async function(e) {
      e.preventDefault();
      var msgEl = document.getElementById('msg');
      var name = (document.getElementById('name').value || '').trim();
      var description = (document.getElementById('description').value || '').trim();
      var url = (document.getElementById('url').value || '').trim();
      var method = document.getElementById('method').value || 'GET';
      var apiAuthType = (document.getElementById('apiAuthType').value || 'none').trim();
      var apiKeyRef = (document.getElementById('apiKeyRef').value || '').trim();
      var apiUserRef = (document.getElementById('apiUserRef').value || '').trim();
      var apiPasswordRef = (document.getElementById('apiPasswordRef').value || '').trim();
      var getQueryFromEntry = !!(document.getElementById('getQueryFromEntry') && document.getElementById('getQueryFromEntry').checked);
      var responseTarget = document.getElementById('responseTarget').value || 'update';
      var template = (document.getElementById('template').value || '').trim();
      var responseField = (document.getElementById('responseField').value || '').trim();
      var responseStart = (document.getElementById('responseStart').value || '');
      var responseEnd = (document.getElementById('responseEnd').value || '');
      var urlApi = formId ? '/api/apis/' + encodeURIComponent(formId) : '/api/apis';
      var methodHttp = formId ? 'PUT' : 'POST';
      var body = { name: name, description: description, url: url, method: method, apiAuthType: apiAuthType, template: template, responseField: responseField, responseStart: responseStart, responseEnd: responseEnd, apiKeyRef: apiKeyRef, apiUserRef: apiUserRef, apiPasswordRef: apiPasswordRef, getQueryFromEntry: getQueryFromEntry, responseTarget: responseTarget };
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

function renderEditApiKeyPage(doc, err, returnTo, defaultName, appUi, defaultApiKeyDocId, credentialField) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const isEdit = !!(doc && doc._id);
  const id = doc && doc._id;
  const apiKeyDocIdVal = id ? id : (typeof defaultApiKeyDocId === "string" ? defaultApiKeyDocId.trim() : "");
  const rev = doc && doc._rev;
  const nameVal = doc && typeof doc.name === "string" ? escapeHtml(doc.name) : (typeof defaultName === "string" && defaultName ? escapeHtml(defaultName) : "");
  const credRaw = typeof credentialField === "string" ? credentialField.trim() : "";
  const credentialReturnParam = new Set(["apiKeyRef", "apiUserRef", "apiPasswordRef"]).has(credRaw) ? credRaw : "apiKeyRef";
  const keyLabelHint =
    credentialReturnParam === "apiUserRef"
      ? "Stored value is used as the HTTP username (Basic/Digest)."
      : credentialReturnParam === "apiPasswordRef"
        ? "Stored value is used as the HTTP password (Basic/Digest)."
        : "Stored value is used as Bearer token and api-key header when the API uses bearer auth.";
  const keyPlaceholder = isEdit ? "Leave blank to keep current value" : "Secret value";
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
  <p class="sub">Stored in the config store. The document ID is derived from the name (e.g. &quot;My Service&quot; → key_my-service). ${escapeHtml(keyLabelHint)}</p>
  ${errHtml}
  <form id="api-key-form" autocomplete="off">
    ${revInput}
    ${returnToInput}
    <input type="hidden" id="keyId" value="${id ? escapeHtml(id) : ""}">
    <label for="apiKeyDocId">API key document ID</label>
    <input type="text" id="apiKeyDocId" value="${apiKeyDocIdVal ? escapeHtml(apiKeyDocIdVal) : ""}" readonly>
    <label for="name">Description</label>
    <input type="text" id="name" name="name" required placeholder="e.g. OpenWeather API key" value="${nameVal}">
    <label for="key">Secret value</label>
    <input type="password" id="key" name="key" placeholder="${escapeHtml(keyPlaceholder)}" autocomplete="off">
  </form>
  <div id="msg"></div>
  <script>
    var form = document.getElementById('api-key-form');
    var keyId = document.getElementById('keyId').value;
    var apiKeyDocIdEl = document.getElementById('apiKeyDocId');
    var returnToEl = document.getElementById('returnTo');
    var returnToVal = returnToEl ? returnToEl.value : '';
    var credentialField = ${JSON.stringify(credentialReturnParam)};

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
          setTimeout(function() { window.location.href = returnToVal + sep + credentialField + '=' + encodeURIComponent(data.id); }, 500);
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

function renderCreateEntryFormPage(err, flows, queries, appUi) {
  return renderEntryFormPage(null, null, err, flows, queries, appUi);
}

function renderEditEntryFormPage(doc, err, flows, queries, appUi) {
  return renderEntryFormPage(doc, doc._rev, err, flows, queries, appUi);
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

function renderEntryFormPage(doc, rev, err, flows, queries, appUi) {
  const appTheme = normalizeAppTheme(appUi && appUi.theme);
  const appThemeVars = getAppThemeVars(appTheme);
  const flowsList = Array.isArray(flows) ? flows : [];
  const queriesList = Array.isArray(queries) ? queries : [];
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
    : [{ enabled: !!(doc && doc.flowButtonEnabled), target: (doc && doc.flowTarget === "api") ? "api" : (doc && doc.flowTarget === "localDb") ? "localDb" : (doc && doc.flowTarget === "response") ? "response" : "log", label: (doc && typeof doc.flowButtonLabel === "string" && doc.flowButtonLabel.trim()) ? doc.flowButtonLabel.trim() : "Send to Flow", param: (doc && typeof doc.flowButtonParam === "string") ? doc.flowButtonParam : "", flowId: "" }];
  const initialFlowConfigsJson = JSON.stringify(flowConfigs);
  const labelsArr = (doc && Array.isArray(doc.labels) ? doc.labels : []);
  const fieldLayout = (doc && Array.isArray(doc.fieldLayout) ? doc.fieldLayout : []);
  const linkedQueryCfg = doc && doc.linkedQuery && typeof doc.linkedQuery === "object" ? doc.linkedQuery : null;
  const linkedQueryIdVal = linkedQueryCfg && typeof linkedQueryCfg.id === "string" ? linkedQueryCfg.id : "";
  const linkedQueryWidthVal = linkedQueryCfg && typeof linkedQueryCfg.width === "string" ? linkedQueryCfg.width : "";
  const linkedQueryButtonLabelVal = linkedQueryCfg && typeof linkedQueryCfg.buttonLabel === "string" ? linkedQueryCfg.buttonLabel : "";
  const linkedQueryXVal = linkedQueryCfg && linkedQueryCfg.x != null ? String(linkedQueryCfg.x) : "";
  const linkedQueryYVal = linkedQueryCfg && linkedQueryCfg.y != null ? String(linkedQueryCfg.y) : "";
  const linkedQueryHeightVal = linkedQueryCfg && linkedQueryCfg.height != null ? String(linkedQueryCfg.height) : "";
  const linkedQueryLoadOnDemandVal = !!(linkedQueryCfg && linkedQueryCfg.loadOnDemand);
  const entryNavForwardBackVal = !!(
    doc &&
    (doc.entryNavForwardBackEnabled === true || doc.entryNavForwardBackEnabled === "true")
  );
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
            const isRepeatGroup = isRepeatGroupLayoutItem(item);
            const fieldOrLabel = isRepeatGroup ? "" : item.fieldName || item.labelId || "";
            const xVal = item.x != null ? String(item.x) : "";
            const yVal = item.y != null ? String(item.y) : "";
            const hVal = item.height != null ? String(item.height) : "";
            const fieldTypeVal =
              item.fieldType === "markdown"
                ? "markdown"
                : item.fieldType === "url"
                ? "url"
                : item.fieldType === "image"
                ? "image"
                : item.fieldType === "chart"
                ? "chart"
                : item.fieldType === "repeat"
                ? "repeat"
                : "text";
            const repeatModeVal = item.repeatMode === "stack" ? "stack" : "table";
            const repeatAddLabelVal =
              item.fieldType === "repeat" && typeof item.repeatAddLabel === "string" && item.repeatAddLabel.trim()
                ? item.repeatAddLabel.trim()
                : "Add row";
            const repeatConfigHtml =
              fieldTypeVal === "repeat" && (item.fieldName || isRepeatGroup)
                ? buildRepeatFormDesignerConfigHtml({
                    visible: true,
                    repeatMode: repeatModeVal,
                    repeatAddLabel: repeatAddLabelVal,
                    repeatColumns: item.repeatColumns,
                    fieldName: item.fieldName || "",
                  })
                : "";
            const typeSelect =
              item.fieldName || isRepeatGroup
                ? `<select class="fl-type"><option value="text"${fieldTypeVal === "text" ? " selected" : ""}>Text</option><option value="markdown"${fieldTypeVal === "markdown" ? " selected" : ""}>Markdown</option><option value="url"${fieldTypeVal === "url" ? " selected" : ""}>URL</option><option value="image"${fieldTypeVal === "image" ? " selected" : ""}>Image</option><option value="chart"${fieldTypeVal === "chart" ? " selected" : ""}>Chart</option><option value="repeat"${fieldTypeVal === "repeat" ? " selected" : ""}>Repeat group</option></select>${repeatConfigHtml}`
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

  const linkedQueryOptions =
    queriesList.length > 0
      ? '<option value="">— None —</option>' +
        queriesList
          .map((q) => {
            const id = q && q._id ? String(q._id) : "";
            const label = q && (q.name || q._id) ? String(q.name || q._id) : id;
            const sel = id && linkedQueryIdVal && id === linkedQueryIdVal ? " selected" : "";
            return `<option value="${escapeHtml(id)}"${sel}>${escapeHtml(label)}</option>`;
          })
          .join("")
      : '<option value="">No linked queries</option>';

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
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); font-weight: 600; }
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
    .field-layout-table td { padding: 0.25rem; vertical-align: top; }
    .field-layout-table input { width: 100%; }
    .fl-repeat-config { margin-top: 0.35rem; min-width: 14rem; }
    .fl-repeat-sub-label { font-size: 0.75rem; margin-top: 0.35rem; display: block; color: var(--app-label, #8b949e); font-weight: 600; }
    .fl-repeat-cols-table { width: 100%; border-collapse: collapse; margin-top: 0.25rem; font-size: 0.8rem; }
    .fl-repeat-cols-table th, .fl-repeat-cols-table td { padding: 0.2rem; border-bottom: 1px solid var(--app-table-border, #30363d); }
    .fl-repeat-cols-table th { color: var(--app-label, #8b949e); font-weight: 600; text-align: left; }
    .fl-repeat-cols-table input, .fl-repeat-cols-table select { font-size: 0.8rem; padding: 0.25rem; }
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
    .actions { margin-bottom: 1rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    <p class="sub" style="margin-top:0;">Use a profile field name, a label id from above, or leave the first column empty with type <strong>Repeat group</strong> (pairs profile repeat fields by row index — column keys must match profile field names such as PROMPT and RESPONSE). Type: Text, Markdown, URL, Image, Chart, or Repeat group. For a section heading only, add a static label row (e.g. id <code>dialog</code>, text Dialog) above the repeat group row. On edit entry, the field name is the button that opens the file picker. Each upload is limited to ${Math.round(MAX_ENTRY_IMAGE_BYTES / 1024)} KiB before processing (an app policy to keep memory and attachments bounded; not a CouchDB hard limit). Administrators can raise or lower it with the environment variable <code>MAX_ENTRY_IMAGE_BYTES</code> (bytes). For Image fields, the layout Width column also sets the maximum long edge in pixels when scaling on upload (e.g. <code>400px</code>, <code>32ch</code>, or <code>50%</code> of the default screen cap). Leave empty to use profile field order. Width: e.g. 50%, 1fr, or 40ch. Only Stack supports X (ch), Y (em), and Height (em) for positioning. In <strong>Grid</strong> layout, Width sets the column size. In <strong>Stack</strong> layout, Height on image/file-preview fields sizes the value box (and no longer forces <code>position:absolute</code> when only Height is set). <strong>Height (em)</strong> limits the box around those fields in both layouts (single-entry view and edit).</p>
    <table class="field-layout-table">
      <thead><tr><th>Field name or label id</th><th>Order</th><th>Type</th><th>Width</th><th>X (ch)</th><th>Y (em)</th><th>Height (em)</th><th></th></tr></thead>
      <tbody id="field-layout-tbody">${fieldLayoutRows}
      </tbody>
    </table>
    <button type="button" class="btn btn-secondary" id="add-field-layout" style="margin-top:0.5rem;">+ Add row</button>

    <label style="margin-top:1.5rem;">Linked query (single-entry view)</label>
    <p class="sub" style="margin-top:0;">Optional: show a related-records table from another Elenko database on the single-entry view.</p>
    <label for="linkedQueryId" style="margin-top:0.5rem;">Linked Query</label>
    <select id="linkedQueryId" name="linkedQueryId">${linkedQueryOptions}</select>
    <p class="sub" style="margin-top:0.25rem;">Select one linked query (configured under Special → Linked queries).</p>
    <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0.75rem;max-width:40rem;">
      <div>
        <label for="linkedQueryWidth" style="margin-top:0;">Width</label>
        <input type="text" id="linkedQueryWidth" placeholder="e.g. 100%, 24rem" value="${escapeHtml(linkedQueryWidthVal)}">
      </div>
      <div>
        <label for="linkedQueryX" style="margin-top:0;">X (ch)</label>
        <input type="number" id="linkedQueryX" step="any" placeholder="—" value="${escapeHtml(linkedQueryXVal)}">
      </div>
      <div>
        <label for="linkedQueryY" style="margin-top:0;">Y (em)</label>
        <input type="number" id="linkedQueryY" step="any" placeholder="—" value="${escapeHtml(linkedQueryYVal)}">
      </div>
      <div>
        <label for="linkedQueryHeight" style="margin-top:0;">Height (em)</label>
        <input type="number" id="linkedQueryHeight" step="any" min="0" placeholder="—" value="${escapeHtml(linkedQueryHeightVal)}">
      </div>
    </div>
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:0.75rem 1rem;margin-top:0.75rem;">
      <label style="display:flex;align-items:center;gap:0.5rem;margin:0;">
        <input type="checkbox" id="linkedQueryLoadOnDemand" ${linkedQueryLoadOnDemandVal ? "checked" : ""} style="width:auto;">
        <span style="color:var(--app-text,#e6edf3);">Load on demand (start empty; show button to load linked query table)</span>
      </label>
      <span id="linkedQueryButtonLabelWrap" style="display:flex;align-items:center;gap:0.5rem;flex:1 1 14rem;min-width:min(100%,12rem);">
        <label for="linkedQueryButtonLabel" style="margin:0;white-space:nowrap;">Button label</label>
        <input type="text" id="linkedQueryButtonLabel" placeholder="Load linked data" value="${escapeHtml(linkedQueryButtonLabelVal)}" style="flex:1;min-width:8rem;">
      </span>
    </div>
    <p class="sub" style="margin-top:0.5rem;">Grid layout: X/Y/Height position the table. Other layouts: table is placed below entry data. Height adds a vertical scrollbar when needed.</p>
    <label style="margin-top:1.5rem;">Forward / Back (single-entry view)</label>
    <p class="sub" style="margin-top:0;">Optional buttons after <strong>Edit</strong> that open the previous or next entry in this database using the same order as the list (sort key and direction on the profile).</p>
    <label style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
      <input type="checkbox" id="entryNavForwardBack" ${entryNavForwardBackVal ? "checked" : ""} style="width:auto;">
      <span style="color:var(--app-text,#e6edf3);">Show Forward and Back on single-entry view</span>
    </label>
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
    const queriesList = ${JSON.stringify(queriesList)};
    function addFlowConfigRow(cfg) {
      const tr = document.createElement('tr');
      tr.className = 'flow-config-row';
      const enabled = !!cfg.enabled;
      const flowId = (cfg && cfg.flowId != null) ? String(cfg.flowId) : '';
      const isSingleStep = !flowId;
      const target = (cfg.target === 'localDb' || cfg.target === 'api' || cfg.target === 'response') ? cfg.target : 'log';
      const label = (cfg && cfg.label != null) ? String(cfg.label).replace(/"/g, '&quot;') : '';
      const param = (cfg && cfg.param != null) ? String(cfg.param).replace(/"/g, '&quot;') : '';
      let flowOpts = '<option value="">Single step</option>';
      flowsList.forEach(function(f) {
        const id = (f._id || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
        const name = (f.name || f._id || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        flowOpts += '<option value="' + id + '"' + (f._id === flowId ? ' selected' : '') + '>' + name + '</option>';
      });
      const targetOptsSingle = '<option value="log"' + (target === 'log' ? ' selected' : '') + '>Log file</option><option value="localDb"' + (target === 'localDb' ? ' selected' : '') + '>Send to Local Database</option><option value="api"' + (target === 'api' ? ' selected' : '') + '>Call API</option><option value="response"' + (target === 'response' ? ' selected' : '') + '>Save as response</option>';
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
          const cur = (targetSel.value === 'localDb' || targetSel.value === 'api' || targetSel.value === 'response') ? targetSel.value : 'log';
          targetSel.innerHTML = '<option value="log"' + (cur === 'log' ? ' selected' : '') + '>Log file</option><option value="localDb"' + (cur === 'localDb' ? ' selected' : '') + '>Send to Local Database</option><option value="api"' + (cur === 'api' ? ' selected' : '') + '>Call API</option><option value="response"' + (cur === 'response' ? ' selected' : '') + '>Save as response</option>';
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
      const typeVal =
        fieldType === "markdown"
          ? "markdown"
          : fieldType === "url"
          ? "url"
          : fieldType === "image"
          ? "image"
          : fieldType === "chart"
          ? "chart"
          : fieldType === "repeat"
          ? "repeat"
          : "text";
      tr.innerHTML =
        '<td><input type="text" class="fl-field" placeholder="Field name or label id" value="' +
        (fieldName || "").replace(/"/g, "&quot;") +
        '"></td><td><input type="number" class="fl-order" min="0" value="' +
        (order != null ? order : n) +
        '"></td><td><select class="fl-type"><option value="text"' +
        (typeVal === "text" ? " selected" : "") +
        '>Text</option><option value="markdown"' +
        (typeVal === "markdown" ? " selected" : "") +
        '>Markdown</option><option value="url"' +
        (typeVal === "url" ? " selected" : "") +
        '>URL</option><option value="image"' +
        (typeVal === "image" ? " selected" : "") +
        '>Image</option><option value="chart"' +
        (typeVal === "chart" ? " selected" : "") +
        '>Chart</option><option value="repeat"' +
        (typeVal === "repeat" ? " selected" : "") +
        '>Repeat group</option></select>' +
        repeatConfigPanelHtml({ visible: typeVal === "repeat", fieldName: fieldName || "" }) +
        '</td><td><input type="text" class="fl-width" placeholder="50%, 1fr, or 40ch" value="' +
        (width || "100%").replace(/"/g, "&quot;") +
        '"></td><td><input type="number" class="fl-x" step="any" placeholder="—"></td><td><input type="number" class="fl-y" step="any" placeholder="—"></td><td><input type="number" class="fl-height" step="any" placeholder="—" min="0"></td><td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      tr.querySelector('.fl-x').value = xv;
      tr.querySelector('.fl-y').value = yv;
      tr.querySelector('.fl-height').value = hv;
      const removeBtn = tr.querySelector('.btn-remove');
      if (removeBtn) {
        removeBtn.onclick = () => tr.remove();
      }
      const typeEl = tr.querySelector('.fl-type');
      if (typeEl) {
        typeEl.addEventListener('change', () => toggleRepeatConfig(tr));
        toggleRepeatConfig(tr);
      }
      wireRepeatConfigPanel(tr);
      tbody.appendChild(tr);
    }

    const defaultRepeatColumnsForDesigner = [
      { key: 'PROMPT', label: 'Prompt', fieldType: 'text' },
      { key: 'RESPONSE', label: 'Response', fieldType: 'text' },
    ];

    function repeatColRowInnerHtml(col) {
      col = col || { key: '', label: '', fieldType: 'text' };
      const key = (col.key || '').replace(/"/g, '&quot;');
      const label = (col.label || '').replace(/"/g, '&quot;');
      const ft = col.fieldType === 'markdown' ? 'markdown' : col.fieldType === 'url' ? 'url' : 'text';
      return '<td><input type="text" class="fl-repeat-col-key" value="' + key + '" placeholder="PROMPT"></td>' +
        '<td><input type="text" class="fl-repeat-col-label" value="' + label + '" placeholder="Label"></td>' +
        '<td><select class="fl-repeat-col-type">' +
        '<option value="text"' + (ft === 'text' ? ' selected' : '') + '>Text</option>' +
        '<option value="markdown"' + (ft === 'markdown' ? ' selected' : '') + '>Markdown</option>' +
        '<option value="url"' + (ft === 'url' ? ' selected' : '') + '>URL</option>' +
        '</select></td>' +
        '<td><button type="button" class="btn btn-remove fl-repeat-col-remove" aria-label="Remove column">Remove</button></td>';
    }

    function repeatConfigPanelHtml(opts) {
      opts = opts || {};
      const visible = !!opts.visible;
      const addLabel = (opts.repeatAddLabel || 'Add row').replace(/"/g, '&quot;');
      const mode = opts.repeatMode === 'stack' ? 'stack' : 'table';
      const cols = Array.isArray(opts.repeatColumns) && opts.repeatColumns.length > 0 ? opts.repeatColumns : defaultRepeatColumnsForDesigner.slice();
      const colRows = cols.map(function(c) {
        return '<tr class="fl-repeat-col-row">' + repeatColRowInnerHtml(c) + '</tr>';
      }).join('');
      return '<div class="fl-repeat-config"' + (visible ? '' : ' style="display:none;"') + '>' +
        '<label class="fl-repeat-sub-label">Repeat layout</label>' +
        '<select class="fl-repeat-mode"><option value="table"' + (mode === 'table' ? ' selected' : '') + '>Table</option><option value="stack"' + (mode === 'stack' ? ' selected' : '') + '>Vertical stack</option></select>' +
        '<label class="fl-repeat-sub-label">Add button label</label>' +
        '<input type="text" class="fl-repeat-add-label" value="' + addLabel + '" placeholder="Add row">' +
        '<label class="fl-repeat-sub-label">Profile fields (linked by row index)</label>' +
        '<table class="fl-repeat-cols-table"><thead><tr><th>Profile field</th><th>Label</th><th>Type</th><th></th></tr></thead><tbody class="fl-repeat-cols-tbody">' + colRows + '</tbody></table>' +
        '<button type="button" class="btn btn-secondary fl-repeat-col-add" style="margin-top:0.35rem;">+ Add column</button>' +
        '</div>';
    }

    function wireRepeatColRow(colTr) {
      const removeBtn = colTr && colTr.querySelector('.fl-repeat-col-remove');
      if (removeBtn) removeBtn.onclick = function() { colTr.remove(); };
    }

    function wireRepeatConfigPanel(row) {
      const cfg = row && row.querySelector('.fl-repeat-config');
      if (!cfg) return;
      const addColBtn = cfg.querySelector('.fl-repeat-col-add');
      const tbody = cfg.querySelector('.fl-repeat-cols-tbody');
      if (addColBtn && tbody) {
        addColBtn.onclick = function() {
          const tr = document.createElement('tr');
          tr.className = 'fl-repeat-col-row';
          tr.innerHTML = repeatColRowInnerHtml({ key: '', label: '', fieldType: 'text' });
          wireRepeatColRow(tr);
          tbody.appendChild(tr);
        };
      }
      cfg.querySelectorAll('.fl-repeat-col-row').forEach(wireRepeatColRow);
    }

    function collectRepeatColumnsFromLayoutRow(tr) {
      const rows = tr.querySelectorAll('.fl-repeat-col-row');
      return Array.from(rows).map(function(colTr) {
        const key = (colTr.querySelector('.fl-repeat-col-key') && colTr.querySelector('.fl-repeat-col-key').value.trim()) || '';
        const labelRaw = colTr.querySelector('.fl-repeat-col-label') && colTr.querySelector('.fl-repeat-col-label').value.trim();
        const label = labelRaw || key;
        const typeEl = colTr.querySelector('.fl-repeat-col-type');
        const fieldType = typeEl && (typeEl.value === 'markdown' || typeEl.value === 'url') ? typeEl.value : 'text';
        if (!key || !/^[\\w.-]+$/.test(key)) return null;
        return { key: key, label: label, fieldType: fieldType };
      }).filter(Boolean);
    }

    function toggleRepeatConfig(row) {
      const typeEl = row && row.querySelector('.fl-type');
      const cfg = row && row.querySelector('.fl-repeat-config');
      if (!cfg) return;
      cfg.style.display = typeEl && typeEl.value === 'repeat' ? 'block' : 'none';
    }
    // Wire remove handlers for any initial field layout rows rendered from the server
    Array.from(tbody.querySelectorAll('.field-layout-row .btn-remove')).forEach((btn) => {
      btn.onclick = () => {
        const row = btn.closest('.field-layout-row');
        if (row) row.remove();
      };
    });
    Array.from(tbody.querySelectorAll('.field-layout-row')).forEach((row) => {
      const typeEl = row.querySelector('.fl-type');
      if (typeEl) {
        typeEl.addEventListener('change', () => toggleRepeatConfig(row));
        toggleRepeatConfig(row);
      }
      wireRepeatConfigPanel(row);
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

    const linkedQueryLoadOnDemandEl = document.getElementById('linkedQueryLoadOnDemand');
    const linkedQueryButtonLabelWrap = document.getElementById('linkedQueryButtonLabelWrap');
    function syncLinkedQueryButtonLabelRow() {
      if (!linkedQueryButtonLabelWrap) return;
      linkedQueryButtonLabelWrap.style.display = (linkedQueryLoadOnDemandEl && linkedQueryLoadOnDemandEl.checked) ? '' : 'none';
    }
    if (linkedQueryLoadOnDemandEl) linkedQueryLoadOnDemandEl.addEventListener('change', syncLinkedQueryButtonLabelRow);
    syncLinkedQueryButtonLabelRow();

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
        const typeEl = tr.querySelector('.fl-type');
        const typeRaw = typeEl ? typeEl.value : "text";
        const isRepeatGroupRow = typeRaw === "repeat" && !firstCol;
        if (!firstCol && !isRepeatGroupRow) return null;
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
        if (firstCol && labelIds.has(firstCol)) {
          item.labelId = firstCol;
        } else if (typeRaw === "repeat") {
          item.fieldType = "repeat";
          if (firstCol) item.fieldName = firstCol;
          else item.repeatGroup = true;
          const modeEl = tr.querySelector(".fl-repeat-mode");
          item.repeatMode = modeEl && modeEl.value === "stack" ? "stack" : "table";
          const addLabelEl = tr.querySelector(".fl-repeat-add-label");
          item.repeatAddLabel =
            addLabelEl && typeof addLabelEl.value === "string" && addLabelEl.value.trim()
              ? addLabelEl.value.trim()
              : "Add row";
          const parsedCols = collectRepeatColumnsFromLayoutRow(tr);
          item.repeatColumns =
            parsedCols.length > 0 ? parsedCols : defaultRepeatColumnsForDesigner.slice();
        } else {
          item.fieldName = firstCol;
          item.fieldType =
            typeRaw === "markdown" ||
            typeRaw === "url" ||
            typeRaw === "image" ||
            typeRaw === "chart"
              ? typeRaw
              : "text";
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
        return !c.flowId && (c.target === '' || (c.target !== 'log' && c.target !== 'localDb' && c.target !== 'api' && c.target !== 'response'));
      });
      if (flowConfigErr) {
        msgEl.textContent = 'When using Single step, please select a Target (Log file, Send to Local Database, Call API, or Save as response) for each flow button.';
        msgEl.className = 'msg err';
        return;
      }
      const url = formId ? '/api/entry-forms/' + encodeURIComponent(formId) : '/api/entry-forms';
      const method = formId ? 'PUT' : 'POST';
      const linkedQueryId = (document.getElementById('linkedQueryId') && document.getElementById('linkedQueryId').value) || '';
      const linkedQueryWidth = (document.getElementById('linkedQueryWidth') && document.getElementById('linkedQueryWidth').value.trim()) || '';
      const linkedQueryButtonLabel = (document.getElementById('linkedQueryButtonLabel') && document.getElementById('linkedQueryButtonLabel').value.trim()) || '';
      const linkedQueryX = parseNumInput(document.getElementById('linkedQueryX'));
      const linkedQueryY = parseNumInput(document.getElementById('linkedQueryY'));
      const linkedQueryH = parseNumInput(document.getElementById('linkedQueryHeight'));
      const linkedQueryLoadOnDemand = !!(document.getElementById('linkedQueryLoadOnDemand') && document.getElementById('linkedQueryLoadOnDemand').checked);
      const body = {
        name,
        labels,
        theme,
        layout,
        fieldLayout,
        customCss,
        flowConfigs,
        entryNavForwardBackEnabled: !!(document.getElementById('entryNavForwardBack') && document.getElementById('entryNavForwardBack').checked),
      };
      if (linkedQueryId && linkedQueryId.trim()) {
        body.linkedQuery = { id: linkedQueryId.trim() };
        if (linkedQueryWidth) body.linkedQuery.width = linkedQueryWidth;
        if (linkedQueryLoadOnDemand && linkedQueryButtonLabel) body.linkedQuery.buttonLabel = linkedQueryButtonLabel;
        if (linkedQueryX != null) body.linkedQuery.x = linkedQueryX;
        if (linkedQueryY != null) body.linkedQuery.y = linkedQueryY;
        if (linkedQueryH != null) body.linkedQuery.height = linkedQueryH;
        if (linkedQueryLoadOnDemand) body.linkedQuery.loadOnDemand = true;
      }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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

function renderStartPage(profiles, role, appUi, keyFileNotice) {
  const keyFileBanner = keyFileNotice ? String(keyFileNotice) : "";
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
  const userAdminOptions = '<option value="" disabled selected>Admin</option><option value="/account/change-password">Change password</option><option value="/account/unlock-keyfile">Provide key file</option>' + (isAdmin ? '<option value="/account/couchdb-password">CouchDB password</option><option value="/account/users">Manage users</option><option value="/account/users/create">Create user</option>' : '');
  const specialOptions = '<option value="" disabled selected>Special</option><option value="/app-config">Application design / theme</option><option value="/application-properties">Application properties</option><option value="/config-export-import">Export / Import configuration</option><option value="/data-export-import">Export / Import data</option><option value="/profiles">Elenko profiles</option><option value="/entry-forms">Single Entry forms</option><option value="/queries">Linked queries</option><option value="/documents">All documents</option><option value="/deletions">Marked for deletion</option>';
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
  ${keyFileBanner}
  <p class="nav-bar">
    ${isAdmin ? actionsAdmin : actionsUser}
    ${actionsCommon}
    <select id="nav-user-admin" class="nav-select nav-select-admin" aria-label="Administration">${userAdminOptions}</select>
    ${isAdmin ? '<select id="nav-flow-processing" class="nav-select nav-select-flow" aria-label="Flow"><option value="" disabled selected>Flow</option><option value="/flows">Flows</option><option value="/timers">Timers</option><option value="/apis">REST APIs</option><option value="/js-processing">JS Processing</option></select>' : ''}
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

function renderEditProfilePage(doc, forms = [], appUi, keyFileUsers = []) {
  const appTheme = normalizeAppTheme(appUi && appUi.theme);
  const appThemeVars = getAppThemeVars(appTheme);
  const name = escapeHtml(doc.name || "");
  const description = escapeHtml(doc.description || "");
  const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const fieldDefaultSources = Array.isArray(doc.fieldDefaultSources) ? doc.fieldDefaultSources : [];
  const initialDefaultSources = fieldNames.map((_, i) => (fieldDefaultSources[i] !== undefined && DEFAULT_VALUE_SOURCES.includes(fieldDefaultSources[i]) ? fieldDefaultSources[i] : ""));
  const initialFieldDisplay = normalizeFieldDisplay(fieldNames, doc.fieldDisplay);
  const initialFieldKinds = normalizeFieldKinds(fieldNames, doc.fieldKinds);
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
  const primaryKeyFieldsCfg = Array.isArray(doc.primaryKeyFields) ? doc.primaryKeyFields : [];
  const primaryKeySegmentLengthsCfg = Array.isArray(doc.primaryKeySegmentLengths) ? doc.primaryKeySegmentLengths : [];
  const dbCode8Display =
    typeof doc.dbCode8 === "string" && doc.dbCode8.length === DB_CODE_LEN
      ? doc.dbCode8
      : "(not assigned yet; save profile)";
  const primaryKeyImportPolicyVal =
    typeof doc.primaryKeyImportPolicy === "string" && doc.primaryKeyImportPolicy.trim()
      ? doc.primaryKeyImportPolicy.trim()
      : "";
  const pkLen0 = String(
    primaryKeySegmentLengthsCfg[0] != null && Number.isFinite(Number(primaryKeySegmentLengthsCfg[0]))
      ? Math.floor(Number(primaryKeySegmentLengthsCfg[0]))
      : 32
  );
  const pkLen1 = String(
    primaryKeySegmentLengthsCfg[1] != null && Number.isFinite(Number(primaryKeySegmentLengthsCfg[1]))
      ? Math.floor(Number(primaryKeySegmentLengthsCfg[1]))
      : 32
  );
  const pkLen2 = String(
    primaryKeySegmentLengthsCfg[2] != null && Number.isFinite(Number(primaryKeySegmentLengthsCfg[2]))
      ? Math.floor(Number(primaryKeySegmentLengthsCfg[2]))
      : 32
  );
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
  const entriesPageSizeRaw = Number(doc.entriesPageSize);
  const entriesPageSize =
    Number.isFinite(entriesPageSizeRaw) &&
    entriesPageSizeRaw >= ENTRIES_PAGE_SIZE_MIN &&
    entriesPageSizeRaw <= ENTRIES_PAGE_SIZE_MAX
      ? Math.floor(entriesPageSizeRaw)
      : ENTRIES_PAGE_SIZE;
  const searchAccentFoldingChecked = isProfileSearchAccentFoldingEnabled(doc);
  const encryptionEnabledChecked = isProfilePersonalEncryptionEnabled(doc);
  const encryptionOwnerUsername =
    getProfileEncryptionOwnerUsername(doc) ||
    (doc.encryption && typeof doc.encryption.ownerUsername === "string" ? doc.encryption.ownerUsername.trim() : "");
  const keyFileUserOptions = (Array.isArray(keyFileUsers) ? keyFileUsers : [])
    .map((u) => {
      const un = u && u.username ? String(u.username) : "";
      if (!un) return "";
      return `<option value="${escapeHtml(un)}"${encryptionOwnerUsername === un ? " selected" : ""}>${escapeHtml(un)}</option>`;
    })
    .join("");
  const splitViewCfgEdit = doc && doc.splitView && typeof doc.splitView === "object" ? doc.splitView : null;
  const splitViewEnabled = !!(splitViewCfgEdit && splitViewCfgEdit.enabled);
  const splitViewOrientation = splitViewCfgEdit && splitViewCfgEdit.orientation === "horizontal" ? "horizontal" : "vertical";
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
  function primaryKeyFieldSelect(id, selected) {
    const fieldOpts = fieldNames
      .map((fn) => `<option value="${escapeHtml(fn)}"${selected === fn ? " selected" : ""}>${escapeHtml(fn)}</option>`)
      .join("");
    return `<select id="${id}" name="${id}"><option value="">— None —</option>${fieldOpts}</select>`;
  }
  const pkSelect1 = primaryKeyFieldSelect("primaryKeyField1", primaryKeyFieldsCfg[0]);
  const pkSelect2 = primaryKeyFieldSelect("primaryKeyField2", primaryKeyFieldsCfg[1]);
  const pkSelect3 = primaryKeyFieldSelect("primaryKeyField3", primaryKeyFieldsCfg[2]);
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
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); font-weight: 600; }
    input[type="text"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input[type="text"]:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    textarea { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    textarea:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    select { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    select:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .field-row { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center; flex-wrap: wrap; }
    .field-row input[name="fieldNames"] { flex: 1; min-width: 10rem; }
    .field-row select[name="fieldKinds"] { flex: 0 0 auto; width: auto; min-width: 5.5rem; max-width: 7rem; font-size: 0.875rem; }
    .field-row select[name="fieldDefaultSources"] { flex: 0 0 auto; width: auto; min-width: 10rem; max-width: 14rem; }
    .field-row select[name="fieldDisplay"] { flex: 0 0 6.75rem; min-width: 6.75rem; max-width: 7.5rem; font-size: 0.875rem; }
    .field-list-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.25rem; font-size: 0.875rem; color: #8b949e; flex-wrap: wrap; }
    .field-list-header .col-name,
    .field-list-header .col-type,
    .field-list-header .col-prefill,
    .field-list-header .col-display {
      padding: 0.5rem;
      border: 1px solid transparent;
      border-radius: 6px;
      box-sizing: border-box;
    }
    .field-list-header .col-name { flex: 1; min-width: 10rem; }
    .field-list-header .col-type { flex: 0 0 auto; min-width: 5.5rem; max-width: 7rem; }
    .field-list-header .col-prefill { flex: 0 0 auto; width: auto; min-width: 10rem; max-width: 14rem; }
    .field-list-header .col-display { flex: 0 0 6.75rem; min-width: 6.75rem; font-size: 0.8rem; }
    .field-list-header .col-action { flex: 0 0 2.75rem; width: 2.75rem; min-width: 2.75rem; box-sizing: border-box; }
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
    <p class="sub" style="margin-top:0.25rem;"><strong>Type</strong> is stored on the profile: <em>Text</em> values live in the entry document; <em>File</em> stores the filename on the entry and the bytes as a CouchDB attachment (images, PDF, or plain text for now—same size limit as entry images). Optional default value is used when creating a new entry. <strong>Display</strong> sets desktop list column width: <em>Auto</em> shares leftover space; <em>Hide</em> hides the column on desktop (still visible on mobile if selected in the mobile list below); percentage widths are scaled so they sum to 100% together.</p>
    <div class="field-list" id="field-list">
      <div class="field-list-header"><span class="col-name">Field name</span><span class="col-type">Type</span><span class="col-prefill">Prefill value</span><span class="col-display">Display</span><span class="col-action"></span></div>
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
    <label for="entriesPageSize" style="margin-top:0.75rem;">Entries per page</label>
    <p class="sub" style="margin-top:0.25rem;">Rows shown in the database list pagination. Default is 25.</p>
    <input type="number" id="entriesPageSize" name="entriesPageSize" min="${ENTRIES_PAGE_SIZE_MIN}" max="${ENTRIES_PAGE_SIZE_MAX}" step="1" value="${escapeHtml(String(entriesPageSize))}">
    <label style="margin-top:1rem;">Entry search: fold accents and umlauts</label>
    <p class="sub" style="margin-top:0.25rem;">When enabled, the database list search treats letters as equal if they differ only by accents or case (for example Lourié matches Lourie; Müller matches Muller). <strong>Performance:</strong> with this on, each search may load and scan up to many thousand entry rows on the server before paginating, which can be slow or memory-heavy for very large databases. When off (default), search is faster and uses the database index, but spelling must match stored text except for letter case. Do not select password or similar secret fields for search indexing — use identifiers such as site or account names instead.</p>
    <label style="display:flex;align-items:flex-start;gap:0.5rem;margin-top:0.35rem;">
      <input type="checkbox" id="searchAccentFolding" name="searchAccentFolding" style="width:auto;margin-top:0.2rem;" ${
        searchAccentFoldingChecked ? "checked" : ""
      }>
      <span>Enable accent folding for search</span>
    </label>
    <label style="margin-top:1.5rem;">Split view (database + single entry)</label>
    <p class="sub" style="margin-top:0.25rem;">Show the database list and selected single-entry view on the same screen. Clicking the first-column link loads the entry in the split pane instead of full-screen navigation.</p>
    <label style="display:flex;align-items:center;gap:0.5rem;margin-top:0.25rem;">
      <input type="checkbox" id="splitViewEnabled" style="width:auto;" ${splitViewEnabled ? "checked" : ""}>
      <span>Enable split view</span>
    </label>
    <div style="max-width:18rem;margin-top:0.5rem;">
      <label for="splitViewOrientation" style="margin-top:0;">Split orientation</label>
      <select id="splitViewOrientation" name="splitViewOrientation">
        <option value="vertical"${splitViewOrientation === "vertical" ? " selected" : ""}>Vertical (left/right)</option>
        <option value="horizontal"${splitViewOrientation === "horizontal" ? " selected" : ""}>Horizontal (top/bottom)</option>
      </select>
    </div>
    <label style="margin-top:1.5rem;">Visible fields in Mobile entry list (up to 3)</label>
    <p class="sub" style="margin-top:0.25rem;">On narrow screens (mobile), only these columns stay visible in the entries table. If empty, the first fields are used.</p>
    <div style="display:flex;flex-wrap:wrap;gap:0.75rem 1rem;align-items:center;margin-top:0.5rem;">
      <div><label for="listField1" style="margin:0;font-size:0.875rem;">1</label><br>${listFieldSelect1}</div>
      <div><label for="listField2" style="margin:0;font-size:0.875rem;">2</label><br>${listFieldSelect2}</div>
      <div><label for="listField3" style="margin:0;font-size:0.875rem;">3</label><br>${listFieldSelect3}</div>
    </div>
    <p class="sub" style="margin-top:1.5rem;margin-bottom:0.25rem;"><strong>Database code (8 characters):</strong> <code id="dbCode8-display">${escapeHtml(dbCode8Display)}</code></p>
    <p class="sub" style="margin-top:0;">First segment of the business primary key. Saving assigns a code; renaming the profile may allocate a new code and recompute keys on entries.</p>
    <label style="margin-top:1.5rem;">Encrypted for personal use</label>
    <p class="sub" style="margin-top:0.25rem;">When enabled, all entry field values are encrypted in CouchDB. Only the selected user (with an unlocked key file at login) can read or edit entries. Attachment file names stay readable; attachment bytes are encrypted.</p>
    <label style="display:flex;align-items:flex-start;gap:0.5rem;margin-top:0.35rem;">
      <input type="checkbox" id="encryptionEnabled" name="encryptionEnabled" style="width:auto;margin-top:0.2rem;" ${
        encryptionEnabledChecked ? "checked" : ""
      }>
      <span>Encrypt all entry data for personal use</span>
    </label>
    <label for="encryptionOwnerUsername" style="margin-top:0.75rem;">Encryption owner</label>
    <p class="sub" style="margin-top:0.25rem;">Must be a user with a registered key file. Log in as this user with the key file unlocked before enabling encryption or importing data.</p>
    <select id="encryptionOwnerUsername" name="encryptionOwnerUsername">
      <option value="">— Select user —</option>
      ${keyFileUserOptions}
    </select>
    <label style="margin-top:1rem;">Primary key segments (up to 3 profile fields)</label>
    <p class="sub" style="margin-top:0.25rem;">Optional. Full key = database code plus truncated and space-padded field values (per segment length). Uniqueness is enforced when saving entries. Do not select password or similar secret fields — use an identifier such as a site or account name instead.</p>
    <p class="sub" style="margin-top:0.35rem;">When you save, if the database code or primary key settings changed, the server writes the computed <code>primaryKey</code> on <strong>every existing entry</strong> in this profile. Enabling or changing the primary key can make that save noticeably slower when there are many entries.</p>
    <div style="display:flex;flex-wrap:wrap;gap:0.75rem 1rem;align-items:flex-end;margin-top:0.5rem;">
      <div><label for="primaryKeyField1" style="margin:0;font-size:0.875rem;">1</label><br>${pkSelect1}<label for="primaryKeyLen1" style="display:block;margin-top:0.35rem;font-size:0.8rem;">Length</label><input type="number" id="primaryKeyLen1" min="${PRIMARY_KEY_SEGMENT_LEN_MIN}" max="${PRIMARY_KEY_SEGMENT_LEN_MAX}" step="1" value="${escapeHtml(pkLen0)}" style="max-width:6rem;padding:0.35rem;background:var(--app-table-bg, #161b22);border:1px solid var(--app-table-border, #30363d);border-radius:6px;color:var(--app-text, #e6edf3);"></div>
      <div><label for="primaryKeyField2" style="margin:0;font-size:0.875rem;">2</label><br>${pkSelect2}<label for="primaryKeyLen2" style="display:block;margin-top:0.35rem;font-size:0.8rem;">Length</label><input type="number" id="primaryKeyLen2" min="${PRIMARY_KEY_SEGMENT_LEN_MIN}" max="${PRIMARY_KEY_SEGMENT_LEN_MAX}" step="1" value="${escapeHtml(pkLen1)}" style="max-width:6rem;padding:0.35rem;background:var(--app-table-bg, #161b22);border:1px solid var(--app-table-border, #30363d);border-radius:6px;color:var(--app-text, #e6edf3);"></div>
      <div><label for="primaryKeyField3" style="margin:0;font-size:0.875rem;">3</label><br>${pkSelect3}<label for="primaryKeyLen3" style="display:block;margin-top:0.35rem;font-size:0.8rem;">Length</label><input type="number" id="primaryKeyLen3" min="${PRIMARY_KEY_SEGMENT_LEN_MIN}" max="${PRIMARY_KEY_SEGMENT_LEN_MAX}" step="1" value="${escapeHtml(pkLen2)}" style="max-width:6rem;padding:0.35rem;background:var(--app-table-bg, #161b22);border:1px solid var(--app-table-border, #30363d);border-radius:6px;color:var(--app-text, #e6edf3);"></div>
    </div>
    <label for="primaryKeyImportPolicy" style="margin-top:0.75rem;">Bulk import policy</label>
    <p class="sub" style="margin-top:0.25rem;">When CSV or picture import would create a duplicate business primary key: <em>Skip duplicate</em> leaves the existing entry unchanged; <em>Overwrite existing</em> replaces that entry’s data (CSV) or the file field and attachment (picture import). Default matches skip.</p>
    <select id="primaryKeyImportPolicy" name="primaryKeyImportPolicy">
      <option value=""${!primaryKeyImportPolicyVal ? " selected" : ""}>— Default —</option>
      <option value="skip"${primaryKeyImportPolicyVal === "skip" ? " selected" : ""}>Skip duplicate</option>
      <option value="overwrite"${primaryKeyImportPolicyVal === "overwrite" ? " selected" : ""}>Overwrite existing</option>
    </select>
    <label style="margin-top:1.5rem;">Sort key fields (up to 3)</label>
    <p class="sub" style="margin-top:0.25rem;">Entry list is sorted by these fields in order (CouchDB index). Use profile fields or Creation/Update date. Do not select password or similar secret fields. On encrypted profiles, sorting runs in memory after decryption and may be slower on large databases.</p>
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
    <p style="margin-top:0.5rem;"><button type="button" class="btn btn-secondary" id="rebuild-sort-keys-btn">Rebuild sort keys and primary keys for existing entries</button> <span id="rebuild-msg"></span></p>
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
    const initialFieldKinds = ${JSON.stringify(initialFieldKinds)};
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

    function addFieldRow(value, defaultSource, kindVal, displayVal) {
      const row = document.createElement('div');
      row.className = 'field-row';
      const esc = (v) => (v || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const selectOpts = defaultSourceOptions.map(function(opt) {
        return '<option value="' + esc(opt.value) + '"' + (defaultSource === opt.value ? ' selected' : '') + '>' + esc(opt.label) + '</option>';
      }).join('');
      const kind = kindVal === 'file' ? 'file' : kindVal === 'repeat' ? 'repeat' : 'text';
      const kindOpts =
        '<option value="text"' + (kind === 'text' ? ' selected' : '') + '>Text</option>' +
        '<option value="repeat"' + (kind === 'repeat' ? ' selected' : '') + '>Repeat</option>' +
        '<option value="file"' + (kind === 'file' ? ' selected' : '') + '>File</option>';
      const disp = displayVal && typeof displayVal === 'string' ? displayVal : 'auto';
      const dispOpts = displayOptions.map(function(opt) {
        return '<option value="' + esc(opt.value) + '"' + (disp === opt.value ? ' selected' : '') + '>' + esc(opt.label) + '</option>';
      }).join('');
      row.innerHTML = '<input type="text" name="fieldNames" placeholder="Field name" value="' + esc(value) + '"><select name="fieldKinds" title="Field type: text, repeat, or file">' + kindOpts + '</select><select name="fieldDefaultSources" title="Default for new entries">' + selectOpts + '</select><select name="fieldDisplay" title="Desktop list column width">' + dispOpts + '</select><button type="button" class="btn btn-remove" aria-label="Remove" title="Remove">✕</button>';
      row.querySelector('.btn-remove').onclick = () => row.remove();
      fieldList.appendChild(row);
    }

    addBtn.onclick = () => addFieldRow('', '', 'text', 'auto');
    (initialFields.length ? initialFields : ['', '']).forEach((v, i) => addFieldRow(v, initialDefaultSources[i] || '', (initialFieldKinds && initialFieldKinds[i]) ? initialFieldKinds[i] : 'text', (initialFieldDisplay && initialFieldDisplay[i]) ? initialFieldDisplay[i] : 'auto'));

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
      const fieldKinds = [];
      const fieldDefaultSources = [];
      const fieldDisplay = [];
      fieldRows.forEach((row) => {
        const input = row.querySelector('input[name="fieldNames"]');
        const kindSel = row.querySelector('select[name="fieldKinds"]');
        const select = row.querySelector('select[name="fieldDefaultSources"]');
        const dispSel = row.querySelector('select[name="fieldDisplay"]');
        const name = input ? input.value.trim() : '';
        if (name) {
          fieldNames.push(name);
          const kv = kindSel && kindSel.value ? kindSel.value : 'text';
          fieldKinds.push(kv === 'file' ? 'file' : kv === 'repeat' ? 'repeat' : 'text');
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
            fieldKinds,
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
            infoImportButtonTitle: (document.getElementById('infoImportButtonTitle') && document.getElementById('infoImportButtonTitle').value.trim()) || '',
            entriesPageSize: (document.getElementById('entriesPageSize') && document.getElementById('entriesPageSize').value) || '${ENTRIES_PAGE_SIZE}',
            searchAccentFolding: !!(document.getElementById('searchAccentFolding') && document.getElementById('searchAccentFolding').checked),
            splitView: {
              enabled: !!(document.getElementById('splitViewEnabled') && document.getElementById('splitViewEnabled').checked),
              orientation: (document.getElementById('splitViewOrientation') && document.getElementById('splitViewOrientation').value === 'horizontal') ? 'horizontal' : 'vertical'
            },
            primaryKeyFields: (function() {
              var ids = ['primaryKeyField1','primaryKeyField2','primaryKeyField3'];
              var lens = ['primaryKeyLen1','primaryKeyLen2','primaryKeyLen3'];
              var fields = [];
              var lengths = [];
              for (var i = 0; i < ids.length; i++) {
                var sel = document.getElementById(ids[i]);
                var v = sel && sel.value ? sel.value.trim() : '';
                if (!v) continue;
                fields.push(v);
                var lenEl = document.getElementById(lens[i]);
                var n = lenEl ? parseInt(lenEl.value, 10) : 32;
                lengths.push(Number.isFinite(n) ? n : 32);
              }
              return fields;
            })(),
            primaryKeySegmentLengths: (function() {
              var ids = ['primaryKeyField1','primaryKeyField2','primaryKeyField3'];
              var lens = ['primaryKeyLen1','primaryKeyLen2','primaryKeyLen3'];
              var lengths = [];
              for (var i = 0; i < ids.length; i++) {
                var sel = document.getElementById(ids[i]);
                var v = sel && sel.value ? sel.value.trim() : '';
                if (!v) continue;
                var lenEl = document.getElementById(lens[i]);
                var n = lenEl ? parseInt(lenEl.value, 10) : 32;
                lengths.push(Number.isFinite(n) ? n : 32);
              }
              return lengths;
            })(),
            primaryKeyImportPolicy: (document.getElementById('primaryKeyImportPolicy') && document.getElementById('primaryKeyImportPolicy').value) || '',
            encryption: {
              enabled: !!(document.getElementById('encryptionEnabled') && document.getElementById('encryptionEnabled').checked),
              ownerUsername: (document.getElementById('encryptionOwnerUsername') && document.getElementById('encryptionOwnerUsername').value) || ''
            }
          })
        });
        const data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        document.getElementById('rev').value = data.rev;
        msgEl.textContent = data.encryptionMigrationPending
          ? 'Profile saved. Log in as the encryption owner with key file unlocked and save again to encrypt existing entries.'
          : 'Profile saved.';
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
    .field-row select[name="fieldKinds"] { flex: 0 0 auto; min-width: 5.5rem; max-width: 7rem; font-size: 0.875rem; }
    .field-row select[name="fieldDisplay"] { flex: 0 0 6.75rem; min-width: 6.75rem; font-size: 0.875rem; }
    .field-list-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.25rem; font-size: 0.875rem; color: #8b949e; flex-wrap: wrap; }
    .field-list-header .col-name,
    .field-list-header .col-type,
    .field-list-header .col-display {
      padding: 0.5rem;
      border: 1px solid transparent;
      border-radius: 6px;
      box-sizing: border-box;
    }
    .field-list-header .col-name { flex: 1; min-width: 8rem; }
    .field-list-header .col-type { flex: 0 0 auto; min-width: 5.5rem; max-width: 7rem; }
    .field-list-header .col-display { flex: 0 0 6.75rem; min-width: 6.75rem; font-size: 0.8rem; }
    .field-list-header .col-action { flex: 0 0 2.75rem; width: 2.75rem; min-width: 2.75rem; box-sizing: border-box; }
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
    <p class="sub" style="margin-top:0.25rem;"><strong>Type</strong>: Text (default) or File (attachment on each entry). <strong>Display</strong> sets desktop list column width (Auto, Hide, or percentages scaled to 100% together).</p>
    <div class="field-list" id="field-list">
      <div class="field-list-header"><span class="col-name">Field name</span><span class="col-type">Type</span><span class="col-display">Display</span><span class="col-action"></span></div>
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
    function addFieldRow(value, kindVal, displayVal) {
      const row = document.createElement('div');
      row.className = 'field-row';
      const esc = (v) => (v || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
      const kind = kindVal === 'file' ? 'file' : kindVal === 'repeat' ? 'repeat' : 'text';
      const kindOpts =
        '<option value="text"' + (kind === 'text' ? ' selected' : '') + '>Text</option>' +
        '<option value="repeat"' + (kind === 'repeat' ? ' selected' : '') + '>Repeat</option>' +
        '<option value="file"' + (kind === 'file' ? ' selected' : '') + '>File</option>';
      const disp = displayVal && typeof displayVal === 'string' ? displayVal : 'auto';
      const dispOpts = displayOptions.map(function(opt) {
        return '<option value="' + esc(opt.value) + '"' + (disp === opt.value ? ' selected' : '') + '>' + esc(opt.label) + '</option>';
      }).join('');
      row.innerHTML = '<input type="text" name="fieldNames" placeholder="Field name" value="' + (value || '').replace(/"/g, '&quot;') + '"><select name="fieldKinds" title="Field type: text, repeat, or file">' + kindOpts + '</select><select name="fieldDisplay" title="Desktop list column width">' + dispOpts + '</select><button type="button" class="btn btn-remove" aria-label="Remove" title="Remove">✕</button>';
      row.querySelector('.btn-remove').onclick = () => row.remove();
      fieldList.appendChild(row);
    }

    addBtn.onclick = () => addFieldRow('', 'text', 'auto');
    addFieldRow('', 'text', 'auto'); addFieldRow('', 'text', 'auto');

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
      const fieldKinds = [];
      const fieldDisplay = [];
      fieldRows.forEach((row) => {
        const input = row.querySelector('input[name="fieldNames"]');
        const kindSel = row.querySelector('select[name="fieldKinds"]');
        const dispSel = row.querySelector('select[name="fieldDisplay"]');
        const fn = input ? input.value.trim() : '';
        if (fn) {
          fieldNames.push(fn);
          const kv = kindSel && kindSel.value ? kindSel.value : 'text';
          fieldKinds.push(kv === 'file' ? 'file' : kv === 'repeat' ? 'repeat' : 'text');
          fieldDisplay.push(dispSel ? dispSel.value : 'auto');
        }
      });
      try {
        const r = await fetch('/api/profiles', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, description, customCss, fieldNames, fieldKinds, fieldDisplay })
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
    input[type="text"], input[type="password"], input[type="file"] { width: 100%; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--app-link, #58a6ff); }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    .login-err { color: #f85149; margin-top: 1rem; }
    .login-hint { color: var(--app-label, #8b949e); font-size: 0.875rem; margin-top: 0.35rem; }
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
    <form method="post" action="/login" enctype="multipart/form-data">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <label for="keyFile">Key file (optional)</label>
      <input type="file" id="keyFile" name="keyFile" accept=".key,application/octet-stream">
      <p class="login-hint">Upload your <code>elenko-username.key</code> file if you have one. Required when &quot;Enforce key-based login&quot; is enabled for your account.</p>
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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

function renderApplicationPropertiesPage(appUi, err) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  ensureAppUiTimeFields(appUi || {});
  const mode = appUi.flowLogDisplayMode || "utc";
  const ianaVal = typeof appUi.flowLogIana === "string" ? appUi.flowLogIana : "";
  const utcOffVal = Number.isFinite(appUi.flowLogUtcOffsetMinutes) ? String(appUi.flowLogUtcOffsetMinutes) : "0";
  const dockAdjVal = Number.isFinite(appUi.flowLogDockerAdjustMinutes) ? String(appUi.flowLogDockerAdjustMinutes) : "0";
  const id = appUi && appUi._id ? String(appUi._id) : "";
  const rev = appUi && appUi._rev ? String(appUi._rev) : "";
  const msgErr = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const now = new Date();
  const serverTz = process.env.TZ && String(process.env.TZ).trim() ? String(process.env.TZ).trim() : "(not set)";
  const serverIso = now.toISOString();
  const serverLocal = now.toString();
  const previewMs = Date.now();
  const tsPreview = new Date(previewMs).toISOString();
  const tsDisplayPreview = computeFlowLogTsDisplay(previewMs, appUi) || "(not shown; choose IANA or fixed UTC offset below)";

  const sel = (v) => (mode === v ? " selected" : "");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Application properties</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    h2 { font-weight: 600; font-size: 1.05rem; margin-top: 1.5rem; margin-bottom: 0.5rem; color: var(--app-text, #e6edf3); }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="text"], input[type="number"] { width: 100%; max-width: 24rem; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    select { width: 100%; max-width: 24rem; padding: 0.5rem; background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 6px; color: var(--app-text, #e6edf3); font-size: 1rem; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-secondary { background: var(--app-table-header-bg, #21262d); color: var(--app-text, #e6edf3); text-decoration: none; margin-left: 0.5rem; border: 1px solid var(--app-table-border, #30363d); }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: var(--app-link, #58a6ff); text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .panel { background: var(--app-table-bg, #161b22); border: 1px solid var(--app-table-border, #30363d); border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.9rem; }
    .panel code { word-break: break-all; font-size: 0.85em; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1f3d2a; color: #3fb950; }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/" class="btn-secondary" style="display:inline-block;padding:0.5rem 1rem;">← Start</a>
    <button type="submit" form="app-props-form" class="btn btn-primary" style="margin-left:1rem;">Save</button>
    <a href="/" class="btn btn-secondary">Cancel</a>
  </div>
  <h1>Application properties</h1>
  <p class="sub">Operational settings independent of theme. Flow log lines always include <code>ts</code> (UTC ISO). When configured below, a second field <code>tsDisplay</code> is added for your local or business timezone.</p>
  ${msgErr}
  <div class="panel">
    <strong>Server (container) clock — reference only</strong>
    <p class="sub" style="margin:0.5rem 0 0 0;"><code>TZ</code> env: ${escapeHtml(serverTz)}</p>
    <p class="sub" style="margin:0.35rem 0 0 0;"><code>Date.toISOString()</code>: <code>${escapeHtml(serverIso)}</code></p>
    <p class="sub" style="margin:0.35rem 0 0 0;"><code>Date.toString()</code> (Node default locale): <code>${escapeHtml(serverLocal)}</code></p>
    <p class="sub" style="margin:0.75rem 0 0 0;">Timers use the server&apos;s local date/time for their start fields. For correct anchors in Docker, set <code>TZ</code> in compose or use UTC in the timer and rely on <code>tsDisplay</code> here for log readability.</p>
  </div>
  <h2>Flow log timestamps</h2>
  <form id="app-props-form">
    ${id ? `<input type="hidden" id="appPropsId" name="_id" value="${escapeHtml(id)}">` : ""}
    ${rev ? `<input type="hidden" id="appPropsRev" name="_rev" value="${escapeHtml(rev)}">` : ""}
    <label for="flowLogDisplayMode">Display mode (adds <code>tsDisplay</code>)</label>
    <select id="flowLogDisplayMode" name="flowLogDisplayMode">
      <option value="utc"${sel("utc")}>UTC only — only <code>ts</code> (default)</option>
      <option value="iana"${sel("iana")}>IANA timezone (e.g. Europe/Berlin)</option>
      <option value="utc_offset"${sel("utc_offset")}>Fixed offset from UTC (no DST)</option>
    </select>
    <label for="flowLogIana">IANA timezone name</label>
    <input type="text" id="flowLogIana" name="flowLogIana" placeholder="Europe/Berlin" value="${escapeHtml(ianaVal)}">
    <p class="sub" style="margin-top:0.25rem;">Used when mode is IANA. Invalid names are skipped when writing the log.</p>
    <label for="flowLogUtcOffsetMinutes">Fixed offset from UTC (minutes)</label>
    <input type="number" id="flowLogUtcOffsetMinutes" name="flowLogUtcOffsetMinutes" min="-840" max="840" step="15" value="${escapeHtml(utcOffVal)}">
    <p class="sub" style="margin-top:0.25rem;">Example: <code>120</code> for UTC+2. Range −840 … +840. Used when mode is &quot;Fixed offset&quot;.</p>
    <label for="flowLogDockerAdjustMinutes">Docker clock correction (minutes)</label>
    <input type="number" id="flowLogDockerAdjustMinutes" name="flowLogDockerAdjustMinutes" min="-10080" max="10080" step="1" value="${escapeHtml(dockAdjVal)}">
    <p class="sub" style="margin-top:0.25rem;">Added to the event time <em>before</em> formatting <code>tsDisplay</code> (e.g. if the container wall clock is two hours slow but you cannot change <code>TZ</code>, try <code>+120</code>). Does not change <code>ts</code>.</p>
  </form>
  <div class="panel">
    <strong>Preview at save time</strong>
    <p class="sub" style="margin:0.5rem 0 0 0;"><code>ts</code>: <code>${escapeHtml(tsPreview)}</code></p>
    <p class="sub" style="margin:0.35rem 0 0 0;"><code>tsDisplay</code>: <code>${escapeHtml(tsDisplayPreview)}</code></p>
  </div>
  <div id="msg" class="msg" style="display:none;"></div>
  <script>
    (function() {
      var form = document.getElementById('app-props-form');
      var msgEl = document.getElementById('msg');
      if (!form || !msgEl) return;
      form.onsubmit = async function(e) {
        e.preventDefault();
        msgEl.style.display = 'none';
        msgEl.textContent = '';
        var payload = {
          flowLogDisplayMode: document.getElementById('flowLogDisplayMode').value,
          flowLogIana: document.getElementById('flowLogIana').value.trim(),
          flowLogUtcOffsetMinutes: document.getElementById('flowLogUtcOffsetMinutes').value,
          flowLogDockerAdjustMinutes: document.getElementById('flowLogDockerAdjustMinutes').value
        };
        var idEl = document.getElementById('appPropsId');
        var revEl = document.getElementById('appPropsRev');
        if (idEl && idEl.value) payload._id = idEl.value;
        if (revEl && revEl.value) payload._rev = revEl.value;
        try {
          var r = await fetch('/api/application-properties', {
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
          msgEl.textContent = 'Saved. New events will use these settings for tsDisplay.';
          msgEl.className = 'msg ok';
          msgEl.style.display = 'block';
          if (data.id && idEl) idEl.value = data.id;
          if (data.rev && revEl) revEl.value = data.rev;
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
    .section { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--app-table-border, #30363d); }
    .radio-group { margin-top: 0.5rem; }
    .radio-group label { display: inline; margin-top: 0; }
    .import-pictures-divider { margin: 1.25rem 0 0; padding-top: 1.25rem; border-top: 1px solid var(--app-table-border, #30363d); }
    .import-pictures-divider h2 { font-size: 1rem; font-weight: 600; margin: 0 0 0.5rem; color: var(--app-text, #e6edf3); }
  </style>
</head>
<body>
  <div class="actions">
    <a href="/" class="back-nav">← Profiles</a>
  </div>
  <h1>Export / Import data</h1>
  <p class="sub">Export entry data from an Elenko database, import rows from a semicolon-separated CSV file, or import multiple pictures into file-type profile fields.</p>

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
    <button type="button" id="export-data-btn" class="btn btn-primary" disabled title="Select an Elenko database first">Export data</button>
    <p class="sub" style="margin-top:0.75rem;">Downloads a semicolon-separated CSV file. The first row lists profile field names (same format as import with header matching enabled).</p>
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

    <div id="import-pictures-block" class="import-pictures-divider" style="display:none;">
      <h2>Import pictures</h2>
      <p class="sub" id="import-pictures-summary" style="margin-top:0;"></p>
      <label for="import-picture-field-select">File field</label>
      <select id="import-picture-field-select" aria-describedby="import-pictures-summary"></select>
      <label for="import-picture-files" style="margin-top:0.75rem;">Pictures</label>
      <input type="file" id="import-picture-files" accept="image/jpeg,image/png,image/webp,image/gif,.jpg,.jpeg,.png,.webp,.gif" multiple>
      <p class="sub" style="margin-top:0.35rem;">JPEG, PNG, WebP, or GIF. Each file becomes one entry; other fields use profile prefill defaults where set. If the business primary key includes this file field, the key uses the filename truncated to the configured segment length. When the key already exists: <em>Skip duplicate</em> ignores the file; <em>Overwrite existing</em> replaces that entry’s attachment and field (profile setting under primary key).</p>
      <button type="button" id="import-pictures-btn" class="btn btn-primary" style="margin-top:0.75rem;">Import pictures</button>
    </div>
  </div>

  <div id="data-import-msg" class="sub" style="display:none; margin-top:1rem; white-space:pre-wrap;"></div>

  <script>
    (function() {
      var exportSection = document.getElementById('export-data-section');
      var importSection = document.getElementById('import-data-section');
      var exportBtn = document.getElementById('export-data-btn');
      var msgEl = document.getElementById('data-import-msg');
      var importBtn = document.getElementById('import-data-btn');
      var fileInput = document.getElementById('import-csv-file');
      var profileSel = document.getElementById('data-profile');
      var headerChk = document.getElementById('import-header-match');
      var picturesBlock = document.getElementById('import-pictures-block');
      var picturesSummary = document.getElementById('import-pictures-summary');
      var pictureFieldSel = document.getElementById('import-picture-field-select');
      var pictureFilesInput = document.getElementById('import-picture-files');
      var picturesBtn = document.getElementById('import-pictures-btn');
      var importMeta = null;

      function escAttr(s) {
        return String(s != null ? s : '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
      }

      function escOptText(s) {
        return String(s != null ? s : '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
      }

      function refreshExportBtn() {
        if (!exportBtn) return;
        var pid = profileSel && profileSel.value ? profileSel.value.trim() : '';
        exportBtn.disabled = !pid;
        exportBtn.title = pid ? '' : 'Select an Elenko database first';
      }

      function refreshImportMeta() {
        importMeta = null;
        if (picturesBlock) picturesBlock.style.display = 'none';
        if (pictureFieldSel) pictureFieldSel.innerHTML = '';
        var modeImp = document.querySelector('input[name="dataMode"]:checked');
        var isImport = modeImp && modeImp.value === 'import';
        var pid = profileSel && profileSel.value ? profileSel.value.trim() : '';
        if (!isImport || !pid || !picturesBlock) return;
        fetch('/api/profiles/' + encodeURIComponent(pid) + '/data-import-meta')
          .then(function(r) {
            return r.json().then(function(d) {
              return { ok: r.ok, status: r.status, data: d };
            });
          })
          .then(function(o) {
            if (!o.ok || !o.data || !Array.isArray(o.data.fileFields) || o.data.fileFields.length === 0) {
              return;
            }
            importMeta = o.data;
            picturesBlock.style.display = 'block';
            if (pictureFieldSel) {
              pictureFieldSel.innerHTML = o.data.fileFields
                .map(function(fn) {
                  return '<option value="' + escAttr(fn) + '">' + escOptText(fn) + '</option>';
                })
                .join('');
            }
            if (picturesSummary) {
              var lines = [
                'This profile has file-type field(s): ' + o.data.fileFields.map(function(f) { return '"' + f + '"'; }).join(', ') + '.'
              ];
              if (o.data.fileFieldsInPrimaryKey && o.data.fileFieldsInPrimaryKey.length) {
                lines.push(
                  'Included in the business primary key: ' +
                    o.data.fileFieldsInPrimaryKey.map(function(f) { return '"' + f + '"'; }).join(', ') +
                    '.'
                );
              }
              var pol = o.data.primaryKeyImportPolicy || '';
              if (pol === 'overwrite') {
                lines.push('Bulk import policy: overwrite existing entry when the primary key matches.');
              } else if (pol === 'skip') {
                lines.push('Bulk import policy: skip files that would duplicate an existing primary key.');
              } else {
                lines.push('Bulk import policy: default (skip duplicates) unless you set Overwrite on the profile.');
              }
              picturesSummary.textContent = lines.join(' ');
            }
          })
          .catch(function() {
            importMeta = null;
            if (picturesBlock) picturesBlock.style.display = 'none';
          });
      }

      function setMode(isImport) {
        if (exportSection) exportSection.style.display = isImport ? 'none' : 'block';
        if (importSection) importSection.style.display = isImport ? 'block' : 'none';
        if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
        refreshExportBtn();
        refreshImportMeta();
      }
      document.querySelectorAll('input[name="dataMode"]').forEach(function(r) {
        r.addEventListener('change', function() {
          setMode(r.value === 'import');
        });
      });
      if (profileSel) {
        profileSel.addEventListener('change', function() {
          refreshExportBtn();
          refreshImportMeta();
        });
      }
      refreshExportBtn();

      if (exportBtn) {
        exportBtn.addEventListener('click', function() {
          var pid = profileSel && profileSel.value ? profileSel.value.trim() : '';
          if (!pid) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Select an Elenko database first.';
            }
            return;
          }
          exportBtn.disabled = true;
          if (msgEl) {
            msgEl.style.display = 'block';
            msgEl.style.color = 'var(--app-label, #8b949e)';
            msgEl.textContent = 'Exporting…';
          }
          fetch('/api/profiles/' + encodeURIComponent(pid) + '/export-data')
            .then(function(r) {
              var ct = r.headers.get('content-type') || '';
              if (!r.ok) {
                return r.text().then(function(t) {
                  var d = null;
                  try { d = t && t.length ? JSON.parse(t) : null; } catch (_) {}
                  return Promise.reject(new Error((d && d.error) ? d.error : ('Export failed (HTTP ' + r.status + ')')));
                });
              }
              if (ct.indexOf('json') >= 0) {
                return r.json().then(function(d) {
                  return Promise.reject(new Error((d && d.error) ? d.error : 'Export failed'));
                });
              }
              var disp = r.headers.get('Content-Disposition') || '';
              var fnMatch = /filename=\"?([^\";]+)\"?/i.exec(disp);
              var filename = fnMatch ? fnMatch[1] : 'elenko-export.csv';
              return r.blob().then(function(blob) {
                return { blob: blob, filename: filename };
              });
            })
            .then(function(o) {
              var url = URL.createObjectURL(o.blob);
              var a = document.createElement('a');
              a.href = url;
              a.download = o.filename;
              document.body.appendChild(a);
              a.click();
              a.remove();
              setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
              if (msgEl) {
                msgEl.style.display = 'block';
                msgEl.style.color = '#7ee787';
                msgEl.textContent = 'Export downloaded: ' + o.filename;
              }
            })
            .catch(function(e) {
              if (msgEl) {
                msgEl.style.display = 'block';
                msgEl.style.color = '#f85149';
                msgEl.textContent = e.message || 'Export failed';
              }
            })
            .finally(function() {
              refreshExportBtn();
            });
        });
      }

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
                    var lines = ['Imported ' + (o.data.imported || 0) + ' new row(s).'];
                    if (o.data.overwritten) {
                      lines.push('Updated ' + o.data.overwritten + ' existing row(s) (same primary key).');
                    }
                    if (o.data.skippedDuplicates) {
                      lines.push('Skipped ' + o.data.skippedDuplicates + ' row(s) (duplicate primary key).');
                    }
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

      if (picturesBtn) {
        picturesBtn.addEventListener('click', function() {
          var pid = profileSel && profileSel.value ? profileSel.value.trim() : '';
          if (!pid) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Select an Elenko database first.';
            }
            return;
          }
          if (!importMeta || !importMeta.fileFields || !importMeta.fileFields.length) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'This profile has no file-type fields for picture import.';
            }
            return;
          }
          var fieldName = pictureFieldSel && pictureFieldSel.value ? pictureFieldSel.value.trim() : '';
          if (!fieldName) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Choose a file field.';
            }
            return;
          }
          var files = pictureFilesInput && pictureFilesInput.files ? pictureFilesInput.files : null;
          if (!files || !files.length) {
            if (msgEl) {
              msgEl.style.display = 'block';
              msgEl.style.color = '#f85149';
              msgEl.textContent = 'Choose one or more pictures.';
            }
            return;
          }
          picturesBtn.disabled = true;
          if (msgEl) {
            msgEl.style.display = 'block';
            msgEl.style.color = 'var(--app-label, #8b949e)';
            msgEl.textContent = 'Uploading…';
          }
          var fd = new FormData();
          fd.append('fieldName', fieldName);
          for (var i = 0; i < files.length; i++) {
            fd.append('files', files[i]);
          }
          fetch('/api/profiles/' + encodeURIComponent(pid) + '/import-pictures', { method: 'POST', body: fd })
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
                        (t && t.length ? t.slice(0, 120).replace(/\\s+/g, ' ') : ''),
                    },
                  };
                }
                return { ok: r.ok, data: d };
              });
            })
            .then(function(o) {
              picturesBtn.disabled = false;
              if (!msgEl) return;
              msgEl.style.display = 'block';
              if (o.ok && o.data && o.data.ok) {
                msgEl.style.color = '#7ee787';
                var lines = ['Imported ' + (o.data.imported || 0) + ' new entr' + ((o.data.imported || 0) === 1 ? 'y' : 'ies') + '.'];
                if (o.data.overwritten) {
                  lines.push('Updated ' + o.data.overwritten + ' existing (same primary key).');
                }
                if (o.data.skippedDuplicates) {
                  lines.push('Skipped ' + o.data.skippedDuplicates + ' (duplicate primary key).');
                }
                if (o.data.failed) lines.push('Failed: ' + o.data.failed + ' file(s).');
                if (o.data.rowErrors && o.data.rowErrors.length) {
                  lines.push('');
                  o.data.rowErrors.forEach(function(err) {
                    lines.push(String(err.row) + ': ' + err.message);
                  });
                }
                msgEl.textContent = lines.join(String.fromCharCode(10));
              } else {
                msgEl.style.color = '#f85149';
                msgEl.textContent = (o.data && o.data.error) ? o.data.error : 'Import failed';
              }
            })
            .catch(function(e) {
              picturesBtn.disabled = false;
              if (msgEl) {
                msgEl.style.display = 'block';
                msgEl.style.color = '#f85149';
                msgEl.textContent = e.message || 'Request failed';
              }
            });
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
    ? '<option value="__app__">Elenko App Design</option><option value="">— Select database —</option>' +
        profiles.map((p) => `<option value="${escapeHtml(p._id)}">${escapeHtml(p.name || p._id)}</option>`).join("")
    : '<option value="__app__">Elenko App Design</option><option value="">No databases</option>';
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
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
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
      <p class="sub" style="margin-top:0.25rem;">"One Elenko database" exports the selected profile, its linked entry forms and flows, timers that target this profile (and their flows), linked queries, and APIs / JS Processing used by those flows. "All" also includes the Application design document.</p>
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
        var summary = { profiles: 0, entryForms: 0, flows: 0, apis: 0, jsProcessing: 0, appConfig: 0, queries: 0, timers: 0 };
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
          if (doc.type === 'elenko_query') summary.queries += 1;
          if (doc.type === 'elenko_timer') summary.timers += 1;
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
            'linked queries: ' + c.queries,
            'flows: ' + c.flows,
            'timers: ' + c.timers,
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
            const hasKey = !!(u.keyFile && u.keyFile.registered === true);
            const keyStatus = hasKey ? '<span class="key-ok">Registered</span>' : '<span class="muted">None</span>';
            const expectedKeyName = escapeHtml(keyFileDownloadFilename(u.username || "user"));
            const keyActions = hasKey
              ? `<button type="button" class="btn-regen-key">Regenerate key</button>
                 <button type="button" class="btn-remove-key">Remove key</button>
                 <input type="file" class="user-keyfile-upload" accept=".key,application/octet-stream" hidden aria-hidden="true">
                 <button type="button" class="btn-upload-key" title="Upload ${expectedKeyName}">Replace from file</button>`
              : `<button type="button" class="btn-gen-key">Generate key</button>
                 <input type="file" class="user-keyfile-upload" accept=".key,application/octet-stream" hidden aria-hidden="true">
                 <button type="button" class="btn-upload-key" title="Upload ${expectedKeyName}">Upload existing key</button>`;
            const enforceChecked = u.enforceKeyLogin === true ? " checked" : "";
            return `
        <tr data-id="${id}" data-rev="${rev}" data-username="${escapeHtml(u.username || "")}" data-has-key="${hasKey ? "1" : "0"}">
          <td><strong>${username}</strong></td>
          <td><select class="user-role-select" aria-label="Role">${roleOptions}</select></td>
          <td>${keyStatus}<br>${keyActions}</td>
          <td><label class="enforce-label"><input type="checkbox" class="user-enforce-key"${enforceChecked}> Enforce</label></td>
          <td><input type="password" class="user-new-password" placeholder="New password" autocomplete="new-password" style="max-width:12rem;"> <button type="button" class="btn-set-password">Set password</button></td>
          <td>${isSelf ? '<span class="muted">(you)</span>' : `<button type="button" class="btn-delete-user">Delete</button>`}</td>
        </tr>`;
          })
          .join("")
      : `<tr><td colspan="6" class="empty">No users yet. <a href="/account/users/create">Create user</a></td></tr>`;

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
    .btn-set-password, .btn-delete-user, .btn-gen-key, .btn-regen-key, .btn-upload-key, .btn-remove-key { padding: 0.35rem 0.75rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; margin-top: 0.35rem; }
    .btn-set-password, .btn-gen-key { background: #238636; color: #fff; }
    .btn-set-password:hover, .btn-gen-key:hover { background: #2ea043; }
    .btn-upload-key { background: #1f6feb; color: #fff; }
    .btn-upload-key:hover { background: #388bfd; }
    .btn-regen-key { background: #9e6a03; color: #fff; }
    .btn-regen-key:hover { background: #bb8009; }
    .btn-remove-key { background: #21262d; color: #e6edf3; border: 1px solid #484f58; }
    .btn-remove-key:hover { background: #30363d; }
    .btn-delete-user { background: #da3633; color: #fff; }
    .btn-delete-user:hover { background: #f85149; }
    .key-ok { color: #3fb950; font-size: 0.875rem; }
    .enforce-label { display: flex; align-items: center; gap: 0.35rem; cursor: pointer; font-weight: normal; color: var(--app-text, #e6edf3); }
    .enforce-label input { margin: 0; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
    a { color: var(--app-link, #58a6ff); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-left: 0.5rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    a.btn:not(.btn-secondary) { color: #fff; }
    a.btn:hover:not(.btn-secondary) { color: #fff; text-decoration: none; }
    .actions { margin-bottom: 1rem; }
    .actions > a:first-of-type {
      font-size: 1.35rem;
      line-height: 1;
    }
    @media (max-width: 768px) {
      .actions > a:first-of-type {
        font-size: 1.9rem;
        line-height: 1;
        padding: 0.45rem 0.65rem;
        margin: -0.45rem 0.5rem -0.45rem 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 2.75rem;
        min-height: 2.75rem;
      }
    }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a> <a href="/account/users/create" class="btn">Create user</a></div>
  <h1>Manage users</h1>
  <p class="sub">Change role, key file, enforce key login, set password, or delete users. Upload an existing <code>elenko-&lt;username&gt;.key</code> file to register the same key on this instance (user must have no key yet).</p>
  <table>
    <thead>
      <tr>
        <th>Username</th>
        <th>Role</th>
        <th>Key file</th>
        <th>Enforce key login</th>
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

    document.querySelectorAll('.user-enforce-key').forEach(chk => {
      chk.addEventListener('change', async function() {
        const row = this.closest('tr');
        if (!row || row.querySelector('.empty')) return;
        const id = row.getAttribute('data-id');
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enforceKeyLogin: this.checked }) });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Update failed', true); this.checked = !this.checked; return; }
          showMsg('Enforce key login updated.');
        } catch (e) { showMsg(e.message || 'Request failed', true); this.checked = !this.checked; }
      });
    });

    document.querySelectorAll('.btn-gen-key').forEach(btn => {
      btn.addEventListener('click', async function() {
        const row = this.closest('tr');
        if (!row) return;
        const id = row.getAttribute('data-id');
        this.disabled = true;
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id) + '/generate-keyfile', { method: 'POST' });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Generate failed', true); return; }
          if (data.downloadUrl) window.location.href = data.downloadUrl;
          else showMsg('Key file generated.');
        } catch (e) { showMsg(e.message || 'Request failed', true); }
        finally { this.disabled = false; }
      });
    });

    document.querySelectorAll('.btn-upload-key').forEach(btn => {
      btn.addEventListener('click', function() {
        const row = this.closest('tr');
        if (!row) return;
        const input = row.querySelector('.user-keyfile-upload');
        if (input) input.click();
      });
    });

    document.querySelectorAll('.user-keyfile-upload').forEach(input => {
      input.addEventListener('change', async function() {
        const file = this.files && this.files[0];
        if (!file) return;
        const row = this.closest('tr');
        if (!row) return;
        const id = row.getAttribute('data-id');
        const username = row.getAttribute('data-username') || '';
        const hasKey = row.getAttribute('data-has-key') === '1';
        let namePart = username.replace(/[^\\w.-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 64);
        if (!namePart) namePart = 'user';
        const expected = 'elenko-' + namePart + '.key';
        if (file.name.toLowerCase() !== expected.toLowerCase()) {
          showMsg('File name must be ' + expected + ' for this user.', true);
          this.value = '';
          return;
        }
        if (hasKey && !window.confirm(
          'Replace the registered key with ' + expected + '?\\n\\n' +
          'The currently registered key will stop working on this instance. Use this to restore a previously saved key file.'
        )) {
          this.value = '';
          return;
        }
        const uploadBtn = row.querySelector('.btn-upload-key');
        if (uploadBtn) uploadBtn.disabled = true;
        const fd = new FormData();
        fd.append('keyFile', file);
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id) + '/upload-keyfile', { method: 'POST', body: fd });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Upload failed', true); return; }
          showMsg(data.message || 'Key file registered.');
          setTimeout(function() { window.location.reload(); }, 800);
        } catch (e) {
          showMsg(e.message || 'Request failed', true);
        } finally {
          this.value = '';
          if (uploadBtn) uploadBtn.disabled = false;
        }
      });
    });

    document.querySelectorAll('.btn-regen-key').forEach(btn => {
      btn.addEventListener('click', async function() {
        const row = this.closest('tr');
        if (!row) return;
        if (!window.confirm(
          'Regenerate key file?\\n\\n' +
          '• The previous key file will stop working on this instance immediately.\\n' +
          '• When database encryption is enabled (future), data encrypted with the old key will become inaccessible unless you still have that old .key file.\\n\\n' +
          'Continue?'
        )) return;
        const id = row.getAttribute('data-id');
        this.disabled = true;
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id) + '/regenerate-keyfile', { method: 'POST' });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Regenerate failed', true); return; }
          if (data.downloadUrl) window.location.href = data.downloadUrl;
          else showMsg('Key file regenerated.');
        } catch (e) { showMsg(e.message || 'Request failed', true); }
        finally { this.disabled = false; }
      });
    });

    document.querySelectorAll('.btn-remove-key').forEach(btn => {
      btn.addEventListener('click', async function() {
        const row = this.closest('tr');
        if (!row) return;
        if (!window.confirm(
          'Remove key registration for this user?\\n\\n' +
          'Login will no longer accept the current key file until you generate a new one or upload a .key file.\\n' +
          'Use this to restore a previously saved key file via Upload / Replace from file.'
        )) return;
        const id = row.getAttribute('data-id');
        this.disabled = true;
        try {
          const r = await fetch('/api/account/users/' + encodeURIComponent(id) + '/keyfile', { method: 'DELETE' });
          const data = await r.json();
          if (!r.ok) { showMsg(data.error || 'Remove failed', true); return; }
          showMsg(data.message || 'Key registration removed.');
          setTimeout(function() { window.location.reload(); }, 800);
        } catch (e) { showMsg(e.message || 'Request failed', true); }
        finally { this.disabled = false; }
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

function renderKeyFileDownloadPage(filename, token) {
  const safeName = escapeHtml(filename || "elenko-user.key");
  const safeToken = escapeHtml(token || "");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Download key file</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 32rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; font-size: 1.25rem; }
    .warn { background: #3d2e00; color: #f0c040; padding: 0.75rem 1rem; border-radius: 6px; margin: 1rem 0; line-height: 1.5; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; background: #238636; color: #fff; text-decoration: none; margin-top: 0.5rem; }
    .btn:hover { background: #2ea043; }
    a.muted { color: #58a6ff; }
  </style>
</head>
<body>
  <h1>Download key file</h1>
  <p>File: <strong>${safeName}</strong></p>
  <div class="warn">Store this file in a safe place. It cannot be recovered if lost. Anyone with this file and your password can access encrypted databases (when enabled). Regenerating a key invalidates the previous file on this instance; encrypted databases (future) need the key that was used to encrypt them.</div>
  <p><a class="btn" href="/account/users/keyfile-download?token=${safeToken}&amp;download=1">Download ${safeName}</a></p>
  <p><a class="muted" href="/account/users">← Manage users</a></p>
</body>
</html>`;
}

function renderUnlockKeyFilePage(errorMessage, appUi, session) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  const registered = session && session.keyFileRegistered;
  const unlocked = session && session.keyFileUnlocked;
  const status = unlocked
    ? '<p class="msg ok">Key file is loaded for this session.</p>'
    : registered
    ? '<p class="sub">Upload your key file to load it into this session.</p>'
    : '<p class="sub">No key file is registered for your account.</p>';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${FAVICON_LINKS}
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Provide key file</title>
  <style>
    ${themeVars}
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--app-bg, #0f1419); color: var(--app-text, #e6edf3); max-width: 24rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: var(--app-label, #8b949e); margin-bottom: 1rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: var(--app-label, #8b949e); }
    input[type="file"] { width: 100%; color: var(--app-label, #8b949e); }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn-secondary { display: inline-block; margin-top: 0.5rem; background: #21262d; color: #e6edf3; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; }
    .login-err { color: #f85149; margin-top: 1rem; }
    .msg.ok { color: #3fb950; margin-top: 1rem; }
  </style>
</head>
<body>
  <h1>Provide key file</h1>
  ${status}
  ${err}
  ${registered && !unlocked ? `<form method="post" action="/account/unlock-keyfile" enctype="multipart/form-data">
    <label for="keyFile">Key file</label>
    <input type="file" id="keyFile" name="keyFile" accept=".key,application/octet-stream" required>
    <button type="submit" class="btn">Load key file</button>
  </form>` : ""}
  <a href="/" class="btn-secondary">Back to start</a>
</body>
</html>`;
}

function renderCreateUserPage(errorMessage, created, appUi, keyfileToken) {
  const theme = normalizeAppTheme(appUi && appUi.theme);
  const themeVars = getAppThemeVars(theme);
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  const createdMsg = created ? '<p class="msg ok">User created.</p>' : "";
  const token = typeof keyfileToken === "string" ? keyfileToken.trim() : "";
  const keyDownloadMsg =
    created && token
      ? `<p class="msg ok">Key file generated. <a href="/account/users/keyfile-download?token=${escapeHtml(token)}" style="color:#7ee787;">Download key file</a> (link expires in a few minutes).</p>`
      : "";
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
    .checkbox-row { margin-top: 1rem; }
    .checkbox-row label { display: flex; align-items: flex-start; gap: 0.5rem; cursor: pointer; color: var(--app-text, #e6edf3); font-weight: normal; }
    .checkbox-row .hint { color: var(--app-label, #8b949e); font-size: 0.875rem; margin-top: 0.25rem; margin-left: 1.5rem; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="sub">Create new user</p>
  ${createdMsg}
  ${keyDownloadMsg}
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
    <div class="checkbox-row">
      <label><input type="checkbox" name="generateKeyFile" value="1" checked> Generate key file</label>
      <p class="hint">Creates <code>elenko-username.key</code> for download after save. Only a hash is stored on the server.</p>
    </div>
    <div class="checkbox-row">
      <label><input type="checkbox" name="enforceKeyLogin" value="1"> Enforce key-based login</label>
      <p class="hint">When enabled and a key file is registered, login requires a valid key file upload.</p>
    </div>
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

/** Multer and other unhandled errors: return JSON for /api/* so fetch().json() never receives HTML. */
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (!wantsJsonApiResponse(req)) return next(err);
  console.error("[api] error", req.method, req.path, err && err.message);
  if (err && err.name === "MulterError") {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "File too large (max " + Math.round(MAX_ENTRY_IMAGE_BYTES / 1024) + " KiB).",
      });
    }
    return res.status(400).json({ error: err.message || "Upload failed" });
  }
  const code = err && (err.status || err.statusCode);
  const status = typeof code === "number" && code >= 400 && code < 600 ? code : 500;
  return res.status(status).json({ error: (err && err.message) || "Server error" });
});

async function main() {
  await initCouch();
  await getAppUiConfig();
  startApiWorker();
  startFlowWorker();
  startTimerWorker();
  await syncTimersFromDb();
  setInterval(() => {
    syncTimersFromDb().catch((e) => console.error("syncTimersFromDb:", e));
  }, 5 * 60 * 1000);
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
