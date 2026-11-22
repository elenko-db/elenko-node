/**
 * Elenko application user password rules (elenko_user documents).
 * Common-password checks are entirely local (bundled + optional file); no network calls.
 * Optional future: Have I Been Pwned k-anonymity API (SHA-1 prefix only) for breached-password signal.
 */
const fs = require("fs");
const path = require("path");

const PASSWORD_MAX_LEN = 256;
const PASSWORD_MIN_LEN_DEFAULT = 10;
const PASSWORD_MIN_LEN_MIN = 8;
const PASSWORD_MIN_LEN_MAX = 128;
const PASSWORD_MIN_CLASSES_DEFAULT = 2;
const PASSWORD_MIN_CLASSES_MIN = 1;
const PASSWORD_MIN_CLASSES_MAX = 4;

const BUILTIN_COMMON_PASSWORDS = new Set(
  [
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "abc123",
    "111111",
    "123123",
    "admin",
    "admin123",
    "administrator",
    "letmein",
    "welcome",
    "welcome1",
    "monkey",
    "dragon",
    "master",
    "login",
    "passw0rd",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "iloveyou",
    "trustno1",
    "000000",
    "654321",
    "superman",
    "batman",
    "starwars",
    "changeme",
    "access",
    "secret",
    "p@ssw0rd",
    "qazwsx",
    "asdfgh",
    "zxcvbn",
    "zaq12wsx",
    "1q2w3e4r",
    "1qaz2wsx",
    "querty",
    "solo",
    "whatever",
    "freedom",
    "nothing",
    "summer",
    "winter",
    "spring",
    "autumn",
    "computer",
    "internet",
    "database",
    "couchdb",
    "elenko",
    "elenko123",
    "test",
    "test123",
    "guest",
    "root",
    "toor",
    "pass",
    "pa55word",
  ].map((s) => s.toLowerCase())
);

function parseBoundedInt(v, def, min, max) {
  const n = parseInt(String(v ?? ""), 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

function resolveMinPasswordLength() {
  return parseBoundedInt(
    process.env.USER_PASSWORD_MIN_LENGTH,
    PASSWORD_MIN_LEN_DEFAULT,
    PASSWORD_MIN_LEN_MIN,
    PASSWORD_MIN_LEN_MAX
  );
}

function resolveMinPasswordClasses() {
  return parseBoundedInt(
    process.env.USER_PASSWORD_MIN_CLASSES,
    PASSWORD_MIN_CLASSES_DEFAULT,
    PASSWORD_MIN_CLASSES_MIN,
    PASSWORD_MIN_CLASSES_MAX
  );
}

function isCommonPasswordCheckEnabled() {
  const raw = process.env.USER_PASSWORD_CHECK_COMMON;
  if (raw == null || String(raw).trim() === "") return true;
  return !/^(0|false|no|off)$/i.test(String(raw).trim());
}

function loadCommonPasswordSet() {
  const set = new Set(BUILTIN_COMMON_PASSWORDS);
  const defaultFile = path.join(__dirname, "data", "common-passwords.txt");
  const filePath =
    process.env.USER_PASSWORD_DENYLIST_FILE != null && String(process.env.USER_PASSWORD_DENYLIST_FILE).trim()
      ? path.resolve(String(process.env.USER_PASSWORD_DENYLIST_FILE).trim())
      : defaultFile;
  try {
    if (fs.existsSync(filePath)) {
      const text = fs.readFileSync(filePath, "utf8");
      for (const line of text.split(/\r?\n/)) {
        const t = line.replace(/#.*$/, "").trim().toLowerCase();
        if (t) set.add(t);
      }
    }
  } catch (e) {
    console.warn("userPasswordPolicy: could not load denylist file:", e.message || e);
  }
  return set;
}

const commonPasswordSet = loadCommonPasswordSet();

function countPasswordCharacterClasses(password) {
  let n = 0;
  if (/[a-z]/.test(password)) n += 1;
  if (/[A-Z]/.test(password)) n += 1;
  if (/\d/.test(password)) n += 1;
  if (/[^A-Za-z0-9]/.test(password)) n += 1;
  return n;
}

function getUserPasswordPolicyHint() {
  const minLen = resolveMinPasswordLength();
  const minClasses = resolveMinPasswordClasses();
  const common = isCommonPasswordCheckEnabled();
  let s = `At least ${minLen} characters`;
  if (minClasses > 1) {
    s += `, using at least ${minClasses} of: lowercase, uppercase, digit, symbol`;
  }
  s += ", not the same as the username";
  if (common) s += ", and not a common password";
  return s + ".";
}

/**
 * @param {string} password
 * @param {{ username?: string }} [context]
 * @returns {{ ok: true } | { ok: false, error: string }}
 */
function validateUserPassword(password, context) {
  const pw = typeof password === "string" ? password : "";
  if (!pw) {
    return { ok: false, error: "Password is required." };
  }
  if (pw.length > PASSWORD_MAX_LEN) {
    return { ok: false, error: `Password must be at most ${PASSWORD_MAX_LEN} characters.` };
  }
  const minLen = resolveMinPasswordLength();
  if (pw.length < minLen) {
    return { ok: false, error: `Password must be at least ${minLen} characters.` };
  }
  const minClasses = resolveMinPasswordClasses();
  const classes = countPasswordCharacterClasses(pw);
  if (classes < minClasses) {
    return {
      ok: false,
      error: `Password must include at least ${minClasses} character types (lowercase, uppercase, digit, symbol).`,
    };
  }
  const username =
    context && context.username != null ? String(context.username).trim().toLowerCase() : "";
  if (username && pw.toLowerCase() === username) {
    return { ok: false, error: "Password must not be the same as the username." };
  }
  if (isCommonPasswordCheckEnabled() && commonPasswordSet.has(pw.toLowerCase())) {
    return { ok: false, error: "This password is too common. Choose a stronger unique password." };
  }
  return { ok: true };
}

module.exports = {
  validateUserPassword,
  getUserPasswordPolicyHint,
  resolveMinPasswordLength,
  isCommonPasswordCheckEnabled,
};