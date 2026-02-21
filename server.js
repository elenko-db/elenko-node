const crypto = require("crypto");
const { Worker } = require("worker_threads");
const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const iconv = require("iconv-lite");
const nano = require("nano");

const app = express();
const PORT = process.env.PORT || 3000;
const COUCHDB_URL = process.env.COUCHDB_URL || "http://admin:admin@localhost:5984";
const COUCHDB_DB = process.env.COUCHDB_DB || "elenko";
const IO_DIR = process.env.IO_DIR || path.join(__dirname, "io");
const MAX_ENTRIES_PER_PROFILE = 500000;
const ENTRIES_PAGE_SIZE = 25;

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
        return { ...base, fieldName: item.fieldName.trim() };
      }
      return { ...base, labelId: item.labelId.trim() };
    });
  const flowButtonEnabled = !!(body.flowButtonEnabled === true || body.flowButtonEnabled === "true");
  const flowTargetRaw = typeof body.flowTarget === "string" ? body.flowTarget.trim() : "";
  const flowTarget = flowTargetRaw === "log" ? "log" : "log"; // only "log" for now; expand later
  const flowButtonLabel = typeof body.flowButtonLabel === "string" ? body.flowButtonLabel.trim() : "";
  const flowButtonParam = typeof body.flowButtonParam === "string" ? body.flowButtonParam.trim() : "";

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
    flowButtonEnabled,
    flowTarget,
    flowButtonLabel: flowButtonLabel || "Send to Flow",
    flowButtonParam,
  };
}

function escapeRegex(s) {
  return String(s).replace(/[\\^$.*+?()|[\]{}]/g, "\\$&");
}

const PBKDF2_ITERATIONS = 100000;
const SALT_LEN = 16;
const KEY_LEN = 32;

let flowWorker;

function startFlowWorker() {
  const workerPath = path.join(__dirname, "flowWorker.js");
  flowWorker = new Worker(workerPath);
  flowWorker.on("error", (err) => {
    console.error("Flow worker error:", err);
  });
  flowWorker.on("exit", (code) => {
    if (code !== 0) {
      console.error(`Flow worker exited with code ${code}`);
    }
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
    console.error("Failed to send flow message:", err);
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

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.method === "GET" && req.path === "/") return res.redirect("/login");
  res.status(401).set("Content-Type", "text/html; charset=utf-8").send(renderLoginRequiredPage());
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.role === "admin") return next();
  res.status(403).set("Content-Type", "text/html; charset=utf-8").send(renderForbiddenPage());
}

function requireEditor(req, res, next) {
  const role = req.session && req.session.role;
  if (role === "admin" || role === "editor" || role === "user") return next();
  res.status(403).set("Content-Type", "text/html; charset=utf-8").send(renderForbiddenPage());
}

let db;

async function initCouch() {
  const client = nano(COUCHDB_URL);
  const dbName = COUCHDB_DB;
  try {
    await client.db.get(dbName);
  } catch (err) {
    if (err?.statusCode === 404) {
      await client.db.create(dbName);
    } else {
      throw err;
    }
  }
  db = client.db.use(dbName);

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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "elenko-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

app.get("/login", (req, res) => {
  if (req.session && req.session.user) return res.redirect("/");
  res.set("Content-Type", "text/html; charset=utf-8").send(renderLoginPage(null));
});

app.post("/login", async (req, res) => {
  const username = String((req.body && req.body.username) || "").trim();
  const password = (req.body && req.body.password) || "";
  if (!username) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderLoginPage("Invalid username or password."));
  }
  try {
    const result = await db.find({
      selector: { type: "elenko_user", username },
      limit: 1,
    });
    const user = result.docs && result.docs[0];
    if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
      return res.set("Content-Type", "text/html; charset=utf-8").send(renderLoginPage("Invalid username or password."));
    }
    req.session.user = user.username;
    req.session.role = (user.role === "user" ? "editor" : user.role) || "editor";
    sendFlowMessage("auth.login", { username: user.username, role: req.session.role });
    return res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderLoginPage("Invalid username or password."));
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {});
  res.redirect("/login");
});

app.use(requireAuth);
app.use(express.static("public"));

app.get("/", async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_profile" },
      fields: ["_id", "_rev", "name", "description", "createdAt"],
      sort: [{ name: "asc" }],
    });
    const profiles = result.docs || [];
    const role = (req.session && req.session.role) || "editor";
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderStartPage(profiles, role));
  } catch (err) {
    console.error("Error loading profiles:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/account/change-password", (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8").send(renderChangePasswordPage(null));
});

app.post("/account/change-password", async (req, res) => {
  const current = (req.body && req.body.currentPassword) || "";
  const newPass = (req.body && req.body.newPassword) || "";
  const confirm = (req.body && req.body.confirmPassword) || "";
  const username = req.session && req.session.user;
  if (!username) return res.redirect("/login");
  if (!newPass || newPass.length < 1) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderChangePasswordPage("New password is required."));
  }
  if (newPass !== confirm) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderChangePasswordPage("New password and confirmation do not match."));
  }
  try {
    const result = await db.find({ selector: { type: "elenko_user", username }, limit: 1 });
    const user = result.docs && result.docs[0];
    if (!user || !verifyPassword(current, user.passwordHash, user.salt)) {
      return res.set("Content-Type", "text/html; charset=utf-8").send(renderChangePasswordPage("Current password is incorrect."));
    }
    const { hash, salt } = hashPassword(newPass);
    user.passwordHash = hash;
    user.salt = salt;
    await db.insert(user);
    res.redirect("/?password=changed");
  } catch (err) {
    console.error("Change password error:", err);
    res.set("Content-Type", "text/html; charset=utf-8").send(renderChangePasswordPage("An error occurred. Please try again."));
  }
});

app.get("/account/users/create", requireAdmin, (req, res) => {
  const created = req.query.created === "1";
  res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage(null, created));
});

app.post("/account/users/create", requireAdmin, async (req, res) => {
  const username = String((req.body && req.body.username) || "").trim();
  const password = (req.body && req.body.password) || "";
  const roleRaw = (req.body && req.body.role) || "editor";
    const role = roleRaw === "admin" || roleRaw === "reader" ? roleRaw : "editor";
  if (!username) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("Username is required."));
  }
  if (password.length < 1) {
    return res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("Password is required."));
  }
  try {
    const existing = await db.find({ selector: { type: "elenko_user", username }, limit: 1 });
    if (existing.docs && existing.docs.length > 0) {
      return res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("Username already exists."));
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
    res.set("Content-Type", "text/html; charset=utf-8").send(renderCreateUserPage("An error occurred. Please try again."));
  }
});

app.get("/account/users", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_user" },
      fields: ["_id", "_rev", "username", "role"],
      sort: [{ username: "asc" }],
    });
    const users = result.docs || [];
    res.set("Content-Type", "text/html; charset=utf-8").send(renderManageUsersPage(users, req.session && req.session.user));
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
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderAllDocumentsPage(docs));
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
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEntryFormsListPage(forms));
  } catch (err) {
    console.error("Error loading entry forms:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.get("/entry-forms/create", requireAdmin, (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderCreateEntryFormPage(null));
});

app.get("/entry-forms/css-help", requireAdmin, (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderEntryFormCssHelpPage());
});

app.post("/api/entry-forms", requireAdmin, async (req, res) => {
  try {
    const normalized = normalizeEntryFormDoc(req.body || {});
    if (!normalized.name) {
      return res.status(400).json({ error: "Name is required." });
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
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditEntryFormPage(doc));
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
    const result = await db.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry form not found" });
    console.error("Error updating entry form:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/profile/create", requireAdmin, (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(renderCreateProfilePage());
});

app.post("/api/profiles", requireAdmin, async (req, res) => {
  try {
    const { name, description, fieldNames, customCss } = req.body || {};
    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Name is required" });
    }
    const fields = Array.isArray(fieldNames)
      ? fieldNames.filter((f) => typeof f === "string" && f.trim()).map((f) => f.trim())
      : [];
    const doc = {
      type: "elenko_profile",
      name: name.trim(),
      description: description != null ? String(description).trim() : "",
      customCss: customCss != null ? String(customCss) : "",
      fieldNames: fields,
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
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditProfilePage(doc, forms));
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).send(renderErrorPage("Profile not found"));
    console.error("Error loading profile:", err);
    res.status(500).send(renderErrorPage(err.message));
  }
});

app.put("/api/profiles/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { _rev, name, description, fieldNames, customCss, entryFormId, theme } = req.body || {};
    if (!_rev || !name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Name and _rev are required" });
    }
    const fields = Array.isArray(fieldNames)
      ? fieldNames.filter((f) => typeof f === "string" && f.trim()).map((f) => f.trim())
      : [];
    const doc = await db.get(id);
    if (doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    doc.name = name.trim();
    doc.description = description != null ? String(description).trim() : "";
    doc.customCss = customCss != null ? String(customCss) : "";
    doc.fieldNames = fields;
    doc.entryFormId = entryFormId != null && typeof entryFormId === "string" ? entryFormId.trim() : "";
    doc.theme = normalizeProfileTheme(theme);
    const result = await db.insert(doc);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict; refresh and try again" });
    if (err?.statusCode === 404) return res.status(404).json({ error: "Profile not found" });
    console.error("Error updating profile:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/profile/:id/entry/new", requireEditor, async (req, res) => {
  try {
    const doc = await db.get(req.params.id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).send(renderErrorPage("Profile not found"));
    }
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderCreateEntryPage(doc));
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
    const result = await db.insert(record);
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
    if (doc.entryFormId && typeof doc.entryFormId === "string" && doc.entryFormId.trim()) {
      try {
        const loaded = await db.get(doc.entryFormId.trim());
        if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
      } catch (e) {
        // form missing
      }
    }
    const target = formDoc && formDoc.flowTarget === "log" ? "log" : "log";
    const flowButtonParam = formDoc && typeof formDoc.flowButtonParam === "string" ? formDoc.flowButtonParam : "";
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
    if (doc.entryFormId && typeof doc.entryFormId === "string" && doc.entryFormId.trim()) {
      try {
        const loaded = await db.get(doc.entryFormId.trim());
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
    let formDoc = null;
    if (doc.entryFormId) {
      try {
        const loaded = await db.get(doc.entryFormId);
        if (loaded && loaded.type === "elenko_entry_form") formDoc = loaded;
      } catch (_) {}
    }
    const returnQuery = { q: req.query.q, page: req.query.page };
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderEditEntryPage(doc, record, formDoc, returnQuery));
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
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    for (const fn of fieldNames) {
      record[fn] = values[fn] != null ? String(values[fn]).trim() : "";
    }
    const result = await db.insert(record);
    res.json({ ok: true, id: result.id, rev: result.rev });
  } catch (err) {
    if (err?.statusCode === 404) return res.status(404).json({ error: "Entry not found" });
    if (err?.statusCode === 409) return res.status(409).json({ error: "Conflict; refresh and try again" });
    console.error("Error updating entry:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/deletions", requireAdmin, async (req, res) => {
  try {
    const result = await db.find({
      selector: { type: "elenko_pending_deletions" },
    });
    const batches = result.docs || [];
    res.set("Content-Type", "text/html; charset=utf-8");
    res.send(renderDeletionsPage(batches));
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
    const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const searchQuery = (req.query.q || "").trim();
    const skip = (page - 1) * ENTRIES_PAGE_SIZE;

    const selector = { type: "elenko_record", profileId };
    if (searchQuery && fieldNames.length > 0) {
      const pattern = ".*" + escapeRegex(searchQuery) + ".*";
      selector.$or = fieldNames.map((fn) => ({ [fn]: { $regex: pattern } }));
    }

    let totalPages = null;
    if (!searchQuery) {
      try {
        const countResult = await db.view("records", "countByProfile", { key: profileId });
        const totalEntries = countResult.rows && countResult.rows[0] ? countResult.rows[0].value : 0;
        totalPages = Math.max(1, Math.ceil(totalEntries / ENTRIES_PAGE_SIZE));
      } catch (e) {
        totalPages = 1;
      }
    }

    const recordsResult = await db.find({
      selector,
      fields: fieldNames.length ? ["_id", "_rev", ...fieldNames] : ["_id", "_rev"],
      sort: [{ _id: "asc" }],
      limit: ENTRIES_PAGE_SIZE + 1,
      skip,
    });
    const allDocs = recordsResult.docs || [];
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

function renderCreateEntryPage(doc) {
  const title = escapeHtml(doc.name || "Elenko database");
  const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const profileId = doc._id;
  const backUrl = "/profile/" + encodeURIComponent(profileId);
  const customCss = doc.customCss || "";

  const rows =
    fieldNames.length > 0
      ? fieldNames
          .map(
            (fn) => `
        <tr>
          <td class="label">${escapeHtml(fn)}</td>
          <td><input type="text" class="entry-field" name="${escapeHtml(fn)}" placeholder="${escapeHtml(fn)}"></td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="2" class="empty">No fields defined. Edit the profile to add field names.</td></tr>`;

  const fieldNamesJson = JSON.stringify(fieldNames);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
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
        setTimeout(() => { window.location.href = ${JSON.stringify(backUrl)}; }, 800);
      } catch (err) {
        msgEl.textContent = err.message || 'Request failed';
        msgEl.className = 'msg err';
      }
    };
  </script>
</body>
</html>`;
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
    if (item && item.fieldName && set.has(item.fieldName)) byFieldName[item.fieldName] = item;
  }
  const seenFields = new Set();
  const seenLabels = new Set();
  const ordered = [];
  const sorted = formDoc.fieldLayout
    .filter((item) => item && (item.fieldName || item.labelId))
    .sort((a, b) => (a.order != null ? Number(a.order) : 0) - (b.order != null ? Number(b.order) : 0));

  for (const item of sorted) {
    if (item.fieldName && set.has(item.fieldName) && !seenFields.has(item.fieldName)) {
      seenFields.add(item.fieldName);
      ordered.push({
        type: "field",
        fieldName: item.fieldName,
        width: item.width || "100%",
        x: item.x,
        y: item.y,
        height: item.height,
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
  for (const fn of names) {
    if (!seenFields.has(fn)) {
      const item = byFieldName[fn];
      ordered.push({
        type: "field",
        fieldName: fn,
        width: item ? (item.width || "100%") : "100%",
        x: item && item.x,
        y: item && item.y,
        height: item && item.height,
      });
    }
  }
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
  const showFlowButton = !!(formDoc && formDoc.flowButtonEnabled);
  const flowButtonLabel = formDoc && typeof formDoc.flowButtonLabel === "string" && formDoc.flowButtonLabel.trim() ? formDoc.flowButtonLabel.trim() : "Send to Flow";

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
  function itemValue(o) {
    if (o.type === "label") return "";
    const val = record[o.fieldName];
    return val != null ? String(val) : "";
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
          return `
        <div class="entry-field-block"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="value">${escapeHtml(value)}</div>
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
          return `
        <div class="entry-grid-cell"${styleAttr}>
          <span class="${lc}">${escapeHtml(itemLabel(o))}</span>
          <div class="value">${escapeHtml(value)}</div>
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
          return `
        <tr>
          <td class="${lc}">${escapeHtml(itemLabel(o))}</td>
          <td class="value">${escapeHtml(value)}</td>
        </tr>`;
        })
        .join("");
    contentHtml = `<table><tbody>${rows}</tbody></table>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
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
    .entry-view-stack .entry-field-block { margin-bottom: 1rem; }
    .entry-view-stack .label { display: block; margin-bottom: 0.25rem; }
    .entry-view-stack .value { background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 6px; padding: 0.75rem 1rem; }
    .entry-view-stack .entry-label-only .label { white-space: nowrap; }
    .entry-view-grid { display: grid; gap: 1rem; }
    .entry-grid-cell .label { display: block; margin-bottom: 0.25rem; color: var(--entry-label, #8b949e); }
    .entry-grid-cell .value { background: var(--entry-field-bg, #161b22); border: 1px solid var(--entry-field-border, #21262d); border-radius: 6px; padding: 0.75rem 1rem; }
    .entry-grid-cell.entry-label-only .label { white-space: nowrap; }
    .entry-label-row .label { white-space: nowrap; }
  </style>
  ${formCustomCss ? `<style>${formCustomCss}</style>` : ""}
</head>
<body>
  <div class="actions"><a href="${escapeHtml(backUrl)}">← Back to database</a>${canEdit ? ` <a href="${editUrl}">Edit</a>` : ""}</div>
  ${showFlowButton ? `<div class="actions" style="margin-top:0.5rem;"><button type="button" id="send-to-flow-btn" class="btn-flow" data-profile-id="${escapeHtml(profileId)}" data-entry-id="${escapeHtml(entryId)}">${escapeHtml(flowButtonLabel)}</button></div><div id="flow-msg" class="flow-msg"></div>` : ""}
  <h1>${title}</h1>
  ${contentHtml}
  ${showFlowButton ? `
  <style>.btn-flow { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; background: #238636; color: #fff; }.btn-flow:hover { background: #2ea043; }.btn-flow:disabled { opacity: 0.6; cursor: not-allowed; }.flow-msg { margin-top: 0.5rem; font-size: 0.875rem; }.flow-msg.ok { color: #3fb950; }.flow-msg.err { color: #f85149; }</style>
  <script>
    (function() {
      var btn = document.getElementById('send-to-flow-btn');
      var msgEl = document.getElementById('flow-msg');
      if (!btn || !msgEl) return;
      btn.onclick = function() {
        var pid = btn.getAttribute('data-profile-id');
        var eid = btn.getAttribute('data-entry-id');
        if (!pid || !eid) return;
        btn.disabled = true;
        msgEl.textContent = '';
        msgEl.className = 'flow-msg';
        var url = '/api/profile/' + encodeURIComponent(pid) + '/entry/' + encodeURIComponent(eid) + '/send-to-flow';
        fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
          .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
          .then(function(o) {
            if (o.ok) { msgEl.textContent = 'Sent to Flow.'; msgEl.className = 'flow-msg ok'; }
            else { msgEl.textContent = o.data.error || 'Failed'; msgEl.className = 'flow-msg err'; }
            btn.disabled = false;
          })
          .catch(function(e) { msgEl.textContent = e.message || 'Request failed'; msgEl.className = 'flow-msg err'; btn.disabled = false; });
      };
    })();
  </script>` : ""}
</body>
</html>`;
}

function renderEditEntryPage(doc, record, formDoc, returnQuery) {
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
          <div class="value"><input type="text" class="entry-field" name="${escapeHtml(o.fieldName)}" placeholder="${escapeHtml(o.fieldName)}" value="${escapeHtml(value)}"></div>
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
          <div class="value"><input type="text" class="entry-field" name="${escapeHtml(o.fieldName)}" placeholder="${escapeHtml(o.fieldName)}" value="${escapeHtml(value)}"></div>
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
          <td class="value"${valueCellWidth}><input type="text" class="entry-field" name="${escapeHtml(o.fieldName)}" placeholder="${escapeHtml(o.fieldName)}" value="${escapeHtml(value)}"></td>
        </tr>`;
      })
      .join("");
    contentHtml = `<table><tbody>${rows}</tbody></table>`;
  }

  const orderedFieldNamesJson = JSON.stringify(orderedFieldNames);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
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
    .entry-view-stack .entry-field-block { margin-bottom: 1rem; min-width: 0; max-width: 100%; }
    .entry-view-stack .entry-field-block .value { min-width: 0; overflow: hidden; background: var(--entry-field-bg-edit, #161b22); border-radius: 6px; padding: 0.75rem 1rem; }
    .entry-view-stack .label { display: block; margin-bottom: 0.25rem; }
    .entry-view-stack .entry-label-only .label { white-space: nowrap; }
    .entry-view-grid { display: grid; gap: 1rem; }
    .entry-grid-cell { min-width: 0; }
    .entry-grid-cell .label { display: block; margin-bottom: 0.25rem; color: var(--entry-label, #8b949e); }
    .entry-grid-cell .value { min-width: 0; overflow: hidden; background: var(--entry-field-bg-edit, #161b22); border-radius: 6px; padding: 0.75rem 1rem; }
    .entry-grid-cell.entry-label-only .label { white-space: nowrap; }
    .entry-label-row .label { white-space: nowrap; }
    td.value { min-width: 0; overflow: hidden; }
    input.entry-field { width: 100%; min-width: 0; max-width: 100%; padding: 0.5rem; background: var(--entry-field-bg-edit, #161b22); color: var(--entry-text-edit, #e6edf3); border: 1px solid transparent; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
    input.entry-field:focus { outline: none; border-color: var(--entry-link, #58a6ff); }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; margin-top: 1rem; }
    .btn:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; text-decoration: none; }
    .btn-secondary:hover { background: #30363d; }
    .empty { color: var(--entry-label, #8b949e); font-style: italic; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
  ${formCustomCss ? `<style>${formCustomCss}</style>` : ""}
</head>
<body>
  <div class="actions"><a href="${escapeHtml(backUrl)}">← Back to database</a></div>
  <h1>${title}</h1>
  <p class="sub">Edit entry:</p>
  <form id="entry-form">
    <input type="hidden" id="rev" value="${rev}">
    ${contentHtml}
    <div>
      <button type="submit" class="btn">Save</button>
      <a href="${escapeHtml(backUrl)}" class="btn btn-secondary" style="margin-left: 0.5rem;">Cancel</a>
    </div>
  </form>
  <div id="msg"></div>
  <script>
    const profileId = ${JSON.stringify(profileId)};
    const entryId = ${JSON.stringify(entryId)};
    const orderedFieldNames = ${orderedFieldNamesJson};
    const form = document.getElementById('entry-form');
    const msgEl = document.getElementById('msg');

    form.onsubmit = async (e) => {
      e.preventDefault();
      msgEl.textContent = '';
      msgEl.className = 'msg';
      const inputs = form.querySelectorAll('.entry-field');
      const data = { _rev: document.getElementById('rev').value };
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

  const colCount = fieldNames.length > 0 ? fieldNames.length : 1;
  const colWidthPct = 100 / colCount;
  const colgroup =
    colCount === 1
      ? "<colgroup><col style=\"width:100%\"></colgroup>"
      : "<colgroup>" + fieldNames.map(() => `<col style="width:${colWidthPct}%">`).join("") + "</colgroup>";

  const headerRow =
    fieldNames.length > 0
      ? `<tr>${fieldNames.map((f) => `<th>${escapeHtml(f)}</th>`).join("")}</tr>`
      : "<tr><th>—</th></tr>";

  const returnQuery = [];
    if (page > 1) returnQuery.push("page=" + encodeURIComponent(String(page)));
    if (searchQuery) returnQuery.push("q=" + encodeURIComponent(searchQuery));
    const returnQueryStr = returnQuery.length > 0 ? "?" + returnQuery.join("&") : "";

  const dataRows =
    fieldNames.length > 0
      ? records.map((rec) => {
          const cells = fieldNames.map((fn, i) => {
            const val = rec[fn];
            const text = val != null ? String(val) : "";
            const escaped = escapeHtml(text);
            if (i === 0) {
              const entryUrl = "/profile/" + encodeURIComponent(doc._id) + "/entry/" + encodeURIComponent(rec._id) + returnQueryStr;
              return `<td class="entry-link-cell"><a href="${entryUrl}">${escaped}</a></td>`;
            }
            return `<td>${escaped}</td>`;
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
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    table { width: 100%; table-layout: fixed; border-collapse: collapse; background: var(--profile-table-bg, #161b22); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--profile-table-border, #21262d); }
    th { background: var(--profile-table-header-bg, #21262d); color: var(--profile-table-header-text, #8b949e); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .entry-link-cell a { color: var(--profile-link, #58a6ff); text-decoration: none; }
    .entry-link-cell a:hover { text-decoration: underline; }
    .empty { color: var(--profile-label, #8b949e); font-style: italic; }
    .search-bar { margin-bottom: 1rem; display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .search-bar input[type="search"] { padding: 0.5rem 0.75rem; background: var(--profile-table-bg, #161b22); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; color: var(--profile-text, #e6edf3); font-size: 1rem; min-width: 12rem; }
    .search-bar input[type="search"]:focus { outline: none; border-color: var(--profile-link, #58a6ff); }
    .search-bar .btn-search { padding: 0.5rem 0.75rem; background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); border: 1px solid var(--profile-table-border, #21262d); border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
    .search-bar .btn-search:hover { background: #30363d; }
    .pagination { margin-bottom: 1rem; display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
    .pagination .btn-pag { display: inline-block; padding: 0.5rem 0.75rem; border-radius: 6px; text-decoration: none; font-size: 0.875rem; }
    .pagination .btn-pag-prev, .pagination .btn-pag-next { background: var(--profile-table-header-bg, #21262d); color: var(--profile-link, #58a6ff); }
    .pagination .btn-pag-prev:hover, .pagination .btn-pag-next:hover { background: #30363d; }
    .pagination .btn-pag.disabled { color: #484f58; pointer-events: none; }
    .pagination .page-num { color: var(--profile-label, #8b949e); font-size: 0.875rem; }
  </style>
  ${customCss ? `<style>${customCss}</style>` : ""}
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a>${canEdit ? (isAdmin ? `<a href="/profile/${encodeURIComponent(doc._id)}/edit">Edit profile</a>` : "") + `<a href="/profile/${encodeURIComponent(doc._id)}/entry/new" class="btn">Create entry</a>` : ""}</div>
  <h1>${title}</h1>
  ${description ? `<p class="sub">${description}</p>` : ""}
  <form method="get" action="${profileBase}" class="search-bar">
    <input type="search" name="q" value="${escapeHtml(searchQuery)}" placeholder="Search entries…" aria-label="Search entries">
    <input type="hidden" name="page" value="1">
    <button type="submit" class="btn-search">Search</button>
  </form>
  <div class="pagination">
    ${hasPrev ? `<a href="${prevUrl}" class="btn-pag btn-pag-prev">← Previous</a>` : `<span class="btn-pag btn-pag-prev disabled">← Previous</span>`}
    <span class="page-num">Page ${escapeHtml(String(page))}${escapeHtml(pageOfTotal)}</span>
    ${hasNext ? `<a href="${nextUrl}" class="btn-pag btn-pag-next">Next →</a>` : `<span class="btn-pag btn-pag-next disabled">Next →</span>`}
  </div>
  <table>
    ${colgroup}
    <thead>${headerRow}</thead>
    <tbody>${dataRows.join("")}${emptyRow}
    </tbody>
  </table>
</body>
</html>`;
}

function renderDeletionsPage(batches) {
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Marked for deletion</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    .batch { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
    .batch-title { margin: 0 0 0.5rem 0; }
    .batch-ids { font-size: 0.875rem; color: #8b949e; word-break: break-all; margin: 0 0 0.75rem 0; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-danger { background: #da3633; color: #fff; }
    .btn-danger:hover { background: #f85149; }
    .btn-danger:disabled { opacity: 0.6; cursor: not-allowed; }
    .empty { color: #8b949e; font-style: italic; }
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

function renderEntryFormsListPage(forms) {
  const rows =
    forms.length > 0
      ? forms
          .map(
            (f) => `
        <tr>
          <td>${escapeHtml(f.name || f._id)}</td>
          <td><a href="/entry-forms/${encodeURIComponent(f._id)}/edit" class="edit-link">Edit</a></td>
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Entry forms</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 42rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; margin-right: 1rem; }
    .actions a:hover { text-decoration: underline; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #21262d; }
    th { background: #21262d; color: #8b949e; font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .edit-link { color: #58a6ff; }
    .empty { color: #8b949e; font-style: italic; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a><a href="/entry-forms/create" class="btn">Create entry form</a></div>
  <h1>Entry forms</h1>
  <p class="sub">Configure how a single database entry is displayed (colours and field layout). Assign a form to a profile on the profile edit page.</p>
  <table>
    <thead><tr><th>Name</th><th>Actions</th></tr></thead>
    <tbody>${rows}
    </tbody>
  </table>
</body>
</html>`;
}

function renderCreateEntryFormPage(err) {
  return renderEntryFormPage(null, null, err);
}

function renderEditEntryFormPage(doc, err) {
  return renderEntryFormPage(doc, doc._rev, err);
}

function renderEntryFormCssHelpPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Entry form CSS reference</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 48rem; line-height: 1.5; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    h2 { font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; font-size: 1.1rem; }
    p { margin: 0.5rem 0 1rem 0; color: #8b949e; }
    code { background: #21262d; padding: 0.15em 0.4em; border-radius: 4px; font-size: 0.9em; }
    pre { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.875rem; }
    table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1rem 0; }
    th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }
    th { color: #8b949e; font-weight: 600; }
    .back { margin-bottom: 1rem; }
    .back a { color: #58a6ff; text-decoration: none; }
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

function renderEntryFormPage(doc, rev, err) {
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
  const flowButtonChecked = doc && doc.flowButtonEnabled ? " checked" : "";
  const flowTargetValue = doc && doc.flowTarget === "log" ? "log" : "log";
  const flowButtonLabelValue = doc && typeof doc.flowButtonLabel === "string" ? escapeHtml(doc.flowButtonLabel) : "Send to Flow";
  const flowButtonParamValue = doc && typeof doc.flowButtonParam === "string" ? escapeHtml(doc.flowButtonParam) : "";
  const labelsArr = (doc && Array.isArray(doc.labels) ? doc.labels : []);
  const fieldLayout = (doc && Array.isArray(doc.fieldLayout) ? doc.fieldLayout : []);
  const revInput = rev ? `<input type="hidden" id="rev" value="${escapeHtml(rev)}">` : "";
  const errHtml = err ? `<p class="msg err">${escapeHtml(err)}</p>` : "";
  const title = isEdit ? "Edit entry form" : "Create entry form";
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
            return `
        <tr class="field-layout-row">
          <td><input type="text" class="fl-field" placeholder="Field name or label id" value="${escapeHtml(fieldOrLabel)}"></td>
          <td><input type="number" class="fl-order" min="0" value="${item.order != null ? Number(item.order) : idx}"></td>
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – ${title}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 48rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="text"], input[type="number"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input:focus { outline: none; border-color: #58a6ff; }
    select { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    textarea { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; text-decoration: none; }
    .btn-secondary:hover { background: #30363d; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .btn-remove:hover { color: #ff7b72; }
    .msg.err { background: #3d1f1f; color: #f85149; padding: 0.5rem; border-radius: 6px; margin: 1rem 0; }
    .field-layout-table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
    .field-layout-table td { padding: 0.25rem; }
    .field-layout-table input { width: 100%; }
    .theme-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
    .theme-row label { margin: 0; flex: 0 0 10rem; }
    .theme-row input[type="color"] { width: 2.5rem; height: 2rem; padding: 2px; cursor: pointer; border: 1px solid #30363d; border-radius: 4px; background: #161b22; }
    .theme-row input[type="text"] { flex: 1; min-width: 8.5rem; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="actions"><a href="/entry-forms" class="btn-secondary" style="display:inline-block;padding:0.5rem 1rem;">← Entry forms</a></div>
  <h1>${title}</h1>
  <p class="sub">Used to style the single-entry (read-only) view: colours and field positions/sizes.</p>
  ${errHtml}
  <form id="entry-form-form">
    ${revInput}
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="e.g. Compact dark" value="${name}">
    <label>Theme (colours)</label>
    <p class="sub" style="margin-top:0.25rem;">Click the swatch to open the colour picker.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem 1rem;margin-top:0.5rem;">
      <div class="theme-row"><label for="theme-background" style="margin-top:0;">Background</label><input type="color" id="theme-background-color" value="${background}" aria-label="Background"><input type="text" id="theme-background" placeholder="#0f1419" value="${background}"></div>
      <div class="theme-row"><label for="theme-text" style="margin-top:0;">Text</label><input type="color" id="theme-text-color" value="${text}" aria-label="Text"><input type="text" id="theme-text" placeholder="#e6edf3" value="${text}"></div>
      <div class="theme-row"><label for="theme-label" style="margin-top:0;">Label</label><input type="color" id="theme-label-color" value="${label}" aria-label="Label"><input type="text" id="theme-label" placeholder="#8b949e" value="${label}"></div>
      <div class="theme-row"><label for="theme-link" style="margin-top:0;">Link</label><input type="color" id="theme-link-color" value="${link}" aria-label="Link"><input type="text" id="theme-link" placeholder="#58a6ff" value="${link}"></div>
      <div class="theme-row"><label for="theme-fieldBorder" style="margin-top:0;">Field border</label><input type="color" id="theme-fieldBorder-color" value="${fieldBorder}" aria-label="Field border"><input type="text" id="theme-fieldBorder" placeholder="#21262d" value="${fieldBorder}"></div>
      <div class="theme-row"><label for="theme-fieldBackground" style="margin-top:0;">Field background</label><input type="color" id="theme-fieldBackground-color" value="${fieldBackground}" aria-label="Field background"><input type="text" id="theme-fieldBackground" placeholder="#161b22" value="${fieldBackground}"></div>
      <div class="theme-row"><label for="theme-fieldBackgroundEdit" style="margin-top:0;">Field background (edit)</label><input type="color" id="theme-fieldBackgroundEdit-color" value="${fieldBackgroundEdit}" aria-label="Field background edit"><input type="text" id="theme-fieldBackgroundEdit" placeholder="#161b22" value="${fieldBackgroundEdit}"></div>
      <div class="theme-row"><label for="theme-textEdit" style="margin-top:0;">Text (edit)</label><input type="color" id="theme-textEdit-color" value="${textEdit}" aria-label="Text edit"><input type="text" id="theme-textEdit" placeholder="#e6edf3" value="${textEdit}"></div>
    </div>
    <label for="layout">Layout</label>
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
    <label class="field-list-label" style="margin-top:1.5rem;">Field layout (optional: field name or label id, order, width, position)</label>
    <p class="sub" style="margin-top:0;">Use a profile field name or a label id from above. Leave empty to use profile field order. Width: e.g. 50%, 1fr, or 40ch. Only Stack supports X (ch), Y (em), and Height (em) for positioning; Grid uses width as column size only.</p>
    <table class="field-layout-table">
      <thead><tr><th>Field name or label id</th><th>Order</th><th>Width</th><th>X (ch)</th><th>Y (em)</th><th>Height (em)</th><th></th></tr></thead>
      <tbody id="field-layout-tbody">${fieldLayoutRows}
      </tbody>
    </table>
    <button type="button" class="btn btn-secondary" id="add-field-layout" style="margin-top:0.5rem;">+ Add row</button>
    <label style="margin-top:1.5rem;">Flow button (single-entry view)</label>
    <p class="sub" style="margin-top:0;">When enabled, a button appears on the single-entry view that sends the current entry dataset to the Flow facility.</p>
    <div style="margin-top:0.5rem;">
      <label style="display:inline-flex;align-items:center;gap:0.5rem;margin:0;cursor:pointer;">
        <input type="checkbox" id="flowButtonEnabled" name="flowButtonEnabled"${flowButtonChecked}>
        <span>Show &quot;Send to Flow&quot; button</span>
      </label>
    </div>
    <div style="margin-top:0.75rem;">
      <label for="flowTarget" style="margin-top:0;">Target</label>
      <select id="flowTarget" name="flowTarget">
        <option value="log"${flowTargetValue === "log" ? " selected" : ""}>Log file</option>
      </select>
    </div>
    <div style="margin-top:0.75rem;">
      <label for="flowButtonLabel">Button title</label>
      <input type="text" id="flowButtonLabel" name="flowButtonLabel" placeholder="Send to Flow" value="${flowButtonLabelValue}">
    </div>
    <div style="margin-top:0.75rem;">
      <label for="flowButtonParam">Additional parameter (for later use)</label>
      <input type="text" id="flowButtonParam" name="flowButtonParam" placeholder="Optional" value="${flowButtonParamValue}">
    </div>
    <label for="customCss">Custom CSS (entry view and edit)</label>
    <p class="sub" style="margin-top:0;">Optional CSS applied to single-entry view and edit entry page. <a href="/entry-forms/css-help" target="_blank" rel="noopener noreferrer">CSS parameters reference</a></p>
    <textarea id="customCss" name="customCss" placeholder="Optional CSS">${customCss}</textarea>
    <div>
      <button type="submit" class="btn btn-primary">${submitLabel}</button>
      <a href="/entry-forms" class="btn btn-secondary" style="margin-left:0.5rem;">Cancel</a>
    </div>
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

    function addLabelRow(id, text) {
      const tr = document.createElement('tr');
      tr.className = 'labels-row';
      tr.innerHTML = '<td><input type="text" class="label-id" placeholder="e.g. sectionTitle" value="' + (id || '').replace(/"/g, '&quot;') + '"></td><td><input type="text" class="label-text" placeholder="Fixed text shown on entry view" value="' + (text || '').replace(/"/g, '&quot;') + '"></td><td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      tr.querySelector('.btn-remove').onclick = () => tr.remove();
      labelsTbody.appendChild(tr);
    }
    addLabelBtn.onclick = () => addLabelRow('', '');

    function addRow(fieldName, order, width, x, y, height) {
      const tr = document.createElement('tr');
      tr.className = 'field-layout-row';
      const n = tbody.querySelectorAll('.field-layout-row').length;
      const xv = (x != null && x !== '') ? String(x) : '';
      const yv = (y != null && y !== '') ? String(y) : '';
      const hv = (height != null && height !== '') ? String(height) : '';
      tr.innerHTML = '<td><input type="text" class="fl-field" placeholder="Field name or label id" value="' + (fieldName || '').replace(/"/g, '&quot;') + '"></td><td><input type="number" class="fl-order" min="0" value="' + (order != null ? order : n) + '"></td><td><input type="text" class="fl-width" placeholder="50%, 1fr, or 40ch" value="' + (width || '100%').replace(/"/g, '&quot;') + '"></td><td><input type="number" class="fl-x" step="any" placeholder="—"></td><td><input type="number" class="fl-y" step="any" placeholder="—"></td><td><input type="number" class="fl-height" step="any" placeholder="—" min="0"></td><td><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button></td>';
      tr.querySelector('.fl-x').value = xv;
      tr.querySelector('.fl-y').value = yv;
      tr.querySelector('.fl-height').value = hv;
      tr.querySelector('.btn-remove').onclick = () => tr.remove();
      tbody.appendChild(tr);
    }
    addBtn.onclick = () => addRow('', tbody.querySelectorAll('.field-layout-row').length, '100%');

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
        if (labelIds.has(firstCol)) item.labelId = firstCol; else item.fieldName = firstCol;
        return item;
      }).filter(Boolean);
      const flowButtonEnabled = document.getElementById('flowButtonEnabled').checked;
      const flowTarget = document.getElementById('flowTarget').value || 'log';
      const flowButtonLabel = (document.getElementById('flowButtonLabel') && document.getElementById('flowButtonLabel').value.trim()) || 'Send to Flow';
      const flowButtonParam = (document.getElementById('flowButtonParam') && document.getElementById('flowButtonParam').value.trim()) || '';
      const url = formId ? '/api/entry-forms/' + encodeURIComponent(formId) : '/api/entry-forms';
      const method = formId ? 'PUT' : 'POST';
      const body = { name, labels, theme, layout, fieldLayout, customCss, flowButtonEnabled, flowTarget, flowButtonLabel, flowButtonParam };
      if (formId) body._rev = document.getElementById('rev').value;
      try {
        const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await r.json();
        if (!r.ok) { msgEl.textContent = data.error || 'Failed'; msgEl.className = 'msg err'; return; }
        msgEl.textContent = formId ? 'Saved.' : 'Created.';
        msgEl.className = 'msg ok';
        if (!formId) setTimeout(() => { window.location.href = '/entry-forms'; }, 800);
        else { document.getElementById('rev').value = data.rev; }
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

function renderAllDocumentsPage(docs) {
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
              summary = escapeHtml(profileName);
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – All documents</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    .actions { margin-bottom: 1.5rem; }
    .actions a { color: #58a6ff; text-decoration: none; }
    .actions a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #21262d; }
    th { background: #21262d; color: #8b949e; font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .empty { color: #8b949e; font-style: italic; }
    code { font-size: 0.9em; background: #21262d; padding: 0.2em 0.4em; border-radius: 4px; word-break: break-all; }
    .btn { display: inline-block; background: #da3633; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; margin-bottom: 1rem; }
    .btn:hover { background: #f85149; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
</head>
<body>
  <div class="actions"><a href="/">← Profiles</a></div>
  <h1>All documents</h1>
  <p class="sub">CouchDB documents created by the application (profiles, entries, pending-deletion batches).</p>
  <p><label for="doc-summary-search" style="margin-right:0.5rem;">Search Summary:</label><input type="search" id="doc-summary-search" placeholder="Filter by summary…" style="padding:0.5rem 0.75rem;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:1rem;min-width:16rem;"></p>
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

function renderStartPage(profiles, role) {
  const isAdmin = role === "admin";
  const rows = profiles.length
    ? profiles
        .map((p) => {
          if (isAdmin) {
            return `
        <tr>
          <td><a href="/profile/${encodeURIComponent(p._id)}">${escapeHtml(p.name || p._id)}</a></td>
          <td>${escapeHtml(p.description || "—")}</td>
          <td><code>${escapeHtml(p._id)}</code></td>
          <td><a href="/profile/${encodeURIComponent(p._id)}/edit" class="edit-link">Edit</a> <a href="/profile/${encodeURIComponent(p._id)}/delete" class="delete-link">Delete</a></td>
        </tr>`;
          }
          return `
        <tr>
          <td><a href="/profile/${encodeURIComponent(p._id)}">${escapeHtml(p.name || p._id)}</a></td>
          <td>${escapeHtml(p.description || "—")}</td>
        </tr>`;
        })
        .join("")
    : `
        <tr>
          <td colspan="${isAdmin ? 4 : 2}" class="empty">No Elenko database profiles yet.${isAdmin ? ' Add documents with <code>type: "elenko_profile"</code> in CouchDB.' : ""}</td>
        </tr>`;

  const actionsAdmin = '<a href="/profile/create" class="btn">Create Elenko profile</a> <a href="/deletions" class="link-secondary">Marked for deletion</a> <a href="/entry-forms" class="link-secondary">Entry forms</a> <a href="/documents" class="link-secondary">All documents</a> ';
  const actionsUser = "";
  const actionsCommon = '<a href="/account/change-password" class="link-secondary">Change password</a> ' + (isAdmin ? '<a href="/account/users" class="link-secondary">Manage users</a> <a href="/account/users/create" class="link-secondary">Create user</a> ' : '') + '<a href="/logout" class="link-secondary">Log out</a>';
  const theadAdmin = "<tr><th>Name</th><th>Description</th><th>Document ID</th><th>Actions</th></tr>";
  const theadUser = "<tr><th>Name</th><th>Description</th></tr>";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Database profiles</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #21262d; }
    th { background: #21262d; color: #8b949e; font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    code { font-size: 0.9em; background: #21262d; padding: 0.2em 0.4em; border-radius: 4px; }
    .empty { color: #8b949e; font-style: italic; }
    .btn { display: inline-block; background: #238636; color: #fff; padding: 0.5rem 1rem; border-radius: 6px; margin-bottom: 1rem; }
    .btn:hover { background: #2ea043; text-decoration: none; }
    .link-secondary { color: #8b949e; margin-left: 1rem; }
    .link-secondary:hover { color: #e6edf3; }
    .edit-link { color: #58a6ff; }
    .delete-link { color: #f85149; margin-left: 0.5rem; }
    .delete-link:hover { color: #ff7b72; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="sub">Profiles for Elenko databases (CouchDB documents)</p>
  <p>${isAdmin ? actionsAdmin : actionsUser}${actionsCommon}</p>
  <table>
    <thead>${isAdmin ? theadAdmin : theadUser}</thead>
    <tbody>${rows}
    </tbody>
  </table>
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

function renderEditProfilePage(doc, forms = []) {
  const name = escapeHtml(doc.name || "");
  const description = escapeHtml(doc.description || "");
  const fieldNames = Array.isArray(doc.fieldNames) ? doc.fieldNames : [];
  const rev = escapeHtml(doc._rev || "");
  const customCss = doc.customCss || "";
  const entryFormId = doc.entryFormId || "";
  const theme = normalizeProfileTheme(doc.theme);
  const themeBg = toHex6(theme.background);
  const themeText = toHex6(theme.text);
  const themeLabel = toHex6(theme.label);
  const themeLink = toHex6(theme.link);
  const themeTableBg = toHex6(theme.tableBg);
  const themeTableHeaderBg = toHex6(theme.tableHeaderBg);
  const themeTableHeaderText = toHex6(theme.tableHeaderText);
  const themeTableBorder = toHex6(theme.tableBorder);
  const entryFormOptions = (forms || [])
    .map((f) => `<option value="${escapeHtml(f._id)}" ${entryFormId === f._id ? "selected" : ""}>${escapeHtml(f.name || f._id)}</option>`)
    .join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Edit profile</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 48rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="text"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input[type="text"]:focus { outline: none; border-color: #58a6ff; }
    textarea { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    textarea:focus { outline: none; border-color: #58a6ff; }
    select { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    select:focus { outline: none; border-color: #58a6ff; }
    .field-row { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center; }
    .field-row input { flex: 1; }
    .field-list { margin: 1rem 0; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; }
    .btn-secondary:hover { background: #30363d; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .btn-remove:hover { color: #ff7b72; }
    .theme-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
    .theme-row label { margin: 0; flex: 0 0 8rem; }
    .theme-row input[type="color"] { width: 2.5rem; height: 2rem; padding: 2px; cursor: pointer; border: 1px solid #30363d; border-radius: 4px; background: #161b22; }
    .theme-row input[type="text"] { flex: 1; min-width: 8.5rem; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 0.875rem; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="sub">Edit profile</p>
  <form id="edit-form">
    <input type="hidden" id="rev" name="_rev" value="${rev}">
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required placeholder="Profile name" value="${name}">
    <label for="description">Description</label>
    <textarea id="description" name="description" placeholder="Optional description">${description}</textarea>
    <label>Theme (colours)</label>
    <p class="sub" style="margin-top:0.25rem;">Colours for the full database (list) view: background, table, links, etc. Click the swatch to open the colour picker.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem 1rem;margin-top:0.5rem;">
      <div class="theme-row"><label for="theme-background" style="margin-top:0;">Background</label><input type="color" id="theme-background" value="${escapeHtml(themeBg)}" aria-label="Background colour"><input type="text" id="theme-background-hex" value="${escapeHtml(themeBg)}" placeholder="#0f1419"></div>
      <div class="theme-row"><label for="theme-text" style="margin-top:0;">Text</label><input type="color" id="theme-text" value="${escapeHtml(themeText)}" aria-label="Text colour"><input type="text" id="theme-text-hex" value="${escapeHtml(themeText)}" placeholder="#e6edf3"></div>
      <div class="theme-row"><label for="theme-label" style="margin-top:0;">Label</label><input type="color" id="theme-label" value="${escapeHtml(themeLabel)}" aria-label="Label colour"><input type="text" id="theme-label-hex" value="${escapeHtml(themeLabel)}" placeholder="#8b949e"></div>
      <div class="theme-row"><label for="theme-link" style="margin-top:0;">Link</label><input type="color" id="theme-link" value="${escapeHtml(themeLink)}" aria-label="Link colour"><input type="text" id="theme-link-hex" value="${escapeHtml(themeLink)}" placeholder="#58a6ff"></div>
      <div class="theme-row"><label for="theme-tableBg" style="margin-top:0;">Table background</label><input type="color" id="theme-tableBg" value="${escapeHtml(themeTableBg)}" aria-label="Table background"><input type="text" id="theme-tableBg-hex" value="${escapeHtml(themeTableBg)}" placeholder="#161b22"></div>
      <div class="theme-row"><label for="theme-tableHeaderBg" style="margin-top:0;">Table header bg</label><input type="color" id="theme-tableHeaderBg" value="${escapeHtml(themeTableHeaderBg)}" aria-label="Table header background"><input type="text" id="theme-tableHeaderBg-hex" value="${escapeHtml(themeTableHeaderBg)}" placeholder="#21262d"></div>
      <div class="theme-row"><label for="theme-tableHeaderText" style="margin-top:0;">Table header text</label><input type="color" id="theme-tableHeaderText" value="${escapeHtml(themeTableHeaderText)}" aria-label="Table header text"><input type="text" id="theme-tableHeaderText-hex" value="${escapeHtml(themeTableHeaderText)}" placeholder="#8b949e"></div>
      <div class="theme-row"><label for="theme-tableBorder" style="margin-top:0;">Table border</label><input type="color" id="theme-tableBorder" value="${escapeHtml(themeTableBorder)}" aria-label="Table border"><input type="text" id="theme-tableBorder-hex" value="${escapeHtml(themeTableBorder)}" placeholder="#21262d"></div>
    </div>
    <label for="customCss">Custom CSS</label>
    <textarea id="customCss" name="customCss" placeholder="Optional CSS applied to the full database (list) view only">${customCss}</textarea>
    <label for="customCssFile">Load CSS from file</label>
    <input type="file" id="customCssFile" accept=".css,text/css">
    <label for="entryFormId">Entry view form</label>
    <select id="entryFormId" name="entryFormId">
      <option value="">Default</option>
      ${entryFormOptions}
    </select>
    <p class="sub" style="margin-top:0.25rem;">Optional. Choose a form to control colours and layout of the single-entry (read-only) view. <a href="${entryFormId ? "/entry-forms/" + encodeURIComponent(entryFormId) + "/edit" : "/entry-forms"}" id="entry-form-link" class="btn btn-secondary" style="display:inline-block;margin-top:0.25rem;">${entryFormId ? "Edit form" : "Entry forms"}</a></p>
    <label class="field-list-label">Field names</label>
    <div class="field-list" id="field-list"></div>
    <button type="button" class="btn btn-secondary" id="add-field">+ Add field</button>
    <div>
      <button type="submit" class="btn btn-primary">Save</button>
      <a href="/" class="btn btn-secondary" style="margin-left: 0.5rem;">Cancel</a>
    </div>
  </form>
  <div id="msg"></div>
  <script>
    const fieldList = document.getElementById('field-list');
    const addBtn = document.getElementById('add-field');
    const form = document.getElementById('edit-form');
    const msgEl = document.getElementById('msg');
    const profileId = ${JSON.stringify(doc._id)};
    const initialFields = ${JSON.stringify(fieldNames)};

    function addFieldRow(value) {
      const row = document.createElement('div');
      row.className = 'field-row';
      const esc = (v) => (v || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      row.innerHTML = '<input type="text" name="fieldNames" placeholder="Field name" value="' + esc(value) + '"><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button>';
      row.querySelector('.btn-remove').onclick = () => row.remove();
      fieldList.appendChild(row);
    }

    addBtn.onclick = () => addFieldRow();
    (initialFields.length ? initialFields : ['', '']).forEach(v => addFieldRow(v));

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

    const entryFormSelect = document.getElementById('entryFormId');
    const entryFormLink = document.getElementById('entry-form-link');
    if (entryFormSelect && entryFormLink) {
      entryFormSelect.addEventListener('change', () => {
        const val = entryFormSelect.value;
        entryFormLink.href = val ? '/entry-forms/' + encodeURIComponent(val) + '/edit' : '/entry-forms';
        entryFormLink.textContent = val ? 'Edit form' : 'Entry forms';
      });
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
      const fieldNames = Array.from(document.querySelectorAll('input[name="fieldNames"]')).map(i => i.value.trim()).filter(Boolean);
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
          body: JSON.stringify({ _rev, name, description, customCss, fieldNames, entryFormId: document.getElementById('entryFormId').value, theme })
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

function renderCreateProfilePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Create profile</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 32rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="text"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input[type="text"]:focus { outline: none; border-color: #58a6ff; }
    textarea { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; font-family: inherit; min-height: 4rem; resize: vertical; }
    textarea:focus { outline: none; border-color: #58a6ff; }
    .field-row { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center; }
    .field-row input { flex: 1; }
    .field-list { margin: 1rem 0; }
    .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    .btn-primary { background: #238636; color: #fff; margin-top: 1rem; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #e6edf3; }
    .btn-secondary:hover { background: #30363d; }
    .btn-remove { background: transparent; color: #f85149; padding: 0.25rem 0.5rem; }
    .btn-remove:hover { color: #ff7b72; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
  </style>
</head>
<body>
  <h1>Elenko</h1>
  <p class="sub">Create Elenko profile</p>
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
    <div class="field-list" id="field-list"></div>
    <button type="button" class="btn btn-secondary" id="add-field">+ Add field</button>
    <hr>
    <h2 style="margin-top:1.5rem;">Create from import</h2>
    <p class="sub">Load profile definition and data from a configuration in the <code>/io</code> directory.</p>
    <label for="importConfigFile">Config file name in /io</label>
    <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;margin-bottom:0.5rem;">
      <input type="text" id="importConfigFile" placeholder="e.g. compositions.eld" style="flex:1;min-width:12rem;">
      <label for="importFileSelect" style="margin:0;color:#8b949e;">Select file:</label>
      <select id="importFileSelect" class="import-select" style="background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;padding:0.5rem;font-size:1rem;min-width:10rem;">
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

    function addFieldRow(value) {
      const row = document.createElement('div');
      row.className = 'field-row';
      row.innerHTML = '<input type="text" name="fieldNames" placeholder="Field name" value="' + (value || '').replace(/"/g, '&quot;') + '"><button type="button" class="btn btn-remove" aria-label="Remove">Remove</button>';
      row.querySelector('.btn-remove').onclick = () => row.remove();
      fieldList.appendChild(row);
    }

    addBtn.onclick = () => addFieldRow();
    addFieldRow(); addFieldRow();

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
      const fieldNames = Array.from(document.querySelectorAll('input[name="fieldNames"]')).map(i => i.value.trim()).filter(Boolean);
      try {
        const r = await fetch('/api/profiles', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, description, customCss, fieldNames })
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

function renderLoginPage(errorMessage) {
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Login</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .login-box { max-width: 20rem; width: 100%; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input:focus { outline: none; border-color: #58a6ff; }
    .btn { width: 100%; padding: 0.5rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-size: 1rem; margin-top: 1rem; background: #238636; color: #fff; }
    .btn:hover { background: #2ea043; }
    .login-err { color: #f85149; margin-top: 1rem; }
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Elenko</h1>
    <p class="sub">Log in to continue</p>
    ${err}
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required>
      <button type="submit" class="btn">Log in</button>
    </form>
  </div>
</body>
</html>`;
}

function renderChangePasswordPage(errorMessage) {
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Change password</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 24rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="password"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input:focus { outline: none; border-color: #58a6ff; }
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

function renderManageUsersPage(users, currentUsername) {
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Manage users</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; min-height: 100vh; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; max-width: 56rem; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #21262d; }
    th { background: #21262d; color: #8b949e; font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .empty { color: #8b949e; font-style: italic; }
    .empty a { color: #58a6ff; }
    .muted { color: #8b949e; font-size: 0.9em; }
    select { padding: 0.35rem 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; }
    input[type="password"] { padding: 0.35rem 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; }
    .btn-set-password, .btn-delete-user { padding: 0.35rem 0.75rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.875rem; }
    .btn-set-password { background: #238636; color: #fff; }
    .btn-set-password:hover { background: #2ea043; }
    .btn-delete-user { background: #da3633; color: #fff; }
    .btn-delete-user:hover { background: #f85149; }
    .msg { margin-top: 1rem; padding: 0.5rem; border-radius: 6px; }
    .msg.err { background: #3d1f1f; color: #f85149; }
    .msg.ok { background: #1a2f1a; color: #3fb950; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div><a href="/">← Profiles</a> | <a href="/account/users/create">Create user</a></div>
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

function renderCreateUserPage(errorMessage, created) {
  const err = errorMessage ? `<p class="login-err">${escapeHtml(errorMessage)}</p>` : "";
  const createdMsg = created ? '<p class="msg ok">User created.</p>' : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elenko – Create user</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1419; color: #e6edf3; max-width: 24rem; }
    h1 { font-weight: 600; margin-bottom: 0.5rem; }
    .sub { color: #8b949e; margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; margin-bottom: 0.25rem; color: #8b949e; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
    input:focus { outline: none; border-color: #58a6ff; }
    select { width: 100%; padding: 0.5rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; }
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

function renderErrorPage(message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
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

async function main() {
  await initCouch();
  startFlowWorker();
  // Log a startup event so we always get at least one line in the flow log.
  sendFlowMessage("system.start", { pid: process.pid, port: PORT });
  console.log(
    "Flow logging configured for",
    process.env.FLOW_LOG_FILE || path.join(__dirname, "logs", "flow.log")
  );
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Elenko server listening on http://0.0.0.0:${PORT}`);
  });
}

main().catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
