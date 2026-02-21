# Sort key field implementation for Elenko

This guide describes how to add CouchDB index-based sorting using a `_sortKey` field and up to 3 configurable fields per profile (including `_createdAt` / `_updatedAt`). Apply these changes in `server.js`.

---

## 1. Constants and helper

**After** the existing `MAX_ENTRIES_FOR_SORT` (or near other constants), add:

```javascript
// Special sort key field names for creation/update date
const SORT_KEY_SPECIAL = ["_createdAt", "_updatedAt"];
const SORT_KEY_FIELDS_MAX = 3;
```

**Add this helper** (e.g. after `escapeRegex`):

```javascript
function buildSortKey(record, sortKeyFields) {
  if (!Array.isArray(sortKeyFields) || sortKeyFields.length === 0) return [];
  const out = [];
  for (let i = 0; i < Math.min(sortKeyFields.length, SORT_KEY_FIELDS_MAX); i++) {
    const f = sortKeyFields[i];
    if (!f || typeof f !== "string" || !f.trim()) continue;
    const key = f.trim();
    if (SORT_KEY_SPECIAL.includes(key)) {
      out.push(record[key] != null ? String(record[key]) : "");
    } else {
      out.push(record[key] != null ? String(record[key]) : "");
    }
  }
  return out;
}
```

---

## 2. CouchDB index for _sortKey

**In the startup block** where other indexes are created (e.g. after `records-by-profile-id`), add:

```javascript
  // Index for sorting entries by _sortKey (profile's sort key fields)
  try {
    await db.createIndex({
      index: { fields: ["type", "profileId", "_sortKey"] },
      name: "records-by-profile-sortkey",
    });
  } catch (e) {
    // Index may already exist
  }
```

---

## 3. Profile: store sortKeyFields and sortDirection

**In PUT /api/profiles/:id** (where you set `doc.sortField`, `doc.sortDirection`):

- **Remove** the existing `sortField` / `sortDirection` logic (the in-memory sort branch in GET will be replaced by _sortKey).
- **Add** parsing and validation for `sortKeyFields` (array of up to 3 strings: field names or `_createdAt` / `_updatedAt`):

```javascript
    // sortKeyFields: up to 3 field names or _createdAt / _updatedAt
    const rawSortKeyFields = Array.isArray(req.body.sortKeyFields) ? req.body.sortKeyFields : [];
    const sortKeyFields = rawSortKeyFields
      .filter((f) => typeof f === "string" && f.trim())
      .slice(0, SORT_KEY_FIELDS_MAX)
      .map((f) => f.trim())
      .filter((f) => fields.includes(f) || SORT_KEY_SPECIAL.includes(f));
    doc.sortKeyFields = sortKeyFields;
    doc.sortDirection = sortDirection === "desc" ? "desc" : "asc";
```

Keep using `doc.sortDirection` for ascending/descending when querying by `_sortKey`.

---

## 4. Entry create: set _createdAt, _updatedAt, _sortKey

**In POST /api/profiles/:id/entries** (create entry):

- After building `record` (type, profileId, and field values), add:

```javascript
    const now = new Date().toISOString();
    record._createdAt = now;
    record._updatedAt = now;
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    record._sortKey = buildSortKey(record, sortKeyFields);
```

- Then `db.insert(record)` as usual.

---

## 5. Entry update: set _updatedAt and _sortKey

**In PUT /api/profiles/:id/entries/:entryId** (update entry):

- After copying field values into the existing record and before `db.insert(record)`:
  - Set `record._updatedAt = new Date().toISOString();`
  - If the record has no `_createdAt`, set `record._createdAt = record._updatedAt` (for older docs).
  - Load the profile to get `sortKeyFields`: `const profile = await db.get(record.profileId);` then `record._sortKey = buildSortKey(record, profile.sortKeyFields || []);`

---

## 6. Bulk create (import): set _createdAt, _updatedAt, _sortKey

**In the import profile route** that creates multiple entries in a loop:

- For each entry doc before insert: set `_createdAt` and `_updatedAt` to the same timestamp, and set `_sortKey = buildSortKey(entryDoc, profile.sortKeyFields || [])` (use the same `sortKeyFields` from the profile you’re importing into).

---

## 7. GET /profile/:id: use _sortKey index when configured

**Replace** the current logic that uses `sortField` + in-memory sort with:

- If `doc.sortKeyFields` has length > 0:  
  - Use `db.find` with the same selector (`type: "elenko_record", profileId`, plus search `$or` if applicable).
  - Use `sort: [{ _sortKey: doc.sortDirection === "desc" ? "desc" : "asc" }]`.
  - Use `skip` and `limit` for pagination (no in-memory sort; CouchDB handles it).
- Else (no sort key fields):  
  - Keep existing behaviour: `sort: [{ _id: "asc" }]`, same selector, skip/limit.

Keep `totalPages` calculation (view count when no search; when search is used you may need to run a separate count or limit+1 fetch depending on your current implementation).

---

## 8. Rebuild sort keys for existing entries

**Add** an endpoint (e.g. admin-only):

```javascript
app.post("/api/profiles/:id/rebuild-sort-keys", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await db.get(id);
    if (!doc || doc.type !== "elenko_profile") {
      return res.status(404).json({ error: "Profile not found" });
    }
    const sortKeyFields = Array.isArray(doc.sortKeyFields) ? doc.sortKeyFields : [];
    const result = await db.find({
      selector: { type: "elenko_record", profileId: id },
      fields: ["_id", "_rev", "_createdAt", "_updatedAt", ...(Array.isArray(doc.fieldNames) ? doc.fieldNames : [])],
      limit: 50000,
    });
    const docs = result.docs || [];
    let updated = 0;
    const now = new Date().toISOString();
    for (const rec of docs) {
      if (!rec._createdAt) rec._createdAt = now;
      rec._updatedAt = now;
      rec._sortKey = buildSortKey(rec, sortKeyFields);
      await db.insert(rec);
      updated++;
    }
    res.json({ ok: true, updated });
  } catch (err) {
    console.error("Rebuild sort keys error:", err);
    res.status(500).json({ error: err.message || "Rebuild failed" });
  }
});
```

---

## 9. Edit profile UI: sort key fields (up to 3)

**In the edit profile page** (e.g. `renderEditProfilePage`):

- **Remove** the single “Sort entries by” dropdown and “Sort direction” that referred to `sortField` (or keep only “Sort direction” if you still use it for _sortKey).
- **Add** a “Sort key fields” section:
  - Up to 3 dropdowns.
  - Each option: “— None —” (value `""`), then each of `fieldNames`, then “Creation date” (`_createdAt`), “Update date” (`_updatedAt`).
  - Value for each dropdown comes from `doc.sortKeyFields[i]` (or empty).
- On save, send `sortKeyFields` as an array of the selected values (e.g. `["mediaCode", "trackIndex", ""]`) and keep sending `sortDirection`.

Example structure for one dropdown:

```html
<select name="sortKeyField1" id="sortKeyField1">
  <option value="">— None —</option>
  <!-- one option per fieldNames -->
  <option value="_createdAt">Creation date</option>
  <option value="_updatedAt">Update date</option>
</select>
```

Repeat for sortKeyField2 and sortKeyField3. In the submit handler, build:

```javascript
sortKeyFields: [
  document.getElementById('sortKeyField1').value,
  document.getElementById('sortKeyField2').value,
  document.getElementById('sortKeyField3').value,
].filter(Boolean)
```

(Or keep empty strings and filter on the server as in step 3.)

---

## 10. Optional: “Rebuild sort keys” button

In the edit profile page, add a button that calls `POST /api/profiles/:id/rebuild-sort-keys` and shows “Rebuilt N entries” so existing entries get `_sortKey` (and optionally `_createdAt`/`_updatedAt`) without re-saving each one manually.

---

## Summary

- **Index:** `["type", "profileId", "_sortKey"]` for CouchDB to sort by `_sortKey`.
- **Profile:** `sortKeyFields` (array, max 3): field names or `_createdAt` / `_updatedAt`; `sortDirection` for asc/desc.
- **Records:** `_createdAt`, `_updatedAt`, and `_sortKey` (array of values) set on create and update; rebuild endpoint for backfill.
- **Listing:** When `sortKeyFields.length > 0`, use `sort: [{ _sortKey: "asc"|"desc" }]` and normal pagination; otherwise keep `_id` sort.

This removes the need for in-memory sort and the 5000-entry limit when using the sort key.
