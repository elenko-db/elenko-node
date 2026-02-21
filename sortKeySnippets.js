/**
 * Snippets for sort-key implementation in server.js.
 * Copy the parts you need into server.js (see SORT_KEY_IMPLEMENTATION.md).
 */

// --- Constants (add near other constants, e.g. after MAX_ENTRIES_FOR_SORT) ---
const SORT_KEY_SPECIAL = ["_createdAt", "_updatedAt"];
const SORT_KEY_FIELDS_MAX = 3;

// --- Helper: build _sortKey array from record and profile's sortKeyFields ---
function buildSortKey(record, sortKeyFields) {
  if (!Array.isArray(sortKeyFields) || sortKeyFields.length === 0) return [];
  const out = [];
  for (let i = 0; i < Math.min(sortKeyFields.length, SORT_KEY_FIELDS_MAX); i++) {
    const f = sortKeyFields[i];
    if (!f || typeof f !== "string" || !f.trim()) continue;
    const key = f.trim();
    out.push(record[key] != null ? String(record[key]) : "");
  }
  return out;
}

// --- Index creation (add in startup, with other createIndex calls) ---
// await db.createIndex({
//   index: { fields: ["type", "profileId", "_sortKey"] },
//   name: "records-by-profile-sortkey",
// });

module.exports = { SORT_KEY_SPECIAL, SORT_KEY_FIELDS_MAX, buildSortKey };
