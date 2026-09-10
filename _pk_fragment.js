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

