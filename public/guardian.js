// Guardian -> Elenko JS Processing script template
//
// Usage:
// 1) In REST API config, set "Response field" to e.g. "guardianJson".
// 2) In your Flow:
//    - Step 1: Call API (Guardian API doc)
//    - Step 2: JS Processing (this script)
// 3) In profile edit, set "Guardian import Flow ID" to that Flow.
//
// The script reads input.guardianJson and prepares one or more records.
// The backend consumes output._createMany and creates one Elenko entry per item.

// Read raw response text from the API response field.
var raw = (input && typeof input.guardianJson === "string") ? input.guardianJson : "";
if (!raw) {
  output._createMany = [];
  output._writeLog({
    level: "error",
    stage: "input",
    message: "guardianJson is empty. Set API responseField to guardianJson."
  });
  return;
}
output._writeLog({
  level: "info",
  stage: "input",
  message: "guardianJson received",
  rawLength: raw.length
});

var parsed;
try {
  parsed = JSON.parse(raw);
} catch (e) {
  output._createMany = [];
  output._writeLog({
    level: "error",
    stage: "parse",
    message: "Invalid Guardian JSON",
    error: e && e.message ? e.message : String(e)
  });
  return;
}
output._writeLog({
  level: "info",
  stage: "parse",
  message: "JSON parsed successfully"
});

var results =
  parsed &&
  parsed.response &&
  Array.isArray(parsed.response.results)
    ? parsed.response.results
    : [];

// Map Guardian fields -> Elenko profile field names.
// Adjust keys on the LEFT to your own profile fields.
output._createMany = results.map(function(item) {
  return {
    guardianId: item && item.id ? String(item.id) : "",
    webTitle: item && item.webTitle ? String(item.webTitle) : "",
    sectionName: item && item.sectionName ? String(item.sectionName) : "",
    webPublicationDate: item && item.webPublicationDate ? String(item.webPublicationDate) : "",
    webUrl: item && item.webUrl ? String(item.webUrl) : "",
    // Optional fields, available only when requested via show-fields in Guardian query:
    trailText: item && item.fields && item.fields.trailText ? String(item.fields.trailText) : "",
    bodyText: item && item.fields && item.fields.bodyText ? String(item.fields.bodyText) : ""
  };
});

// Optional diagnostics in pipeline dataset/logs.
output.importCount = output._createMany.length;
output._writeLog({
  level: "info",
  stage: "map",
  message: "Mapped Guardian results to _createMany",
  importCount: output.importCount
});
if (output.importCount > 0) {
  output._writeLog({
    level: "debug",
    stage: "sample",
    firstItem: output._createMany[0]
  });
}
