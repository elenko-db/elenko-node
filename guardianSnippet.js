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

function sentenceEndsWithQuote(sentence) {
  return /(?:\.["'\u201d\u2019]+|["'\u201d\u2019]+\.)$/.test(sentence);
}

function splitTextIntoSentences(text) {
  var sentences = [];
  var sentenceStart = 0;
  var quoteChars = "\"'\u201d\u2019";

  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== ".") continue;

    var sentenceEnd = i + 1;
    while (sentenceEnd < text.length && quoteChars.indexOf(text.charAt(sentenceEnd)) !== -1) {
      sentenceEnd += 1;
    }

    if (sentenceEnd >= text.length || /\s/.test(text.charAt(sentenceEnd))) {
      var sentence = text.slice(sentenceStart, sentenceEnd).trim();
      if (sentence) sentences.push(sentence);

      while (sentenceEnd < text.length && /\s/.test(text.charAt(sentenceEnd))) {
        sentenceEnd += 1;
      }
      sentenceStart = sentenceEnd;
      i = sentenceEnd - 1;
    }
  }

  var remainder = text.slice(sentenceStart).trim();
  if (remainder) sentences.push(remainder);

  return sentences;
}

function splitBodyTextIntoSections(bodyText) {
  var text = bodyText ? String(bodyText).replace(/\s+/g, " ").trim() : "";
  if (!text) return [];

  var sentences = splitTextIntoSentences(text);
  var sections = [];
  var current = [];
  var sentenceCount = 0;

  sentences.forEach(function(sentence) {
    var cleanSentence = String(sentence).trim();
    if (!cleanSentence) return;

    current.push(cleanSentence);
    sentenceCount += 1;

    if (sentenceEndsWithQuote(cleanSentence) || sentenceCount >= 3) {
      sections.push(current.join(" "));
      current = [];
      sentenceCount = 0;
    }
  });

  if (current.length > 0) {
    sections.push(current.join(" "));
  }

  return sections;
}

// Map Guardian fields -> Elenko profile field names.
// Adjust keys on the LEFT to your own profile fields.
output._createMany = results.map(function(item) {
  var rawBodyText = item && item.fields && item.fields.bodyText ? String(item.fields.bodyText) : "";
  var bodyTextSections = splitBodyTextIntoSections(rawBodyText);

  return {
    guardianId: item && item.id ? String(item.id) : "",
    webTitle: item && item.webTitle ? String(item.webTitle) : "",
    sectionName: item && item.sectionName ? String(item.sectionName) : "",
    webPublicationDate: item && item.webPublicationDate ? String(item.webPublicationDate) : "",
    webUrl: item && item.webUrl ? String(item.webUrl) : "",
    // Optional fields, available only when requested via show-fields in Guardian query:
    trailText: item && item.fields && item.fields.trailText ? String(item.fields.trailText) : "",
    bodyText: bodyTextSections.join("\n\n"),
    bodyTextSections: bodyTextSections
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
