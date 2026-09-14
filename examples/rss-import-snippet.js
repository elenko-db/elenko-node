// RSS -> Elenko JS Processing script
//
// JS Processing runs in a sandbox (no fetch). Fetch the feed in a prior flow step:
//   1) Call API  — GET URL: #feedUrl#  (or full feed URL), Response field: rssXml
//   2) Run script (this file)
//
// Config profile (one entry per feed), suggested fields:
//   feedUrl          — RSS/Atom URL
//   sourceName       — e.g. "The Guardian UK"
//   targetProfileId  — profile id or name of the news inbox profile
//   maxItems         — optional cap (default 25)
//   lastRun          — ISO UTC (script)
//   lastImported     — Update step, Param: lastImported
//
// News profile fields (map in mapItemToRecord below), e.g.:
//   title, url (URL type), publishedAt, summary (plain text), sourceName, feedGuid
//
// HTML in feed descriptions is stripped to plain text for summary/title/author.
//
// Flow on config entry (timer or flow button with entry context):
//   Call API -> JS Processing
//
// output._createMany rows may set _targetProfileId to push into another profile.

var raw = input && typeof input.rssXml === "string" ? input.rssXml : "";
var sourceName = input && input.sourceName != null ? String(input.sourceName) : "";
var targetProfileId = input && input.targetProfileId != null ? String(input.targetProfileId).trim() : "";
function resolveMaxItems(raw) {
  if (raw == null) return 40;
  var s = String(raw).trim();
  if (!s) return 40;
  if (s.charAt(0) === "{") {
    try {
      var parsed = JSON.parse(s);
      if (parsed && typeof parsed === "object" && Array.isArray(parsed.rows) && parsed.rows.length > 0) {
        s = String(parsed.rows[0] != null ? parsed.rows[0] : "").trim();
      }
    } catch (_) {}
  }
  var n = parseInt(s, 10);
  if (!Number.isFinite(n) || n <= 0) return 40;
  return Math.min(n, 100);
}

var maxItems = resolveMaxItems(input && input.maxItems);

function runTimestampIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

if (!raw.trim()) {
  output._createMany = [];
  output.lastRun = runTimestampIso();
  output._writeLog({
    level: "error",
    stage: "input",
    message: "rssXml is empty. Add a Call API step with Response field rssXml (GET #feedUrl#).",
  });
  return;
}

function decodeXmlEntities(text) {
  var s = text != null ? String(text) : "";
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, function(_, n) {
      var code = parseInt(n, 10);
      return Number.isFinite(code) ? String.fromCharCode(code) : _;
    })
    .replace(/&#x([0-9a-fA-F]+);/g, function(_, h) {
      var code = parseInt(h, 16);
      return Number.isFinite(code) ? String.fromCharCode(code) : _;
    })
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/g, "&");
}

function htmlToPlainText(html) {
  var s = String(html || "");
  s = s.replace(new RegExp("<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>", "gi"), "$1");
  s = s.replace(new RegExp("<script[\\s\\S]*?<\\/script>", "gi"), "");
  s = s.replace(new RegExp("<style[\\s\\S]*?<\\/style>", "gi"), "");
  s = s.replace(new RegExp("<br\\s*/?>", "gi"), "\n");
  s = s.replace(new RegExp("<hr\\s*/?>", "gi"), "\n\n");
  s = s.replace(
    new RegExp(
      "</(?:p|div|section|article|blockquote|h[1-6]|tr|li|ul|ol|pre|figcaption|header|footer|main|aside|figure|table|thead|tbody|tfoot)>",
      "gi"
    ),
    "\n"
  );
  s = s.replace(
    new RegExp(
      "<(?:p|div|section|article|blockquote|h[1-6]|tr|li|ul|ol|pre|figcaption|header|footer|main|aside|figure|table|thead|tbody|tfoot)(?:\\s[^>]*)?>",
      "gi"
    ),
    "\n"
  );
  s = s.replace(/<[^>]+>/g, " ");
  s = decodeXmlEntities(s).replace(/\u00a0/g, " ");
  var lines = s.split("\n");
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].replace(/\s+/g, " ").trim();
    if (!line && out.length && out[out.length - 1] === "") continue;
    out.push(line);
  }
  while (out.length && out[0] === "") out.shift();
  while (out.length && out[out.length - 1] === "") out.pop();
  return out.join("\n");
}

function escapeRegExp(text) {
  return String(text || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizePublishedAt(raw) {
  var s = raw != null ? String(raw).trim() : "";
  if (!s) return "";
  var d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function tagText(block, tagName) {
  var safeTag = escapeRegExp(tagName);
  var re = new RegExp("<" + safeTag + "(?:\\s[^>]*)?>([\\s\\S]*?)<\\/" + safeTag + ">", "i");
  var m = re.exec(block);
  if (!m) return "";
  return htmlToPlainText(m[1]);
}

function linkHref(block) {
  var m = /<link\b([^>]*)>/i.exec(block);
  if (!m) return tagText(block, "link");
  var hrefM = /\bhref\s*=\s*"([^"]+)"/i.exec(m[1]) || /\bhref\s*=\s*'([^']+)'/i.exec(m[1]);
  if (hrefM) return decodeXmlEntities(hrefM[1]).trim();
  return tagText(block, "link");
}

function parseRss2Items(xml) {
  var items = [];
  var text = String(xml || "");
  var parts = text.split(/<item\b/i);
  for (var pi = 1; pi < parts.length; pi++) {
    var chunk = parts[pi];
    var end = chunk.search(/<\/item>/i);
    if (end < 0) continue;
    var block = "<item" + chunk.slice(0, end + 7);
    items.push({
      title: tagText(block, "title"),
      link: linkHref(block),
      description: tagText(block, "description") || tagText(block, "content:encoded"),
      pubDate: tagText(block, "pubDate"),
      guid: tagText(block, "guid") || linkHref(block),
      author: tagText(block, "author") || tagText(block, "dc:creator"),
    });
  }
  return items;
}

function parseAtomEntries(xml) {
  var items = [];
  var re = /<entry\b[\s\S]*?<\/entry>/gi;
  var m;
  while ((m = re.exec(xml)) !== null) {
    var block = m[0];
    var link = "";
    var linkRe = /<link\b([^>]*)\/?>/gi;
    var lm;
    while ((lm = linkRe.exec(block)) !== null) {
      var attrs = lm[1] || "";
      if (/\brel\s*=\s*["']alternate["']/i.test(attrs) || !/\brel\s*=/.test(attrs)) {
        var hrefM = /\bhref\s*=\s*"([^"]+)"/i.exec(attrs) || /\bhref\s*=\s*'([^']+)'/i.exec(attrs);
        if (hrefM) {
          link = decodeXmlEntities(hrefM[1]).trim();
          break;
        }
      }
    }
    items.push({
      title: tagText(block, "title"),
      link: link,
      description: tagText(block, "summary") || tagText(block, "content"),
      pubDate: tagText(block, "updated") || tagText(block, "published"),
      guid: tagText(block, "id") || link,
      author: tagText(block, "name"),
    });
  }
  return items;
}

function parseFeedXml(xml) {
  var text = String(xml || "").trim();
  if (!text) return [];
  if (/<feed\b/i.test(text)) return parseAtomEntries(text);
  return parseRss2Items(text);
}

function mapItemToRecord(item) {
  var title = htmlToPlainText(item && item.title ? item.title : "");
  var url = item && item.link ? String(item.link).trim() : "";
  var guid = item && item.guid ? String(item.guid).trim() : url;
  var row = {
    title: title,
    url: url,
    publishedAt: normalizePublishedAt(item && item.pubDate ? item.pubDate : ""),
    summary: htmlToPlainText(item && item.description ? item.description : ""),
    sourceName: sourceName,
    feedGuid: guid,
    author: htmlToPlainText(item && item.author ? item.author : ""),
  };
  if (targetProfileId) row._targetProfileId = targetProfileId;
  return row;
}

var parsedItems = parseFeedXml(raw);
output._writeLog({
  level: "info",
  stage: "parse",
  message: "RSS/Atom parsed",
  itemCount: parsedItems.length,
  maxItems: maxItems,
  rssBytes: raw.length,
  sourceName: sourceName,
  targetProfileId: targetProfileId || "(current profile)",
});

var rows = [];
for (var i = 0; i < parsedItems.length && rows.length < maxItems; i++) {
  var rec = mapItemToRecord(parsedItems[i]);
  if (!rec.title && !rec.url) continue;
  rows.push(rec);
}

output.lastRun = runTimestampIso();
output._createMany = rows;
output.importCount = rows.length;

if (rows.length > 0) {
  output._writeLog({
    level: "debug",
    stage: "sample",
    firstItem: rows[0],
  });
}
