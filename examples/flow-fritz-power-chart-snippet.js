// Elenko flow → JS Processing step after Call API fills `ApiResponse`.
// Writes chart JSON (line) into `PowerData` for a Single Entry field of type **Chart**
// — or paste into any field configured as Chart. mW → W (÷1000).
// X = time (min), Y = power (W).

(function () {
  var raw = input.ApiResponse;
  var root = null;

  if (raw == null || raw === "") {
    output.PowerData = "";
    return;
  }
  if (typeof raw === "string") {
    try {
      root = JSON.parse(raw);
    } catch (e) {
      output.PowerData = "";
      return;
    }
  } else if (typeof raw === "object") {
    root = raw;
  } else {
    output.PowerData = "";
    return;
  }

  var list = root.statistics && root.statistics.powers;
  if (!Array.isArray(list)) {
    output.PowerData = "";
    return;
  }

  var row = null;
  for (var i = 0; i < list.length; i++) {
    var p = list[i];
    if (p && p.period === "hour" && Number(p.interval) === 10 && Array.isArray(p.values)) {
      row = p;
      break;
    }
  }
  if (!row) {
    output.PowerData = "";
    return;
  }

  var valuesMw = row.values;
  var n = valuesMw.length;
  var xMinutes = [];
  var yWatts = [];
  for (var j = 0; j < n; j++) {
    var minRaw = (j * 10) / 60;
    xMinutes.push(Math.round(minRaw * 10) / 10);
    yWatts.push(Number(valuesMw[j]) / 1000);
  }

  var xTitle = "Time (min)";
  var yTitle = "Power (W)";

  var chart = {
    version: 1,
    chartType: "line",
    title: "",
    xAxis: { title: xTitle, values: xMinutes },
    yAxis: { title: yTitle, values: yWatts },
    heightPx: 320,
  };

  output.PowerData = JSON.stringify(chart);
})();
