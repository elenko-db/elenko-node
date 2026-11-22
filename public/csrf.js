/** Injects X-CSRF-Token on same-origin mutating fetch calls (token from meta or elenko-csrf cookie). */
(function () {
  function readCsrfToken() {
    var meta = document.querySelector('meta[name="elenko-csrf-token"]');
    if (meta) {
      var c = meta.getAttribute("content");
      if (c) return c;
    }
    var m = document.cookie.match(/(?:^|;\s*)elenko-csrf=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  var nativeFetch = window.fetch;
  if (typeof nativeFetch !== "function") return;

  window.fetch = function (input, init) {
    init = init || {};
    var method = (init.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      var url = typeof input === "string" ? input : input && input.url ? input.url : "";
      try {
        var resolved = new URL(url, window.location.href);
        if (resolved.origin === window.location.origin) {
          var token = readCsrfToken();
          if (token) {
            var headers = new Headers(init.headers || {});
            if (!headers.has("X-CSRF-Token")) headers.set("X-CSRF-Token", token);
            init.headers = headers;
          }
        }
      } catch (_) {}
    }
    return nativeFetch.call(this, input, init);
  };
})();