// Sandbox terminal: xterm.js wired to the sandbox service's websocket. eVal issues a short-lived token for each
// connection (POST …/token); the first websocket message presents it, so it never appears in a URL or a log.
(function () {
  var screen = document.querySelector("[data-terminal]");
  if (!screen || typeof Terminal === "undefined" || typeof FitAddon === "undefined") { return; }
  var status = document.querySelector("[data-terminal-status]");
  var css = getComputedStyle(document.documentElement);
  function token(name, fallback) { return (css.getPropertyValue(name) || "").trim() || fallback; }

  var term = new Terminal({
    cursorBlink: true, scrollback: 5000, fontSize: 13, lineHeight: 1.2,
    fontFamily: token("--mono", "monospace"),
    theme: {
      background: token("--term-bg", "#07090c"), foreground: token("--term-fg", "#d4dde5"),
      cursor: token("--term-accent", "#5ccfe6"), selectionBackground: "rgba(92, 207, 230, .3)",
    },
  });
  var fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(screen);
  fit.fit();

  var ws = null, retries = 0, done = false;
  var CLOSED = {
    4000: "the shell exited", 4401: "not authorized", 4404: "the session has ended",
    4408: "the time limit was reached", 4409: "opened in another tab",
  };
  function say(text) { if (status) { status.textContent = text; } }
  function note(text) { term.write("\r\n\x1b[2m[" + text + "]\x1b[0m\r\n"); }
  function send(msg) { if (ws && ws.readyState === WebSocket.OPEN) { ws.send(JSON.stringify(msg)); } }
  function resize() { fit.fit(); send({ t: "r", rows: term.rows, cols: term.cols }); }
  function retry() {
    if (done) { return; }
    if (retries >= 5) { say("disconnected"); note("disconnected; reload the page to reconnect"); return; }
    retries++;
    say("reconnecting…");
    setTimeout(connect, 1000 * retries);
  }

  function connect() {
    say("connecting…");
    fetch(screen.getAttribute("data-token-url"), {
      method: "POST", credentials: "same-origin",
      headers: { Accept: "application/json", "X-CSRFToken": screen.getAttribute("data-csrf") },
    })
      .then(function (r) { return r.json().then(function (data) { return { ok: r.ok, data: data }; }); })
      .then(function (res) {
        if (!res.ok) { done = true; say("ended"); note(res.data.error || "the session has ended"); return; }
        ws = new WebSocket(res.data.url);
        ws.binaryType = "arraybuffer";
        ws.onopen = function () {
          ws.send(JSON.stringify({ t: "auth", token: res.data.token }));
          retries = 0;
          say("connected");
          resize();
          term.focus();
        };
        ws.onmessage = function (ev) { term.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data)); };
        ws.onclose = function (ev) {
          if (CLOSED[ev.code]) { done = true; say(CLOSED[ev.code]); note(CLOSED[ev.code]); return; }
          retry();
        };
      })
      .catch(retry);
  }

  term.onData(function (data) { send({ t: "i", d: data }); });
  var timer = null;
  window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(resize, 150); });
  connect();
})();
