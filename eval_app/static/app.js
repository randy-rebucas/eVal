// Audit progress polling. Elements with data-progress-url poll until the audit finishes, then reload.
(function () {
  // CSP forbids inline style attributes; bar widths are carried in data-width and applied here.
  document.querySelectorAll("[data-width]").forEach(function (el) {
    var w = parseFloat(el.getAttribute("data-width"));
    if (!isNaN(w)) { el.style.width = Math.max(0, Math.min(100, w)) + "%"; }
  });
  // Risk rail steps take space in proportion to their repository count (equal widths without JS).
  document.querySelectorAll("[data-grow]").forEach(function (el) {
    var n = parseFloat(el.getAttribute("data-grow"));
    if (!isNaN(n)) { el.style.flexGrow = String(Math.max(n, 0.5)); }
  });

  document.querySelectorAll("[data-progress-url]").forEach(function (el) {
    var url = el.getAttribute("data-progress-url");
    var bar = el.querySelector(".progress-bar");
    var label = el.querySelector("[data-stage]");
    var pct = el.querySelector("[data-progress-pct]");
    var log = el.querySelector("[data-audit-log-items]");
    var lastStage = label ? label.textContent : "";
    var lastProgress = bar ? parseInt(bar.textContent, 10) : -1;

    function appendLog(stage, progress) {
      if (!log) { return; }
      var item = document.createElement("li");
      var time = document.createElement("time");
      time.textContent = new Date().toLocaleTimeString();
      item.appendChild(time);
      item.appendChild(document.createTextNode(" " + stage + " · " + progress + "%"));
      log.appendChild(item);
      if (el.querySelector("[data-audit-log]").open) {
        log.scrollTop = log.scrollHeight;
      }
    }

    function tick() {
      fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) { return; }
          if (bar) { bar.style.width = data.progress + "%"; bar.textContent = data.progress + "%"; }
          if (label) { label.textContent = data.stage; }
          if (pct) { pct.textContent = data.progress + "%"; }
          if (data.stage !== lastStage || data.progress !== lastProgress) {
            appendLog(data.stage, data.progress);
            lastStage = data.stage;
            lastProgress = data.progress;
          }
          if (["succeeded", "failed", "cancelled"].indexOf(data.status) !== -1) {
            window.location.reload();
          } else {
            setTimeout(tick, 2000);
          }
        })
        .catch(function () { setTimeout(tick, 5000); });
    }
    setTimeout(tick, 1500);
  });

  // Folded register rows. The server renders them open so they read without JS; the fold closes them here.
  document.querySelectorAll("[data-fold]").forEach(function (btn) {
    var body = document.getElementById(btn.getAttribute("aria-controls"));
    if (!body) { return; }
    function set(open) {
      body.hidden = !open;
      btn.setAttribute("aria-expanded", String(open));
      btn.textContent = btn.getAttribute(open ? "data-label-open" : "data-label-closed");
    }
    set(false);
    btn.hidden = false;
    btn.addEventListener("click", function () { set(body.hidden); });
  });

  // Filters that apply when picked with a pointer. Keyboard changes (arrow keys fire "change" on a closed
  // select in some browsers) wait for the Apply button, so moving through options never reloads the page.
  document.querySelectorAll("select[data-autosubmit]").forEach(function (sel) {
    var byPointer = false;
    sel.addEventListener("pointerdown", function () { byPointer = true; });
    sel.addEventListener("keydown", function () { byPointer = false; });
    sel.addEventListener("change", function () { if (byPointer) { sel.form.submit(); } });
  });

  // Confirmation for consequential buttons (inline handlers are blocked by CSP). Drawn as a confirmation
  // note in a native <dialog> (focus held, Esc cancels); browsers without <dialog> fall back to confirm().
  var note = null;
  function confirmNote() {
    if (note) { return note; }
    note = document.createElement("dialog");
    note.className = "confirm-note";
    note.setAttribute("aria-labelledby", "confirm-h");
    note.setAttribute("aria-describedby", "confirm-msg");
    note.innerHTML =
      '<form method="dialog">' +
      '<h2 class="confirm-h" id="confirm-h">Confirm</h2>' +
      '<p class="confirm-msg" id="confirm-msg"></p>' +
      '<div class="confirm-acts">' +
      '<button class="btn-ink" value="ok" data-confirm-ok></button>' +
      '<button class="act act-quiet" value="cancel" autofocus>Cancel</button>' +
      "</div></form>";
    document.body.appendChild(note);
    return note;
  }

  document.querySelectorAll("[data-confirm]").forEach(function (btn) {
    btn.addEventListener("click", function (ev) {
      var message = btn.getAttribute("data-confirm");
      if (typeof HTMLDialogElement !== "function" || !btn.form) {
        if (!window.confirm(message)) { ev.preventDefault(); }
        return;
      }
      ev.preventDefault();
      var dlg = confirmNote();
      dlg.querySelector(".confirm-msg").textContent = message;
      dlg.querySelector("[data-confirm-ok]").textContent = btn.getAttribute("data-confirm-ok") || "Confirm";
      dlg.returnValue = "";
      dlg.addEventListener("close", function () {
        if (dlg.returnValue !== "ok") { btn.focus(); return; }
        if (btn.form.requestSubmit) { btn.form.requestSubmit(btn); } else { btn.form.submit(); }
      }, { once: true });
      dlg.showModal();
    });
  });

  // Landing sample audit: analyzers report in one by one, then the verdict letters itself. The server renders the
  // finished audit, so it reads complete without JS and under reduced motion.
  document.querySelectorAll("[data-live-audit]").forEach(function (pane) {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) { return; }
    var rows = Array.prototype.slice.call(pane.querySelectorAll("[data-step]"));
    var verdict = pane.querySelector("[data-verdict]");
    var state = pane.querySelector("[data-run-state]");
    var count = pane.querySelector("[data-run-count]");
    var replay = pane.querySelector("[data-replay]");
    var doneState = state.textContent, doneCount = count.textContent, timers = [];

    function play() {
      timers.forEach(clearTimeout);
      timers = [];
      pane.classList.add("is-live");
      state.textContent = "Auditing · static analysis only";
      verdict.classList.add("is-pending");
      rows.forEach(function (r) { r.classList.remove("is-active"); r.classList.add("is-pending"); });
      rows.forEach(function (r, i) {
        timers.push(setTimeout(function () {
          if (i > 0) { rows[i - 1].classList.remove("is-active"); }
          r.classList.remove("is-pending");
          r.classList.add("is-active");
          count.textContent = (i + 1) + " of " + rows.length + " analyzers";
        }, 260 + i * 120));
      });
      timers.push(setTimeout(function () {
        rows[rows.length - 1].classList.remove("is-active");
        pane.classList.remove("is-live");
        state.textContent = doneState;
        count.textContent = doneCount;
        verdict.classList.remove("is-pending");
      }, 260 + rows.length * 120 + 200));
    }

    replay.hidden = false;
    replay.addEventListener("click", play);
    play();
  });

  // Theme toggle: dark is the default; the choice is remembered per browser (applied early by theme.js).
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var root = document.documentElement;
      var next = root.getAttribute("data-bs-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("eval-theme", next); } catch (e) { /* storage blocked */ }
    });
  });

  // Sidebar drawer on narrow screens. Without JS the sidebar simply stacks above the page.
  var sideBtn = document.querySelector("[data-side-toggle]");
  if (sideBtn) {
    var setSide = function (open) {
      document.body.classList.toggle("side-open", open);
      sideBtn.setAttribute("aria-expanded", String(open));
    };
    var narrow = window.matchMedia("(max-width: 960px)");
    var syncBtn = function () { sideBtn.hidden = !narrow.matches; if (!narrow.matches) { setSide(false); } };
    syncBtn();
    if (narrow.addEventListener) { narrow.addEventListener("change", syncBtn); }
    sideBtn.addEventListener("click", function () { setSide(!document.body.classList.contains("side-open")); });
    document.addEventListener("click", function (ev) {
      if (document.body.classList.contains("side-open") && !ev.target.closest("#side, [data-side-toggle]")) { setSide(false); }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && document.body.classList.contains("side-open")) { setSide(false); sideBtn.focus(); }
    });
  }

  // Copy-to-clipboard for command snippets.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    if (!navigator.clipboard) { return; }
    btn.hidden = false;
    var label = btn.querySelector("span");
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
        btn.classList.add("is-done");
        if (label) { label.textContent = "copied"; }
        setTimeout(function () { btn.classList.remove("is-done"); if (label) { label.textContent = "copy"; } }, 1600);
      });
    });
  });

  // "Select all" checkbox for finding tables.
  document.querySelectorAll("[data-select-all]").forEach(function (box) {
    box.addEventListener("change", function () {
      document.querySelectorAll(box.getAttribute("data-select-all")).forEach(function (c) { c.checked = box.checked; });
    });
  });
})();
