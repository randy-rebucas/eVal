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

  // AI model picker follows the provider select. Built-in suggestions show at once; the provider's own model
  // list (fetched with the selected key, or from the allow-listed compatible server) replaces them when it
  // arrives. Without JS the saved provider's suggestions are listed and the free-text field stays visible.
  document.querySelectorAll("select[data-ai-models]").forEach(function (sel) {
    var catalog;
    try { catalog = JSON.parse(sel.getAttribute("data-ai-models")); } catch (e) { return; }
    var form = sel.form;
    var provider = document.querySelector(sel.getAttribute("data-provider-select"));
    var custom = document.querySelector(sel.getAttribute("data-custom-input"));
    var status = document.querySelector(sel.getAttribute("data-models-status"));
    var url = sel.getAttribute("data-models-url");
    var request = 0;
    function syncCustom() { if (custom) { custom.hidden = sel.value !== ""; } }
    function say(text) { if (status) { status.textContent = text; } }
    // Keep the current pick (listed or typed) when it is in the new list; otherwise take the first model.
    function fill(models) {
      var want = sel.value || (custom ? custom.value.trim() : "");
      sel.innerHTML = "";
      models.forEach(function (m) { sel.add(new Option(m, m)); });
      sel.add(new Option("Other…", ""));
      if (want && models.indexOf(want) !== -1) {
        sel.value = want;
        if (custom) { custom.value = ""; }
      } else if (want && custom && custom.value.trim() === want) {
        sel.value = "";
      } else {
        sel.selectedIndex = 0;
        if (custom) { custom.value = ""; }
      }
      syncCustom();
    }
    function load() {
      if (!url || !form || !provider) { return; }
      var mine = ++request;
      var key = form.elements.credential_id ? form.elements.credential_id.value : "";
      if (!key && provider.value !== "openai_compatible") {
        say("Select an API key to load this provider's models.");
        return;
      }
      say("Loading models…");
      fetch(url, { method: "POST", body: new FormData(form), credentials: "same-origin",
                   headers: { Accept: "application/json" } })
        .then(function (r) { return r.json().catch(function () { return {}; }); })
        .then(function (data) {
          if (mine !== request) { return; }
          if (data.models && data.models.length) {
            fill(data.models);
            say(data.models.length + " models available to this key.");
          } else {
            say((data.error || "The provider returned no models.") + " Showing suggestions.");
          }
        })
        .catch(function () { if (mine === request) { say("Could not load models. Showing suggestions."); } });
    }
    if (provider) {
      provider.addEventListener("change", function () {
        if (custom) { custom.value = ""; }
        sel.value = "";
        fill(catalog[provider.value] || []);
        load();
      });
    }
    ["credential_id", "base_url"].forEach(function (name) {
      var el = form && form.elements[name];
      if (el) { el.addEventListener("change", load); }
    });
    sel.addEventListener("change", function () {
      syncCustom();
      if (custom && !custom.hidden) { custom.focus(); }
    });
    syncCustom();
    load();
  });

  // Type-to-filter for long row lists (e.g. the GitHub repository browser). Rows carry data-filter-text.
  document.querySelectorAll("[data-filter-rows]").forEach(function (input) {
    var rows = document.querySelectorAll(input.getAttribute("data-filter-rows"));
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      rows.forEach(function (row) {
        row.hidden = q !== "" && (row.getAttribute("data-filter-text") || "").indexOf(q) === -1;
      });
    });
  });

  // Fix editor: file tabs, line numbers, indentation keys and unsaved-change markers. Without JS each file is a
  // plain textarea, stacked, and the form saves the same way.
  document.querySelectorAll("[data-editor]").forEach(function (form) {
    var tabs = Array.prototype.slice.call(form.querySelectorAll(".ed-tab"));
    var panels = Array.prototype.slice.call(form.querySelectorAll(".ed-file"));
    var submitting = false;
    form.classList.add("is-live");
    form.querySelector("[data-editor-tabs]").hidden = false;
    var keys = form.querySelector("[data-editor-keys]");
    if (keys) { keys.hidden = false; }

    function select(i, focus) {
      tabs.forEach(function (t, j) { t.setAttribute("aria-selected", String(i === j)); t.tabIndex = i === j ? 0 : -1; });
      panels.forEach(function (p, j) { p.hidden = i !== j; });
      if (focus) { tabs[i].focus(); }
    }
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () { select(i, false); });
      t.addEventListener("keydown", function (ev) {
        var step = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
        if (step) { ev.preventDefault(); select((i + step + tabs.length) % tabs.length, true); }
      });
    });
    select(0, false);

    function save() {
      submitting = true;
      if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
    }
    form.addEventListener("submit", function () { submitting = true; });
    window.addEventListener("beforeunload", function (ev) {
      if (!submitting && form.querySelector(".ed-tab.is-dirty")) { ev.preventDefault(); ev.returnValue = ""; }
    });

    // Replace a range through the editing pipeline so the browser's undo stack keeps working.
    function replace(text, start, end, value) {
      text.focus();
      text.setSelectionRange(start, end);
      if (!document.execCommand || !document.execCommand("insertText", false, value)) {
        text.setRangeText(value, start, end, "end");
        text.dispatchEvent(new Event("input"));
      }
    }

    panels.forEach(function (panel, i) {
      var text = panel.querySelector("textarea");
      var gutter = panel.querySelector(".ed-gutter");
      var original = text.value;
      var unit = /^\t/m.test(original) && !/^ {2}/m.test(original) ? "\t" : "    ";
      var two = original.match(/^ {2}(?! )\S/m);
      if (unit !== "\t" && two) { unit = "  "; }
      var lines = 0;
      var escaped = false;
      gutter.hidden = false;

      function number() {
        var n = text.value.split("\n").length;
        if (n !== lines) {
          var out = [];
          for (var k = 1; k <= n; k++) { out.push(k); }
          gutter.textContent = out.join("\n");
          lines = n;
        }
        gutter.scrollTop = text.scrollTop;
      }
      function mark() {
        var changed = text.value !== original;
        tabs[i].classList.toggle("is-dirty", changed);
        tabs[i].querySelector(".ed-dirty").hidden = !changed;
      }
      function indent(outdent) {
        var v = text.value, s = text.selectionStart, e = text.selectionEnd;
        if (!outdent && v.slice(s, e).indexOf("\n") === -1) { replace(text, s, e, unit); return; }
        var from = v.lastIndexOf("\n", s - 1) + 1;
        var to = e > s && v[e - 1] === "\n" ? e - 1 : e;
        var block = v.slice(from, to).split("\n").map(function (line) {
          if (!outdent) { return unit + line; }
          return line.indexOf(unit) === 0 ? line.slice(unit.length) : line.replace(/^[ \t]/, "");
        }).join("\n");
        replace(text, from, to, block);
        text.setSelectionRange(from, from + block.length);
      }

      text.addEventListener("input", function () { number(); mark(); });
      text.addEventListener("scroll", function () { gutter.scrollTop = text.scrollTop; });
      text.addEventListener("keydown", function (ev) {
        if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s") { ev.preventDefault(); save(); return; }
        if (ev.key === "Escape") { escaped = true; return; }
        if (ev.key === "Tab" && !escaped && !ev.ctrlKey && !ev.altKey && !ev.metaKey) {
          ev.preventDefault();
          indent(ev.shiftKey);
        } else if (ev.key === "Enter" && !ev.shiftKey && !ev.ctrlKey && !ev.altKey && !ev.metaKey && !ev.isComposing) {
          var v = text.value, s = text.selectionStart;
          var lead = v.slice(v.lastIndexOf("\n", s - 1) + 1, s).match(/^[ \t]*/)[0];
          ev.preventDefault();
          replace(text, s, text.selectionEnd, "\n" + lead);
        }
        escaped = false;
      });
      number();
    });
  });

  // "Select all" checkbox for finding tables.
  document.querySelectorAll("[data-select-all]").forEach(function (box) {
    box.addEventListener("change", function () {
      document.querySelectorAll(box.getAttribute("data-select-all")).forEach(function (c) { c.checked = box.checked; });
    });
  });
})();
