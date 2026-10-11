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

  // Running log: times are rendered in UTC by the server; show them in the viewer's time zone.
  function localTime(iso) {
    var d = new Date(iso.indexOf("Z") === -1 && iso.indexOf("+") === -1 ? iso + "Z" : iso);
    return isNaN(d) ? iso.slice(11, 19) : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  document.querySelectorAll("[data-audit-log-items] time[datetime]").forEach(function (t) {
    t.textContent = localTime(t.getAttribute("datetime"));
  });

  // Mirrors log_kind / log_icons in templates/audits/detail.html.
  var LOG_KINDS = [["fetching", "fetch", "cloud-arrow-down"], ["inspecting", "inspect", "search"],
    ["detecting", "lang", "code-slash"], ["analyzing", "scan", "shield-check"], ["validating", "dedupe", "funnel"],
    ["scoring", "score", "speedometer2"], ["AI", "ai", "stars"], ["saving", "save", "floppy"]];
  function logKind(stage) {
    for (var i = 0; i < LOG_KINDS.length; i++) {
      if (stage.indexOf(LOG_KINDS[i][0]) === 0) { return LOG_KINDS[i]; }
    }
    return [null, "misc", "dot"];
  }
  var REDUCED_MOTION = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var MAX_LOG_ITEMS = 600;

  document.querySelectorAll("[data-progress-url]").forEach(function (el) {
    var url = el.getAttribute("data-progress-url");
    var bar = el.querySelector(".progress-bar");
    var label = el.querySelector("[data-stage]");
    var pct = el.querySelector("[data-progress-pct]");
    var details = el.querySelector("[data-audit-log]");
    var log = el.querySelector("[data-audit-log-items]");
    var now = el.querySelector("[data-log-now]");
    var lastSeq = 0;
    if (log) {
      log.querySelectorAll("[data-seq]").forEach(function (li) {
        lastSeq = Math.max(lastSeq, parseInt(li.getAttribute("data-seq"), 10) || 0);
      });
      log.scrollTop = log.scrollHeight;
    }
    var queue = [];
    var dripping = false;
    var finished = null;

    function span(cls, text) {
      var s = document.createElement("span");
      s.className = cls;
      s.textContent = text;
      return s;
    }
    function icon(name) {
      var i = document.createElement("i");
      i.className = "bi bi-" + name;
      i.setAttribute("aria-hidden", "true");
      return i;
    }

    function render(e) {
      var kind = logKind(e.stage);
      var li = document.createElement("li");
      li.setAttribute("data-seq", e.seq);
      var time = document.createElement("time");
      time.setAttribute("datetime", e.t);
      time.textContent = localTime(e.t);
      li.appendChild(time);
      if (e.msg) {
        li.className = "alog-item alog-" + kind[1] + (e.level ? " is-" + e.level : "") + (REDUCED_MOTION ? "" : " is-new");
        var step = e.step === null || e.step === undefined ? "" : ("  " + e.step).slice(-3) + "%";
        li.appendChild(span("alog-step", step));
        if (e.path) {
          li.appendChild(icon(kind[2]));
          li.appendChild(span("alog-path", e.path));
        }
        li.appendChild(span("alog-msg", e.msg));
      } else {
        li.className = "alog-stage alog-" + kind[1];
        li.appendChild(icon(kind[2]));
        var b = document.createElement("b");
        b.textContent = e.stage;
        li.appendChild(b);
        li.appendChild(span("alog-pct", e.pct + "%"));
      }
      return li;
    }

    function showNow(e) {
      if (!now) { return; }
      var kind = logKind(e.stage);
      now.className = "alog-now is-" + kind[1];
      now.querySelector("[data-log-now-icon]").className = "bi bi-" + kind[2] + " alog-now-icon";
      now.querySelector("[data-log-now-stage]").textContent = e.stage;
      var hasStep = e.step !== null && e.step !== undefined;
      var stageBar = now.querySelector("[data-log-now-bar]");
      if (hasStep) { stageBar.style.width = e.step + "%"; } else if (!e.msg) { stageBar.style.width = "0%"; }
      now.classList.toggle("is-busy", !hasStep && !!e.msg);  // analyzers: file count known, total not
      now.querySelector("[data-log-now-pct]").textContent = hasStep ? e.step + "%" : "";
      var path = now.querySelector("[data-log-now-path]");
      if (e.path || !e.msg) {
        path.textContent = e.path || "";
        if (!REDUCED_MOTION && e.path) {  // restart the lens animation for each file
          path.classList.remove("is-new");
          void path.offsetWidth;
          path.classList.add("is-new");
        }
      }
    }

    function append(e) {
      if (!log) { return; }
      var stick = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
      if (e.seq > lastSeq + 1 && lastSeq > 0) {
        var gap = document.createElement("li");
        gap.className = "alog-gap";
        gap.textContent = "… " + (e.seq - lastSeq - 1) + " more lines";
        log.appendChild(gap);
      }
      lastSeq = e.seq;
      log.appendChild(render(e));
      while (log.children.length > MAX_LOG_ITEMS) { log.removeChild(log.firstChild); }
      if (stick && details && details.open) { log.scrollTop = log.scrollHeight; }
      showNow(e);
    }

    // Reveal queued lines one by one across the polling interval so the log reads file by file.
    function drip() {
      if (!queue.length) {
        dripping = false;
        if (finished) { window.location.reload(); }
        return;
      }
      dripping = true;
      append(queue.shift());
      setTimeout(drip, REDUCED_MOTION ? 0 : Math.max(8, Math.min(140, 1800 / (queue.length + 1))));
    }

    function tick() {
      fetch(url + "?after=" + lastSeqQueued(), { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) { setTimeout(tick, 5000); return; }
          if (bar) { bar.style.width = data.progress + "%"; bar.textContent = data.progress + "%"; }
          if (label) { label.textContent = data.stage; }
          if (pct) { pct.textContent = data.progress + "%"; }
          (data.log || []).forEach(function (e) { queue.push(e); });
          if (["succeeded", "failed", "cancelled"].indexOf(data.status) !== -1) {
            finished = data.status;
            if (!dripping) { drip(); }
            setTimeout(function () { window.location.reload(); }, 4000);  // don't wait on a long backlog
          } else {
            if (!dripping) { drip(); }
            setTimeout(tick, 2000);
          }
        })
        .catch(function () { setTimeout(tick, 5000); });
    }
    function lastSeqQueued() {
      return queue.length ? queue[queue.length - 1].seq : lastSeq;
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
