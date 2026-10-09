// Audit progress polling. Elements with data-progress-url poll until the audit finishes, then reload.
(function () {
  // CSP forbids inline style attributes; bar widths are carried in data-width and applied here.
  document.querySelectorAll("[data-width]").forEach(function (el) {
    var w = parseFloat(el.getAttribute("data-width"));
    if (!isNaN(w)) { el.style.width = Math.max(0, Math.min(100, w)) + "%"; }
  });

  document.querySelectorAll("[data-progress-url]").forEach(function (el) {
    var url = el.getAttribute("data-progress-url");
    var bar = el.querySelector(".progress-bar");
    var label = el.querySelector("[data-stage]");
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

  // Confirmation for destructive buttons (inline handlers are blocked by CSP).
  document.querySelectorAll("[data-confirm]").forEach(function (btn) {
    btn.addEventListener("click", function (ev) {
      if (!window.confirm(btn.getAttribute("data-confirm"))) { ev.preventDefault(); }
    });
  });

  // "Select all" checkbox for finding tables.
  document.querySelectorAll("[data-select-all]").forEach(function (box) {
    box.addEventListener("change", function () {
      document.querySelectorAll(box.getAttribute("data-select-all")).forEach(function (c) { c.checked = box.checked; });
    });
  });
})();
