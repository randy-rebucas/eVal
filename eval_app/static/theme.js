// Loaded synchronously in <head> so the stored theme applies before first paint (CSP blocks inline scripts).
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  try {
    var saved = localStorage.getItem("eval-theme");
    if (saved === "light" || saved === "dark") { root.setAttribute("data-bs-theme", saved); }
  } catch (e) { /* storage blocked: keep the server default */ }
})();
