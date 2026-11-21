// Runs before the page paints: applies a theme the visitor chose earlier on
// this site, if any, so the page does not flash in the other one. Without a
// choice, or without script, the page follows the system setting.
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  try {
    var theme = window.localStorage.getItem("theme");
    if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
  } catch (e) {
    // Storage can be blocked; the system setting applies.
  }
})();
