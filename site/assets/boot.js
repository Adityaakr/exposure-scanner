// Runs before the page paints. It marks the page as one with script, and as
// one that welcomes motion unless the visitor asked for less, so the
// stylesheet can hold back the text that site.js is about to type. Without
// script, or with reduced motion, every word is simply there.
//
// It also applies the theme the visitor picked with the switch, if they
// picked one, so the page does not flash the other theme first. Without a
// choice the stylesheet follows the system's light or dark setting.
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduce) root.classList.add("motion");

  var theme = null;
  try {
    theme = window.localStorage.getItem("exposure-theme");
  } catch (e) {
    theme = null;
  }
  if (theme === "light" || theme === "dark") {
    root.setAttribute("data-theme", theme);
    var colour = theme === "light" ? "#eef2ef" : "#020403";
    Array.prototype.forEach.call(document.querySelectorAll('meta[name="theme-color"]'), function (meta) {
      meta.setAttribute("content", colour);
    });
  }
})();
