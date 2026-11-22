// Runs before the page paints. It marks the page as one with script, and as
// one that welcomes motion unless the visitor asked for less, so the
// stylesheet can hold back the text that site.js is about to type. Without
// script, or with reduced motion, every word is simply there.
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduce) root.classList.add("motion");
})();
