// The only script on the site. It adds three conveniences and nothing else:
// a light and dark switch, copy buttons on commands, and a rule under the
// header once the page scrolls. It makes no request and stores nothing but
// the theme you pick, in this browser.
(function () {
  "use strict";
  var root = document.documentElement;

  // Theme switch.
  var toggle = document.querySelector(".theme-toggle");
  function current() {
    var set = root.getAttribute("data-theme");
    if (set) return set;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function label() {
    if (!toggle) return;
    var next = current() === "dark" ? "light" : "dark";
    toggle.setAttribute("aria-label", "Switch to the " + next + " theme");
    toggle.setAttribute("title", "Switch to the " + next + " theme");
  }
  if (toggle) {
    label();
    toggle.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { window.localStorage.setItem("theme", next); } catch (e) { /* not kept */ }
      label();
    });
  }

  // Copy buttons. The prompt and any output lines are left out of the copy.
  var copyIcon =
    '<svg class="idle" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/><path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"/></svg>' +
    '<svg class="done" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7"/></svg>';
  var blocks = document.querySelectorAll(".code[data-copy] pre");
  Array.prototype.forEach.call(blocks, function (pre) {
    if (!navigator.clipboard) return;
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.setAttribute("aria-label", "Copy the command");
    button.innerHTML = copyIcon;
    button.addEventListener("click", function () {
      var clone = pre.cloneNode(true);
      Array.prototype.forEach.call(clone.querySelectorAll(".p, .o, .c"), function (node) {
        node.parentNode.removeChild(node);
      });
      var text = clone.textContent
        .split("\n")
        .map(function (line) { return line.replace(/\s+$/, ""); })
        .filter(function (line) { return line.length > 0; })
        .join("\n");
      navigator.clipboard.writeText(text).then(function () {
        button.classList.add("copied");
        button.setAttribute("aria-label", "Copied");
        window.setTimeout(function () {
          button.classList.remove("copied");
          button.setAttribute("aria-label", "Copy the command");
        }, 1600);
      });
    });
    pre.parentNode.appendChild(button);
  });

  // A rule under the header once the page has scrolled.
  var header = document.querySelector(".site-header");
  if (header && !header.classList.contains("solid")) {
    var onScroll = function () { header.classList.toggle("scrolled", window.scrollY > 8); };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }
})();
