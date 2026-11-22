// The site's conveniences, and nothing else: copy buttons on commands, a
// guess at the visitor's system for the steps, headings and commands typed
// out as they come into view, and figures that settle in. It makes no
// request and stores nothing. Typing and playback run only when boot.js
// found that motion is welcome; otherwise the page stays as it was written.
(function () {
  "use strict";
  var root = document.documentElement;
  var motion = root.classList.contains("motion");
  var each = function (list, fn) { Array.prototype.forEach.call(list, fn); };

  // Copy buttons. The prompt and any output lines are left out of the copy.
  var copyIcon =
    '<svg class="idle" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="5.5" y="5.5" width="8" height="8" rx="1"/><path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"/></svg>' +
    '<svg class="done" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7"/></svg>';
  // A command that does not work yet gets no button, whatever its markup says.
  if (navigator.clipboard) {
    each(document.querySelectorAll(".code[data-copy]:not(.is-planned) pre"), function (pre) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "copy";
      button.setAttribute("aria-label", "Copy the command");
      button.innerHTML = copyIcon;
      button.addEventListener("click", function () {
        var clone = pre.cloneNode(true);
        each(clone.querySelectorAll(".p, .o, .c"), function (node) {
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
  }

  // The steps open on the visitor's own system when it can be told, and on
  // macOS otherwise. The choice is the radio button's; this only sets it.
  (function () {
    var ua = navigator.userAgent || "";
    var platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    var system = null;
    if (/android/i.test(platform) || /android/i.test(ua)) system = "android";
    else if (/^win|windows/i.test(platform) || /windows/i.test(ua)) system = "windows";
    else if (/mac|iphone|ipad|ipod/i.test(platform) || /mac os x|iphone|ipad/i.test(ua)) system = "mac";
    else if (/linux|x11|cros/i.test(platform) || /linux|cros/i.test(ua)) system = "linux";
    var input = system && document.getElementById("os-" + system);
    if (input && !document.querySelector(".os-opts input:checked:not([data-default])")) input.checked = true;
  })();

  // Everything below moves, so it runs only when motion is welcome.
  if (!motion) {
    each(document.querySelectorAll(".reveal"), function (node) { node.classList.add("is-in"); });
    return;
  }

  var later = function (fn, ms) { window.setTimeout(fn, ms); };

  // Types the text of `target` over itself, inside the block `host`. The
  // overlay holds the whole text, the untyped rest kept transparent, so the
  // lines break where they will end up; the original text stays underneath,
  // transparent, and is what assistive technology reads.
  function typeOver(host, target, speed, done) {
    var wrapped = null;
    if (host === target) {
      // The overlay goes inside the host, so the text it covers moves into
      // a span of its own for the time of the typing.
      wrapped = document.createElement("span");
      while (host.firstChild) wrapped.appendChild(host.firstChild);
      host.appendChild(wrapped);
      target = wrapped;
    }
    var full = target.textContent;
    var before = "";
    if (!wrapped) {
      var range = document.createRange();
      range.setStart(host, 0);
      range.setEndBefore(target);
      before = range.toString();
    }
    var overlay = document.createElement("span");
    overlay.className = "typed";
    overlay.setAttribute("aria-hidden", "true");
    var spacer = document.createElement("span");
    spacer.className = "spacer";
    spacer.textContent = before;
    var shown = document.createElement("span");
    var caret = document.createElement("span");
    caret.className = "caret";
    var rest = document.createElement("span");
    rest.className = "rest";
    rest.textContent = full;
    overlay.appendChild(spacer);
    overlay.appendChild(shown);
    overlay.appendChild(caret);
    overlay.appendChild(rest);
    host.classList.add("typing-host");
    target.classList.add("ghosted");
    host.appendChild(overlay);

    var i = 0;
    (function next() {
      i += 1;
      shown.textContent = full.slice(0, i);
      rest.textContent = full.slice(i);
      if (i < full.length) {
        var ch = full.charAt(i - 1);
        later(next, speed + (ch === " " ? speed : 0) + (/[.,:]/.test(ch) ? speed * 4 : 0));
      } else {
        later(function () {
          host.removeChild(overlay);
          host.classList.remove("typing-host");
          target.classList.remove("ghosted");
          if (wrapped) {
            while (wrapped.firstChild) host.insertBefore(wrapped.firstChild, wrapped);
            host.removeChild(wrapped);
          }
          if (done) done();
        }, 260);
      }
    })();
  }

  function typeHeading(el, speed, done) {
    el.classList.add("is-typing");
    typeOver(el, el, speed, function () {
      el.classList.remove("is-typing");
      el.classList.add("is-typed");
      if (done) done();
    });
  }

  // A terminal plays back: the lines before the command, the command typed,
  // then its output a line at a time.
  function play(term, done) {
    var lines = term.querySelectorAll("pre.lines .ln");
    var cmd = term.querySelector(".cmd");
    var line = cmd ? cmd.closest(".ln") : null;
    var after = false;
    each(lines, function (ln) {
      if (after) ln.classList.add("wait");
      if (ln === line) after = true;
    });
    term.classList.add("is-playing");
    var waiting = term.querySelectorAll(".ln.wait");
    var n = 0;
    function output() {
      if (n >= waiting.length) {
        term.classList.remove("is-playing");
        term.classList.add("is-played");
        if (done) done();
        return;
      }
      waiting[n].classList.remove("wait");
      n += 1;
      later(output, n === 1 ? 320 : 38);
    }
    if (cmd && line) typeOver(line, cmd, 34, function () { later(output, 120); });
    else output();
  }

  var watch = function (nodes, start, margin) {
    if (!("IntersectionObserver" in window)) {
      each(nodes, start);
      return;
    }
    var watcher = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          watcher.unobserve(entry.target);
          start(entry.target);
        }
      });
    }, { rootMargin: margin || "0px 0px -15% 0px", threshold: 0 });
    each(nodes, function (node) { watcher.observe(node); });
  };

  // Arm everything first: from here the script shows them, not the timer
  // in the stylesheet.
  var headings = document.querySelectorAll("[data-type]");
  var terms = document.querySelectorAll("[data-play]");
  each(headings, function (el) { el.classList.add("is-armed"); });
  each(terms, function (el) { el.classList.add("is-armed"); });

  // The first heading types at once; the hero's terminal waits for it.
  var first = document.querySelector("h1[data-type]");
  var heroTerm = document.querySelector(".hero [data-play]");
  var rest = Array.prototype.filter.call(terms, function (t) { return t !== heroTerm; });
  if (first) {
    later(function () {
      typeHeading(first, 42, function () { if (heroTerm) watch([heroTerm], function (t) { play(t); }); });
    }, 250);
  } else if (heroTerm) {
    watch([heroTerm], function (t) { play(t); });
  }
  watch(Array.prototype.filter.call(headings, function (h) { return h !== first; }), function (h) {
    typeHeading(h, 16);
  });
  watch(rest, function (t) { play(t); });

  // Figures settle in once, the first time they come into view.
  watch(document.querySelectorAll(".reveal"), function (node) { node.classList.add("is-in"); }, "0px 0px -10% 0px");
})();
