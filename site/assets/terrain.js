// Draws the wireframe terrain behind the page: a grid of lines laid over
// hills that roll slowly toward the viewer, with a flat valley down the
// middle, under the column of text. It is a few sine waves drawn on a
// canvas; nothing is loaded. A visitor who asks for reduced motion gets one
// still frame, and without script the page has only its dotted backdrop.
// The lines take their colour and strength from the stylesheet (--terrain
// and --terrain-strength), so the light theme draws them deeper and fainter.
(function () {
  "use strict";
  var canvas = document.getElementById("terrain");
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext("2d");
  if (!ctx) return;
  var query = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

  var COLS = 60;      // lines across, half on each side of the middle
  var ROWS = 46;      // lines into the distance
  var DEPTH = 46;     // how far the grid reaches, in grid units
  var NEAR = 0.9;     // the nearest row, in grid units from the eye
  var SPEED = 1.4;    // grid units per second
  var EYE = 2.3;      // the eye's height above the valley floor
  var width = 0;
  var height = 0;
  var rgb = "61, 255, 140";
  var strength = 1;

  // The theme's colour for the lines, read again when the theme changes.
  function colours() {
    var style = window.getComputedStyle(document.documentElement);
    var parts = style.getPropertyValue("--terrain").trim().split(/[\s,]+/);
    if (parts.length === 3) rgb = parts.join(", ");
    var s = parseFloat(style.getPropertyValue("--terrain-strength"));
    strength = isFinite(s) ? Math.max(0, Math.min(1, s)) : 1;
  }
  function rgba(alpha) {
    return "rgba(" + rgb + ", " + (alpha * strength).toFixed(3) + ")";
  }

  function resize() {
    var ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  // The height of the ground at (x, z): flat in the valley, hills from
  // about seven units out on either side.
  function ground(x, z) {
    var side = Math.min(1, (x * x) / 49);
    var hills =
      Math.sin(x * 0.38 + z * 0.17) * 1.1 +
      Math.sin(x * 0.11 - z * 0.29 + 1.3) * 1.6 +
      Math.sin((x + z) * 0.53 + 0.4) * 0.45 +
      Math.cos(z * 0.09 - x * 0.07) * 0.9;
    return Math.max(0, hills + 2.2) * side * 1.7;
  }

  function draw(seconds) {
    var travel = seconds * SPEED;
    var step = DEPTH / ROWS;
    var shift = travel % step;
    var horizon = height * 0.5;
    var focal = Math.max(width, height) * 0.6;
    var half = COLS / 2;
    var xs = [];
    var ys = [];
    var r;
    var c;

    for (r = 0; r <= ROWS; r++) {
      // Nearest row first; each row slides toward the eye as we travel.
      var z = NEAR + (r + 1) * step - shift;
      var world = z + travel;
      var rowX = [];
      var rowY = [];
      for (c = 0; c <= COLS; c++) {
        var x = c - half;
        rowX.push(width / 2 + (x * focal) / z);
        rowY.push(horizon + ((EYE - ground(x, world)) * focal) / z);
      }
      xs.push(rowX);
      ys.push(rowY);
    }

    ctx.clearRect(0, 0, width, height);

    // A faint glow along the horizon.
    var glow = ctx.createLinearGradient(0, horizon - height * 0.18, 0, horizon + height * 0.06);
    glow.addColorStop(0, rgba(0));
    glow.addColorStop(0.75, rgba(0.05));
    glow.addColorStop(1, rgba(0));
    ctx.fillStyle = glow;
    ctx.fillRect(0, horizon - height * 0.18, width, height * 0.24);

    // The grid fades out into the distance, toward the horizon.
    var fade = ctx.createLinearGradient(0, horizon - height * 0.12, 0, height);
    fade.addColorStop(0, rgba(0));
    fade.addColorStop(0.22, rgba(0.16));
    fade.addColorStop(1, rgba(0.5));
    ctx.strokeStyle = fade;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (r = 0; r <= ROWS; r++) {
      ctx.moveTo(xs[r][0], ys[r][0]);
      for (c = 1; c <= COLS; c++) ctx.lineTo(xs[r][c], ys[r][c]);
    }
    for (c = 0; c <= COLS; c++) {
      ctx.moveTo(xs[0][c], ys[0][c]);
      for (r = 1; r <= ROWS; r++) ctx.lineTo(xs[r][c], ys[r][c]);
    }
    ctx.stroke();
  }

  var frame = 0;
  var start = null;
  var last = 0;
  function tick(now) {
    frame = window.requestAnimationFrame(tick);
    if (now - last < 1000 / 30) return;
    last = now;
    if (start === null) start = now;
    draw((now - start) / 1000);
  }
  function still() { return query && query.matches; }
  function run() {
    window.cancelAnimationFrame(frame);
    if (still()) draw(6);
    else frame = window.requestAnimationFrame(tick);
  }

  // A new theme, picked with the switch or set by the system: new colours,
  // and the still frame drawn again in them.
  function recolour() {
    colours();
    if (still()) draw(6);
  }

  colours();
  resize();
  run();
  window.addEventListener("resize", function () {
    resize();
    if (still()) draw(6);
  });
  if (query) {
    if (query.addEventListener) query.addEventListener("change", run);
    else if (query.addListener) query.addListener(run);
  }
  var scheme = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  if (scheme) {
    if (scheme.addEventListener) scheme.addEventListener("change", recolour);
    else if (scheme.addListener) scheme.addListener(recolour);
  }
  if (window.MutationObserver) {
    new MutationObserver(recolour).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  }
})();
