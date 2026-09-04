/* =========================================================================
   Chart interaction layer.

   No charting library: the charts are inline SVG rendered server-side, and
   this file adds the behaviour — hover tooltips, click-to-filter, count-up,
   reveal-on-scroll. Keeping the marks in SVG means they inherit the theme's
   CSS custom properties, so a theme toggle repaints every chart without a
   re-render and without a second palette to maintain.

   Every interactive element also carries its value in text somewhere on the
   page. The tooltip enriches; it is never the only way to read a number.
   ========================================================================= */

(function () {
  "use strict";

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------------------------
     Tooltip — one element, reused by every chart
     --------------------------------------------------------------------- */

  let tip;
  function ensureTip() {
    if (tip) return tip;
    tip = document.createElement("div");
    tip.className = "viz-tip";
    tip.setAttribute("role", "tooltip");
    tip.hidden = true;
    document.body.appendChild(tip);
    return tip;
  }

  function showTip(html, event) {
    const el = ensureTip();
    el.innerHTML = html;
    el.hidden = false;
    positionTip(event);
  }

  function positionTip(event) {
    if (!tip || tip.hidden) return;
    const pad = 14;
    const rect = tip.getBoundingClientRect();
    let x = event.clientX + pad;
    let y = event.clientY + pad;
    if (x + rect.width > window.innerWidth - 8) x = event.clientX - rect.width - pad;
    if (y + rect.height > window.innerHeight - 8) y = event.clientY - rect.height - pad;
    tip.style.left = Math.max(8, x) + "px";
    tip.style.top = Math.max(8, y) + "px";
  }

  function hideTip() {
    if (tip) tip.hidden = true;
  }

  /* Any element with data-tip becomes hoverable and keyboard-focusable. */
  function bindTips(root) {
    (root || document).querySelectorAll("[data-tip]:not([data-tip-bound])").forEach((el) => {
      el.setAttribute("data-tip-bound", "1");
      if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "0");
      const show = (e) => showTip(el.getAttribute("data-tip"), e);
      el.addEventListener("mouseenter", show);
      el.addEventListener("mousemove", positionTip);
      el.addEventListener("mouseleave", hideTip);
      el.addEventListener("focus", (e) => {
        const r = el.getBoundingClientRect();
        show({ clientX: r.left + r.width / 2, clientY: r.top });
      });
      el.addEventListener("blur", hideTip);
    });
  }

  /* ---------------------------------------------------------------------
     Animated number
     --------------------------------------------------------------------- */

  function countUp(el) {
    const target = parseFloat(el.dataset.count || "0");
    const decimals = parseInt(el.dataset.decimals || "0", 10);
    const prefix = el.dataset.prefix || "";
    const suffix = el.dataset.suffix || "";
    if (!isFinite(target)) { el.textContent = "—"; return; }

    const fmt = (v) =>
      prefix + v.toLocaleString(undefined, {
        minimumFractionDigits: decimals, maximumFractionDigits: decimals,
      }) + suffix;

    // Write the true value first. The animation is decoration; if rAF never
    // runs — headless capture, a background tab, a throttled device — the
    // number must still be correct rather than frozen at zero. A stuck "0"
    // beside "issues being exploited now" is worse than no animation at all.
    el.textContent = fmt(target);
    if (reduceMotion || typeof requestAnimationFrame !== "function") return;

    const start = performance.now();
    const dur = Math.min(1100, 380 + Math.abs(target) * 1.6);
    let finished = false;
    const finish = () => { if (!finished) { finished = true; el.textContent = fmt(target); } };

    requestAnimationFrame(function frame(now) {
      const p = Math.min((now - start) / dur, 1);
      if (finished) return;
      el.textContent = fmt(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(frame); else finish();
    });
    setTimeout(finish, dur + 400);  // belt and braces
  }

  /* ---------------------------------------------------------------------
     Reveal — bars and arcs grow into place when scrolled into view
     --------------------------------------------------------------------- */

  const revealObserver =
    "IntersectionObserver" in window
      ? new IntersectionObserver(
          (entries, obs) => {
            entries.forEach((entry) => {
              if (!entry.isIntersecting) return;
              reveal(entry.target);
              obs.unobserve(entry.target);
            });
          },
          { threshold: 0.15 }
        )
      : null;

  function reveal(el) {
    if (el.dataset.width) el.style.width = el.dataset.width;
    if (el.dataset.dash) el.setAttribute("stroke-dasharray", el.dataset.dash);
    if (el.dataset.height) {
      el.setAttribute("height", el.dataset.height);
      if (el.dataset.y) el.setAttribute("y", el.dataset.y);
    }
    if (el.dataset.counted === undefined && el.dataset.count !== undefined) {
      el.dataset.counted = "1";
      countUp(el);
    }
  }

  function bindReveals(root) {
    const sel = "[data-width]:not([data-revealed]), [data-dash]:not([data-revealed]), " +
                "[data-height]:not([data-revealed]), [data-count]:not([data-revealed])";
    (root || document).querySelectorAll(sel).forEach((el) => {
      el.setAttribute("data-revealed", "1");
      if (revealObserver && el.getBoundingClientRect) {
        revealObserver.observe(el);
        // If the element never intersects (print, headless capture, a
        // collapsed container) reveal it anyway rather than leaving a
        // zero-width bar that reads as "no data".
        setTimeout(() => reveal(el), 1800);
      } else {
        reveal(el);
      }
    });
  }

  /* ---------------------------------------------------------------------
     Cross-highlight — hovering a legend row dims the other marks
     --------------------------------------------------------------------- */

  function bindSeriesHighlight(root) {
    (root || document)
      .querySelectorAll("[data-series-group]:not([data-series-bound])")
      .forEach((group) => {
        group.setAttribute("data-series-bound", "1");
        group.querySelectorAll("[data-series]").forEach((el) => {
          const key = el.getAttribute("data-series");
          const set = (on) =>
            group.querySelectorAll("[data-series]").forEach((other) => {
              other.classList.toggle(
                "viz-dim",
                on && other.getAttribute("data-series") !== key
              );
            });
          el.addEventListener("mouseenter", () => set(true));
          el.addEventListener("mouseleave", () => set(false));
          el.addEventListener("focus", () => set(true));
          el.addEventListener("blur", () => set(false));
        });
      });
  }

  /* ---------------------------------------------------------------------
     Init
     --------------------------------------------------------------------- */

  function initAll(root) {
    bindTips(root);
    bindReveals(root);
    bindSeriesHighlight(root);
  }

  window.VizCharts = { init: initAll, showTip, hideTip };

  document.addEventListener("DOMContentLoaded", () => initAll(document));
  document.body &&
    document.body.addEventListener("htmx:afterSwap", (e) => initAll(e.target));
  window.addEventListener("scroll", hideTip, { passive: true });
})();
