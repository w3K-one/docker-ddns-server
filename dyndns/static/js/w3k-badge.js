/**
 * w3k-badge.js — the w3K "secret hotkey badge", one canonical reusable build.
 * ---------------------------------------------------------------------------
 * Hold SHIFT+ALT (Shift+Option on Mac) anywhere on the page and a small
 * circular 3K badge fades in, fixed bottom-right, 10px inset. It is an
 * <a> to https://w3K.one that opens in a new tab; its tooltip picks a fresh
 * w3K one-liner every time you hover in. Release the combo — or the window
 * loses focus — and it disappears. That's the whole thing.
 *
 * SELF-CONTAINED: the 3K mark is inlined as raw minified SVG markup (not
 * base64 — that would inflate it ~33%). Nothing to copy alongside this file
 * — no image asset, no CSS, no dependencies. This file has zero imports, so
 * it works identically as a bare browser-loaded module or inside any
 * bundler — nothing to break either way.
 *
 * It is an ES module. Modern <script type="module"> covers every browser,
 * so there is no separate "classic script" build to keep in sync.
 *
 * React project? Don't import this file's exports directly from React code
 * — use the small wrapper in ./w3k-badge-react.js instead (it does
 * `import { initW3kBadge } from './w3k-badge.js'` under the hood). Keeping
 * the React dependency in a separate file means THIS file can stay
 * dependency-free and usable from a plain <script type="module"> with no
 * bundler and no import map — a static top-level `import ... from 'react'`
 * right here would make the whole file fail to load in that case, even for
 * callers who never touch React at all (confirmed by testing it directly:
 * a bare <script type="module" src="w3k-badge.js" data-auto> throws
 * "Failed to resolve module specifier react" and nothing loads, since a
 * browser resolves every static import at parse time regardless of which
 * exports actually get used — 2026-09-07).
 *
 * ===========================================================================
 *  INSTALL — pick the line that matches the project. Nothing else to do.
 * ===========================================================================
 *
 *  1. Any HTML page — one tag, auto-runs on load, no JS to write:
 *
 *       <script type="module" src="w3k-badge.js" data-auto></script>
 *
 *  2. Bundler / app entry (Vite, webpack, plain module):
 *
 *       import { initW3kBadge } from './w3k-badge.js';
 *       initW3kBadge();
 *
 *  3. React — use the wrapper file instead of importing from here directly:
 *
 *       import { W3kBadge } from './w3k-badge-react.js';
 *       <W3kBadge />
 *
 * ===========================================================================
 *  OPTIONS (all optional) — initW3kBadge(opts) / <W3kBadge {...opts} />
 * ===========================================================================
 *   iconUrl   string   override the embedded mark with your own image URL
 *   targetUrl string   link target            (default 'https://w3K.one')
 *   size      number   badge diameter px      (default 40)
 *   inset     string   distance from corner   (default '10px')
 *   corner    string   'bottom-right' (default) | 'bottom-left'
 *                      | 'top-right' | 'top-left'
 *   modifiers string[] key flags that must ALL be held, from
 *                      'shiftKey' 'altKey' 'ctrlKey' 'metaKey'
 *                      (default ['shiftKey','altKey'] — never ctrl+alt, it
 *                       collides with macOS right-click emulation)
 *   titles    string[] | string  tooltip pool, re-randomised per hover
 *   onReveal  fn()     called each time the badge appears — use this for the
 *                      "force-trigger a hidden thing while held" variant
 *   onHide    fn()     called each time it disappears
 *
 *   initW3kBadge(opts) returns teardown() — removes listeners + any live badge.
 *
 * Provenance: w3K signature Easter egg. The Ctrl+Alt→Shift+Alt fix and the
 * per-hover tooltip pool were worked out in the xFer project (2026-09-07);
 * consolidated into this single self-contained file 2026-09-07 so it never
 * has to be rebuilt per project again.
 */

// --- the 3K mark, inlined as raw SVG markup ---
//
// Single flat path extracted from the w3K icon font
// (w3KxPress/Plugins/w3K/assets/w3K.svg, glyph "3K" U+E900) and kept in
// Snippets-and-Scripts/SVG/w3K-marks/3K.svg.
//
// This replaced a 21 KB / 55-path greyscale RENDERING of the same mark
// (2026-10-02). The flat version is 4.7 KB — 78% smaller — and, more
// usefully, it is `fill="currentColor"`, so the badge tints it instead of
// carrying baked-in greys. At the real badge size (~31px) the rendered
// version's mid-greys muddied together; this one stays crisp and inverts
// correctly on both light and dark pills.
//
// The transform is required, not decorative: SVG fonts are Y-up with the
// baseline at 0, so the glyph is upside down in normal SVG space.
// translate(0,960) scale(1,-1) flips it back — 960 is the font's ascent
// (units-per-em 1024). Without it the markup is still valid SVG of the
// expected size and simply renders inverted and out of frame.
// (NOT base64 — base64 would inflate it ~33%. When a project passes
//  its own `iconUrl`, this is ignored and an <img> is used instead.)
const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024"><g transform="translate(0,960) scale(1,-1)"><path fill="currentColor" d="M465.988 919.006c63.932 8.772 129.399 1.263 190.891-17.545 82.483-29.423 154.914-83.866 209.852-151.671 5.769-5.513 5.734-13.943 4.779-21.316-1.724-9.882-4.164-19.627-6.434-29.389 23.962-10.581 48.623-23.671 63.198-46.319 35.618-67.618 52.275-143.735 57.19-219.614 2.884-17.22-11.23-30.071-19.712-43.315 11.827-19.917 10.769-44.732 5.837-66.662-12.373-46.729-33.007-91.238-60.194-131.209-66.116-99.004-170.001-171.401-285.082-201.233-79.94-20.156-164.847-24.201-245.146-3.686 62.635 21.197 126.515 38.741 188.45 62.054 65.417 24.183 131.243 48.947 190.993 85.436 69.376 43.52 135.834 98.185 174.438 171.895 9.591 23.484 24.183 45.909 22.699 72.414-16.93-15.991-29.833-35.652-46.746-51.661-102.519-107.366-233.011-184.525-370.159-239.104-58.419-23.996-119.159-41.54-179.063-61.269-21.367-5.615-45.244-11.162-66.406-1.809-27.887 11.998-53.402 28.86-77.943 46.541-23.723 18.739-47.701 37.444-68.454 59.494-4.233 4.813-9.216 11.503-5.513 18.057 14.473 30.379 39.049 54.255 61.474 78.797-29.594-3.652-58.846-11.469-88.849-10.223-16.247 2.731-33.041 7.885-45.21 19.558-11.861 16.708-15.957 37.376-21.982 56.627-4.13 17.988-10.411 35.925-9.933 54.562 10.428 40.107 25.31 79.599 48.077 114.432-11.247-0.222-22.972-1.929-33.673 2.577-11.366 9.421-16.555 24.969-14.575 39.407 17.92 105.574 66.799 206.336 141.619 283.29 17.903 18.347 39.287 32.734 60.297 47.189 66.953 45.38 144.657 75.349 225.28 83.695zM196.83 787.046c-43.281-41.66-83.831-89.19-104.448-146.449-4.523-9.847 5.598-19.644 15.155-20.139 31.283-1.331 60.058 12.134 89.207 21.248 7.509 2.628 15.258 4.813 22.153 8.892 23.245 13.090 47.889 23.433 71.27 36.284 49.527 25.054 96.137 55.381 141.756 86.886 16.811 11.469 32.734 24.166 48.521 36.983-5.871 8.38-13.551 15.309-19.251 23.808 32.256 5.444 64.819 8.977 97.126 14.165 26.061 3.362 51.917 8.533 78.182 10.223-0.87-24.098-7.919-47.377-10.121-71.339-5.308-34.611-10.377-69.342-17.698-103.595-8.738 6.212-16.418 13.909-25.702 19.302-3.857 1.946-7.492-1.417-10.394-3.584-20.207-18.381-44.254-31.71-65.417-48.896-115.132-82.569-243.9-148.924-382.583-180.821-14.37-2.645-22.716-16.521-30.293-27.546-10.974-19.575-20.873-41.079-21.897-63.829 2.816-9.728 15.223-10.581 23.364-12.151 39.953-1.98 80.606 1.109 119.245 11.844 35.789 11.878 70.417 27.187 103.953 44.373 63.659 34.185 126.447 69.973 188.928 106.257 47.343 29.15 92.041 62.993 130.884 102.878 26.846 26.897 54.221 54.204 73.233 87.433 16.213 17.818 29.713 37.871 41.95 58.59 8.738 15.718 13.278 34.748 9.028 52.514-6.485 11.844-18.586 19.319-29.116 27.204-50.569 35.721-112.896 48.384-173.278 55.62-132.233 14.746-267.742-35.191-363.759-126.157zM860.194 681.933c-29.303-65.57-69.12-126.43-118.101-179.012-24.951-28.57-54.221-52.855-83.098-77.312-16.128-12.561-33.178-23.91-50.347-34.987-38.485-23.467-80.367-40.448-120.866-60.023-48.367-23.245-96.802-46.473-146.466-66.884-18.415-7.236-36.813-14.848-56.286-18.893-19.541-5.257-39.765-8.038-58.931-14.592-9.114-7.919-16.606-17.442-24.525-26.505-12.544-14.899-26.061-29.508-34.202-47.445 17.203-7.083 35.977-9.626 54.494-8.789 38.093 0.99 76.851 2.099 113.715 12.766 72.789 20.173 142.814 49.766 208.845 86.374 81.015 45.158 158.498 96.751 230.878 154.812 14.251 11.281 26.351 25.020 41.062 35.755 25.549 22.033 50.091 45.431 71.987 71.117 11.759 18.995 23.245 38.434 31.283 59.341 7.953 23.518 9.216 51.712-5.035 73.079-11.571 20.634-32.495 33.775-54.409 41.199zM817.408 908.868c7.202 10.325 21.231 10.394 32.461 10.394 11.878 0.222 23.825 0.546 35.669-0.683 7.27-1.161 11.059-7.834 14.37-13.602 4.369 9.131 13.619 18.176 24.61 13.636 7.919-5.922 5.359-17.766 8.226-26.368 12.049 8.892 19.337 28.006 36.71 26.931 7.509 2.543 13.244-2.543 18.603-6.537-7.936-11.435-16.179-22.784-26.214-32.478-5.325-0.085-9.353 4.062-13.807 6.349 8.55-16.555 22.221-29.474 33.536-44.049 4.642-6.144 4.42-14.234 5.905-21.504-6.622-1.417-14.268-6.656-20.702-1.997-12.356 8.090-20.565 20.838-30.14 31.795-1.775-0.222-3.533-0.427-5.274-0.649-0.307-12.732 0.222-29.065-15.189-33.553-11.401-4.454-16.367 5.205-15.479 14.797-4.011-5.7-8.789-11.162-15.206-14.234-16.725-1.314-33.553-1.178-50.227 0.324-12.681 1.058-21.879 12.766-25.412 24.149-1.399 4.813 0.119 11.895 5.82 12.902 7.885 3.072 15.701-1.382 22.733-4.574 8.738-4.983 19.115-3.482 28.809-3.823-4.13 6.468-9.643 12.117-12.919 19.098 0.085 9.779 8.243 16.503 12.22 24.866-8.789-0.751-18.227 1.451-26.539-2.304-8.943-4.045-18.449-6.844-28.228-7.902-3.447 10.018-2.236 21.111 5.666 29.013zM881.783 867.721c5.888-8.465 12.442-16.452 19.115-24.32 0.29 16.828 0.171 33.655-0.051 50.483-6.366-8.721-12.766-17.408-19.063-26.163z"/></g></svg>`;

const DEFAULT_TITLES = [
  'Another site created, designed and developed by w3K',
  'Powered by w3K',
  'w3K was here',
  'Crafted by w3K',
  'Built with w3K precision',
  'Yet another w3K original',
];

const CORNERS = {
  'bottom-right': (i) => ({ bottom: i, right: i }),
  'bottom-left':  (i) => ({ bottom: i, left: i }),
  'top-right':    (i) => ({ top: i, right: i }),
  'top-left':     (i) => ({ top: i, left: i }),
};

export function initW3kBadge(opts = {}) {
  const targetUrl = opts.targetUrl || 'https://w3K.one';
  const size      = opts.size || 40;
  const inset     = opts.inset || '10px';
  const corner    = CORNERS[opts.corner] ? opts.corner : 'bottom-right';
  const modifiers = opts.modifiers && opts.modifiers.length ? opts.modifiers : ['shiftKey', 'altKey'];
  const pool      = Array.isArray(opts.titles) ? opts.titles
                  : (typeof opts.titles === 'string' ? [opts.titles] : DEFAULT_TITLES);
  // The inlined mark is fill="currentColor", so the badge must set a colour.
  // Without this it inherits from the <a> and renders in the browser's
  // default link blue — which is exactly what happened the first time, and
  // is invisible in any test that only checks the icon is present.
  const iconColor = opts.iconColor || '#11151d';
  const onReveal  = typeof opts.onReveal === 'function' ? opts.onReveal : null;
  const onHide    = typeof opts.onHide === 'function' ? opts.onHide : null;

  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return () => {}; // SSR / non-DOM: no-op, safe to import anywhere
  }

  const rnd  = () => pool[Math.floor(Math.random() * pool.length)];
  const held = (e) => modifiers.every((m) => e[m]);

  let badge = null;

  // inject the reveal keyframes once (id-guarded so repeated inits are cheap)
  function ensureKeyframes() {
    if (document.getElementById('w3k-badge-kf')) return;
    const st = document.createElement('style');
    st.id = 'w3k-badge-kf';
    st.textContent =
      '@keyframes w3kBadgeIn{from{opacity:0;transform:scale(.85)}to{opacity:1;transform:none}}';
    document.head.appendChild(st);
  }

  function show() {
    if (badge) return;
    badge = document.createElement('a');
    badge.href = targetUrl;
    badge.target = '_blank';
    badge.rel = 'noopener noreferrer';
    badge.setAttribute('aria-label', 'w3K');
    badge.title = rnd();
    badge.addEventListener('mouseenter', () => { badge.title = rnd(); });

    const s = badge.style;
    s.position = 'fixed';
    s.width = s.height = size + 'px';
    s.borderRadius = '9999px';
    s.border = '2px solid #19b4ff';
    s.background = '#fff';
    s.color = iconColor;          // drives the inlined mark's currentColor
    s.boxShadow = '0 4px 12px rgba(0,0,0,.25)';
    s.display = 'flex';
    s.alignItems = s.justifyContent = 'center';
    s.padding = '0';
    s.cursor = 'pointer';
    s.zIndex = '2147483647';
    s.animation = 'w3kBadgeIn .12s ease-out both';
    const pos = CORNERS[corner](inset);
    for (const k in pos) s[k] = pos[k];

    if (opts.iconUrl) {
      // caller supplied their own image URL
      const img = document.createElement('img');
      img.src = opts.iconUrl;
      img.alt = '';
      img.style.width = img.style.height = '70%';
      img.style.objectFit = 'contain';
      img.style.pointerEvents = 'none';
      badge.appendChild(img);
    } else {
      // built-in 3K mark, injected as inline SVG (crisper, no encoding cost)
      const wrap = document.createElement('span');
      wrap.style.width = wrap.style.height = '70%';
      wrap.style.display = 'flex';
      wrap.style.pointerEvents = 'none';
      wrap.innerHTML = ICON_SVG;
      const svgEl = wrap.firstElementChild;
      if (svgEl) { svgEl.style.width = svgEl.style.height = '100%'; svgEl.setAttribute('aria-hidden', 'true'); }
      badge.appendChild(wrap);
    }

    ensureKeyframes();
    document.body.appendChild(badge);
    if (onReveal) onReveal();
  }

  function hide() {
    if (!badge) return;
    badge.remove();
    badge = null;
    if (onHide) onHide();
  }

  function onKeyDown(e) {
    if (held(e)) {
      // Alt can emit alternate glyphs into a focused input on some keyboard
      // layouts (Mac Option key) — stop that leaking through.
      if (e.preventDefault) e.preventDefault();
      show();
    }
  }
  function onKeyUp(e) { if (!held(e)) hide(); }
  // A tab switch or OS shortcut can swallow keyup — hide on blur too so the
  // badge never gets stranded visible.
  function onBlur() { hide(); }

  window.addEventListener('keydown', onKeyDown);
  window.addEventListener('keyup', onKeyUp);
  window.addEventListener('blur', onBlur);

  return function teardown() {
    window.removeEventListener('keydown', onKeyDown);
    window.removeEventListener('keyup', onKeyUp);
    window.removeEventListener('blur', onBlur);
    hide();
  };
}

export default initW3kBadge;

// --- auto-run for <script type="module" src="w3k-badge.js" data-auto> ---
// (or any renamed copy of this same file — see w3k-badge-wp-config/ for an
// example that ships it as wp-custom.js instead)
try {
  const cur = typeof document !== 'undefined' ? document.currentScript : null;
  // currentScript is null for module scripts in some engines; fall back to
  // a bare data-auto lookup (no filename match — this file is deliberately
  // renamed by some install packages, e.g. the WordPress wp-config.php
  // loader, specifically so it doesn't announce itself; a src*="w3k-badge"
  // filter here would silently break auto-init for any renamed copy,
  // which is exactly what happened before this was caught by testing a
  // renamed deployment directly, 2026-09-08).
  const auto =
    (cur && cur.hasAttribute && cur.hasAttribute('data-auto')) ||
    (typeof document !== 'undefined' &&
      document.querySelector('script[data-auto][type="module"]'));
  if (auto) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => initW3kBadge());
    } else {
      initW3kBadge();
    }
  }
} catch (e) { /* non-DOM import: ignore */ }
