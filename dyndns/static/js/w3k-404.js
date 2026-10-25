/**
 * w3k-pacman-404.js — a playable, w3K-branded Pac-Man for 404 pages.
 * w3K-404 v1.5.9 — generated; edit engine/ in the w3K-404 repo.
 * ---------------------------------------------------------------------------
 * Drop-in for ANY site: static HTML, PHP, WordPress, Laravel — anything that
 * serves a 404. Self-contained: injects its own CSS and markup, loads no
 * images, fonts, or libraries, and makes no network requests. One file.
 *
 * INSTALL — plain HTML or PHP (404.php, error page, anything)
 *
 *     <div id="w3k-404"></div>
 *     <script src="w3k-pacman-404.js"></script>
 *     <script>w3kPacman404('#w3k-404');</script>
 *
 *   Or let it place itself (appends to <body>):
 *
 *     <script src="w3k-pacman-404.js" data-auto></script>
 *
 * INSTALL — WordPress, in the theme's 404.php
 *
 *     <div id="w3k-404"></div>
 *     <script src="<?php echo get_template_directory_uri(); ?>/w3k-pacman-404.js"></script>
 *     <script>w3kPacman404('#w3k-404');</script>
 *
 *   Or enqueue it properly from functions.php (no theme-file edit):
 *
 *     add_action('wp_enqueue_scripts', function () {
 *         if (is_404()) {
 *             wp_enqueue_script('w3k-pacman-404',
 *                 get_template_directory_uri() . '/w3k-pacman-404.js', [], '1.0', true);
 *             wp_add_inline_script('w3k-pacman-404', 'w3kPacman404();');
 *         }
 *     });
 *
 * INSTALL — Apache / nginx for a whole site
 *
 *     Apache .htaccess:  ErrorDocument 404 /404.html
 *     nginx:             error_page 404 /404.html;
 *   ...where 404.html contains the two lines from the plain-HTML install.
 *
 * OPTIONS — w3kPacman404(target, opts)
 *
 *     target          CSS selector or element; omit to append to <body>.
 *     opts.code       big number        (default "404")
 *     opts.title      headline text     (default "This path doesn't exist.")
 *     opts.path       path to show      (default location.pathname; "" hides)
 *     opts.homeUrl    back-link href    (default "/")
 *     opts.homeLabel  back-link text    (default "back to home")
 *     opts.chrome     false = game only, no 404 text  (default true)
 *     opts.accent     maze colour       (default "#00c4f0", w3K cyan)
 *     opts.scoreboard high-score endpoint (default https://files.w3k.dev/_hs;
 *                     set to null/'' to disable the boards entirely)
 *
 * Returns teardown() — stops the loop, unbinds keys, empties the mount.
 *
 * Defines window.w3kPacman404, and exports for CommonJS bundlers, so a plain
 * <script> tag and a build pipeline both work unmodified.
 *
 * Controls: arrows/WASD, swipe on touch, P to pause. High score persists in
 * localStorage per-origin. No cookies, no tracking, no outbound requests.
 *
 * Pairs with w3k-badge.js but is independent of it — load either or both.
 *
 * (c) w3K LLC
 */

(function (root) {
  'use strict';

  var STYLE_ID = 'w3k-pac-404-style';
  var CSS = ".w3kpac, .w3kpac * { box-sizing: border-box; }\n.w3kpac {\n  display: block; background: var(--card); color: var(--text);\n  font-family: 'Consolas','Cascadia Code','SF Mono',ui-monospace,monospace;\n  padding: 26px 16px 30px; border-radius: 8px;\n  max-width: 100%; overflow-x: clip;\n}\n/* Reclaim the side padding on a phone \u2014 at 320px those 32px are\n   10% of the screen and the board is the thing that matters. */\n@media (max-width: 480px) {\n  .w3kpac { padding: 18px 8px 20px; border-radius: 6px; }\n}\n.w3kpac * { font-family: inherit; }\n.w3kpac a { color: var(--accent); text-decoration: none; }\n.w3kpac a:hover { text-decoration: underline; }\n\n.w3kpac *, .w3kpac *::before, .w3kpac *::after { box-sizing: border-box; margin: 0; padding: 0; }\n.w3kpac { --bg:      #070b14;\n  --surface: #0d1525;\n  --border:  #162036;\n  --text:    #c4d4e4;\n  --muted:   #5a7090;\n  --accent:  #00c4f0;\n  --green:   #4ecf98;\n  --err:     #ff5555;\n  --pac:     #f0c000;\n  --font:    'Consolas', 'Cascadia Code', 'SF Mono', ui-monospace, monospace;\n   \n  --card: color-mix(in srgb, var(--bg) 76%, transparent); }\n.w3kpac { background: var(--card); color: var(--text); font-family: var(--font);\n  font-size: 14px; min-height: 100vh; display: flex; flex-direction: column; }\n.w3kpac a { color: var(--accent); text-decoration: none; }\n.w3kpac a:hover { text-decoration: underline; }\n.w3kpac header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; gap: 16px; }\n.w3kpac .logo { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: .04em; }\n.w3kpac .logo span { color: var(--muted); font-weight: 400; }\n.w3kpac main { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; padding: 28px 16px 40px; }\n.w3kpac .msg { text-align: center; margin-bottom: 20px; }\n.w3kpac .code { font-size: 44px; font-weight: 700; color: var(--err); letter-spacing: .08em; line-height: 1; }\n.w3kpac .headline { font-size: 15px; margin-top: 10px; }\n.w3kpac .path { font-size: 12px; color: var(--muted); margin-top: 8px;\n  word-break: break-all; max-width: 90vw; }\n.w3kpac .back { margin-top: 14px; font-size: 13px; }\n.w3kpac .hud { display: flex; gap: clamp(7px, 2.2vw, 22px); align-items: baseline;\n  justify-content: center; flex-wrap: nowrap;\n  font-size: 12px; color: var(--muted); margin-bottom: 8px; letter-spacing: .08em;\n  max-width: 100%; overflow-x: auto; overflow-y: hidden;\n  \n  scrollbar-width: none; -webkit-overflow-scrolling: touch; }\n.w3kpac .hud::-webkit-scrollbar { display: none; }\n.w3kpac .hud > * { flex: 0 0 auto; white-space: nowrap; }\n.w3kpac .hud b { color: var(--hud, var(--pac)); font-weight: 700; font-size: 14px; }\n.w3kpac .hud .lives { color: var(--hud, var(--pac)); letter-spacing: 2px; }\n.w3kpac .hud .spd { display: inline-flex; align-items: center; gap: 6px; flex-wrap: nowrap; }\n.w3kpac .hud .spd > span { display: inline-flex; gap: 6px; flex-wrap: nowrap; }\n.w3kpac .spdbtn { background: none; border: 1px solid var(--border); color: var(--muted);\n  font-family: var(--font); font-size: 11px; padding: 3px 8px;\n  border-radius: 3px; cursor: pointer; transition: border-color .15s, color .15s; }\n.w3kpac .spdbtn:hover { border-color: var(--accent); color: var(--accent); }\n.w3kpac .spdbtn.on { border-color: var(--accent); color: var(--accent); font-weight: 700; }\n.w3kpac .stage { position: relative;\n  display: flex; justify-content: center; align-items: flex-start;\n  width: fit-content; max-width: 100%; margin-inline: auto;\n  padding: 10px; }\n.w3kpac canvas { display: block; border: 1px solid var(--border); border-radius: 6px;\n  \n  background: var(--bg); max-width: 100%; height: auto; touch-action: none;\n  margin-inline: auto; }\n.w3kpac .overlay { position: absolute; inset: 0; display: flex; flex-direction: column;\n  align-items: center; justify-content: center; gap: 12px;\n  \n  background: color-mix(in srgb, var(--bg) 88%, transparent);\n  border-radius: 6px; text-align: center; padding: 16px; }\n.w3kpac .overlay.hide { display: none; }\n.w3kpac .overlay h2 { font-size: 16px; font-weight: 700; letter-spacing: .06em; }\n.w3kpac .overlay h2.win { color: var(--green); }\n.w3kpac .overlay h2.lose { color: var(--err); }\n.w3kpac .overlay p { font-size: 12px; color: var(--muted); max-width: 300px; line-height: 1.6; }\n.w3kpac .btn-go { background: var(--accent); border: none; color: var(--on-accent, #000); font-family: var(--font);\n  font-size: 13px; font-weight: 700; padding: 9px 22px; border-radius: 4px; cursor: pointer; }\n.w3kpac .btn-go:hover { opacity: .85; }\n.w3kpac .hint { font-size: 11px; color: var(--muted); margin-top: 12px; text-align: center; line-height: 1.7; }\n.w3kpac footer { background: var(--surface); border-top: 1px solid var(--border); padding: 12px 24px; font-size: 11px; color: var(--muted); display: flex; justify-content: space-between; }\n.w3kpac .hs-open { align-self: center;\n  background: none; border: 1px solid var(--border) !important;\n  color: var(--muted);\n  font-family: var(--font) !important; font-size: 13px !important;\n  line-height: 1 !important; letter-spacing: 0 !important;\n  text-transform: none !important;\n  padding: 4px 9px !important; margin: 0 !important;\n  border-radius: 4px !important; cursor: pointer;\n  transition: border-color .15s, color .15s; }\n.w3kpac .hs-open:hover { border-color: var(--accent); color: var(--accent); }\n.w3kpac .hs-modal { position: fixed; inset: 0;\n  background: color-mix(in srgb, var(--bg) 84%, transparent);\n  display: none; align-items: center; justify-content: center;\n  z-index: 600; padding: 20px; }\n.w3kpac .hs-modal.open { display: flex; }\n.w3kpac .hs-panel { background: var(--surface); border: 1px solid var(--border);\n  border-radius: 8px; padding: 20px 22px; width: 100%; max-width: 460px;\n  max-height: 82vh; overflow-y: auto; }\n.w3kpac .hs-head { display: flex; align-items: center; margin-bottom: 14px; }\n.w3kpac .hs-head h2 { font-size: 14px; font-weight: 700; letter-spacing: .04em; }\n.w3kpac .hs-x { margin-left: auto; background: none; border: none; color: var(--muted);\n  font-family: var(--font); font-size: 15px; cursor: pointer; padding: 2px 4px; }\n.w3kpac .hs-x:hover { color: var(--accent); }\n.w3kpac .boards { display: grid; grid-template-columns: 1fr 1fr; gap: 18px;\n  width: 100%; }\n.w3kpac .board h3 { font-size: 10px; font-weight: 600; text-transform: uppercase;\n  letter-spacing: .12em; color: var(--muted); margin-bottom: 8px;\n  border-bottom: 1px solid var(--border); padding-bottom: 5px; }\n.w3kpac .hs-row { display: grid; grid-template-columns: 20px 1fr auto; gap: 6px;\n  align-items: baseline; font-size: 11px; padding: 2px 0; }\n.w3kpac .hs-rank { color: var(--muted); }\n.w3kpac .hs-name { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n.w3kpac .hs-score { color: var(--pac); font-weight: 700; }\n.w3kpac .hs-dom { grid-column: 2 / -1; color: var(--muted); font-size: 9px; margin-top: -2px; }\n.w3kpac .hs-empty { font-size: 11px; color: var(--muted); padding: 4px 0; }\n.w3kpac #ov-input { background: var(--bg); border: 1px solid var(--border); color: var(--text);\n  font-family: var(--font); font-size: 15px; letter-spacing: .12em;\n  padding: 9px 12px; border-radius: 4px; width: 200px; text-align: center; }\n.w3kpac #ov-input:focus { outline: none; border-color: var(--accent); }\n.w3kpac .ov-err { color: var(--err); font-size: 11px; min-height: 14px; margin-top: 6px; }\n.w3kpac .ab-open { display: inline-flex !important; align-items: center !important;\n  justify-content: center !important; padding: 3px 6px !important; }\n.w3kpac .ab-open svg { display: block; }\n.w3kpac .ab-open:hover svg { color: var(--accent); }\n.w3kpac .ab-panel { max-width: 360px; }\n.w3kpac .ab-line { font-size: 12px; color: var(--muted); line-height: 1.6;\n  margin-bottom: 14px; }\n.w3kpac .ab-rows { display: grid; grid-template-columns: auto 1fr;\n  gap: 6px 14px; font-size: 12px; align-items: baseline; }\n.w3kpac .ab-rows dt { color: var(--muted); letter-spacing: .06em;\n  font-size: 10px; text-transform: uppercase; }\n.w3kpac .ab-rows dd { color: var(--text); }\n.w3kpac .ab-foot { margin-top: 16px; padding-top: 12px;\n  border-top: 1px solid var(--border);\n  font-size: 11px; color: var(--muted); }\n@media (max-width: 700px) {\n.w3kpac .code { font-size: 34px; }\n.w3kpac .boards { grid-template-columns: 1fr; gap: 14px; }\n.w3kpac .hs-panel { padding: 16px; }\n.w3kpac footer { flex-direction: column; gap: 4px; }\n\n\n}\n@media (max-width: 520px) {\n.w3kpac .hud { flex-wrap: wrap;\n    row-gap: 8px; column-gap: 12px;\n    overflow-x: visible; }\n.w3kpac .spdbtn { padding: 7px 10px; font-size: 12px; }\n.w3kpac .hs-open { padding: 5px 9px !important; font-size: 15px !important; }\n.w3kpac .overlay input[type=\"text\"] { font-size: 16px; padding: 11px 12px; }\n\n\n}\n.w3kpac.is-fs { position: fixed; inset: 0; z-index: 2147483000;\n  margin: 0; border-radius: 0;\n  \n  width: 100vw; width: 100dvw;\n  height: 100vh; height: 100svh;\n  max-width: 100vw; max-width: 100dvw;\n  \n  padding: max(4px, env(safe-area-inset-top)) 0\n           max(4px, env(safe-area-inset-bottom));\n  display: flex; flex-direction: column; align-items: center;\n  justify-content: center; gap: 4px;\n  overflow: hidden; }\n.w3kpac.is-fs .msg, .w3kpac.is-fs .hint, .w3kpac.is-fs footer { display: none; }\n.w3kpac .k, .w3kpac .k1 { font-style: normal; }\n.w3kpac .k1 { display: none; }\n.w3kpac.is-fs .hud .k { display: none; }\n.w3kpac.is-fs .hud .k1 { display: inline; }\n.w3kpac.is-fs .hud { flex: 0 0 auto; margin-bottom: 0;\n  flex-wrap: nowrap;          \n  gap: 12px; font-size: 11px;\n  \n  justify-content: flex-start;\n  width: 100%;\n  padding: 0 90px 0 10px;\n  max-width: 100%; overflow: hidden; }\n.w3kpac.is-fs .hs-open:not(.ab-open), .w3kpac.is-fs .spd { display: none; }\n.w3kpac.is-fs .fs-surface { flex: 1 1 auto; min-height: 0; width: 100%;\n  display: flex; flex-direction: column; align-items: center;\n  justify-content: center; gap: 4px; }\n.w3kpac.is-fs .stage { padding: 0;\n  flex: 1 1 auto; min-height: 0;\n  display: flex; align-items: center; justify-content: center;\n  width: 100%; }\n.w3kpac.is-fs canvas { width: auto; height: auto;\n  max-width: 100%; max-height: 100%;\n  aspect-ratio: 448 / 496;\n  border-radius: 4px; }\n.w3kpac .thm-btn { display: none; }\n.w3kpac.is-fs .thm-btn, .w3kpac.is-fs .ab-open, .w3kpac.is-fs .fs-exit { display: flex !important;\n  align-items: center !important; justify-content: center !important;\n  position: absolute;\n  top: max(6px, env(safe-area-inset-top));\n  z-index: 2;\n  width: 16px !important; height: 16px !important;\n  min-width: 16px !important; min-height: 16px !important;\n  max-width: 16px !important; max-height: 16px !important;\n  box-sizing: content-box !important;\n  padding: 5px !important; margin: 0 !important;\n  background: var(--surface); color: var(--text);\n  border: 1px solid var(--muted) !important;\n  \n  border-radius: 6px !important;\n  font-family: var(--font) !important;\n  font-size: 12px !important; line-height: 16px !important;\n  font-weight: 700 !important; letter-spacing: 0 !important;\n  text-transform: none !important; text-indent: 0 !important;\n  cursor: pointer;\n  transition: background .15s, color .15s, border-color .15s; }\n.w3kpac.is-fs .thm-btn { right: 40px; }\n.w3kpac.is-fs .ab-open { right: 72px; }\n.w3kpac.is-fs .ab-open svg { width: 16px; height: 16px; }\n.w3kpac.is-fs .ab-open:hover, .w3kpac.is-fs .ab-open:focus-visible { background: var(--accent); color: var(--bg);\n  border-color: var(--accent) !important; outline: none; }\n.w3kpac.is-fs .ab-open:hover svg { color: inherit; }\n.w3kpac.is-fs .thm-btn:hover, .w3kpac.is-fs .thm-btn:focus-visible { background: var(--accent); color: var(--bg);\n  border-color: var(--accent); outline: none; }\n.w3kpac .fs-exit { display: none; }\n.w3kpac.is-fs .fs-exit:hover, .w3kpac.is-fs .fs-exit:focus-visible { background: var(--accent); color: var(--bg);\n  border-color: var(--accent); outline: none; }\n.w3kpac.is-fs .fs-hint { display: block; flex: 0 0 auto;\n  font-size: 10px; letter-spacing: .08em; color: var(--muted);\n  padding-top: 2px; text-align: center; }\n.w3kpac .fs-hint { display: none; }\n.w3kpac-fs-lock { overflow: hidden !important; }\n.w3kpac.is-fs { --card:    #070b14;      \n  --bg:      #070b14;\n  --surface: #0d1525;\n  --border:  #162036;\n  --text:    #c4d4e4;\n  --muted:   #5a7090;\n  --green:   #4ecf98;\n  --err:     #ff5555;\n  --pac:     #f0c000; }\n@media (min-width: 821px), (pointer: fine) {\n.w3kpac.is-fs { padding: 0;\n    background: color-mix(in srgb, var(--bg) 82%, transparent);\n    backdrop-filter: blur(3px);\n    -webkit-backdrop-filter: blur(3px); }\n.w3kpac.is-fs .fs-surface { position: relative;      \n    background: var(--bg);\n    border: 1px solid var(--border); border-radius: 10px;\n    box-shadow: 0 18px 60px rgba(0, 0, 0, .45);\n    padding: 14px 18px 16px;\n    display: flex; flex-direction: column; align-items: center; gap: 8px;\n    \n    flex: 0 0 auto; width: auto;\n    max-width: calc(100vw - 48px); max-height: calc(100vh - 48px); }\n.w3kpac.is-fs .fs-exit { top: 8px !important; right: 8px !important; }\n.w3kpac.is-fs .thm-btn { top: 8px !important; right: 40px !important; }\n.w3kpac.is-fs .ab-open { top: 8px !important; right: 72px !important; }\n\n\n}\n.w3kpac.is-fs { --hud: var(--pac); }\n\n";
  var MARKUP = "  <div class=\"msg\" data-w3kpac=\"msg\">\n    <div class=\"code\" data-w3kpac=\"code\">404</div>\n    <div class=\"headline\" data-w3kpac=\"title\">This path doesn't exist.</div>\n    <div class=\"path\" data-w3kpac=\"path\"></div>\n    <div class=\"back\"><a href=\"/\" data-w3kpac=\"home\">&larr; back to home</a></div>\n  </div>\n\n  <button class=\"thm-btn\" data-w3kpac=\"thmbtn\" type=\"button\"\n          title=\"Switch light / dark\" aria-label=\"Switch light or dark\">&#9680;</button>\n  <button class=\"fs-exit\" data-w3kpac=\"fsexit\" type=\"button\" title=\"Close (Esc)\"\n          aria-label=\"Close\">&#10005;</button>\n\n  <div class=\"hud\">\n    <span title=\"Level\"><i class=\"k\">LVL</i><i class=\"k1\">L</i> <b data-w3kpac=\"level\">1</b></span>\n    <span title=\"Score\"><i class=\"k\">SCORE</i><i class=\"k1\">S</i> <b data-w3kpac=\"score\">0</b></span>\n    <span title=\"High score\"><i class=\"k\">HIGH</i><i class=\"k1\">H</i> <b data-w3kpac=\"high\">0</b></span>\n    <span class=\"lives\" data-w3kpac=\"lives\" title=\"Lives\">\u25cf\u25cf\u25cf</span>\n    <span class=\"spd\" title=\"Starting speed\"><i class=\"k\">START</i><i class=\"k1\">&#9654;</i> <span data-w3kpac=\"speedbtns\"></span></span>\n    <button class=\"hs-open\" data-w3kpac=\"hsbtn\" title=\"High scores\">\ud83c\udfc6</button>\n    <button class=\"hs-open ab-open\" data-w3kpac=\"abbtn\" type=\"button\"\n            title=\"About w3K 404\" aria-label=\"About w3K 404\"><svg viewBox=\"0 0 1024 1024\" width=\"15\" height=\"15\" aria-hidden=\"true\" focusable=\"false\"><g transform=\"translate(0,960) scale(1,-1)\"><path fill=\"currentColor\" d=\"M465.988 919.006c63.932 8.772 129.399 1.263 190.891-17.545 82.483-29.423 154.914-83.866 209.852-151.671 5.769-5.513 5.734-13.943 4.779-21.316-1.724-9.882-4.164-19.627-6.434-29.389 23.962-10.581 48.623-23.671 63.198-46.319 35.618-67.618 52.275-143.735 57.19-219.614 2.884-17.22-11.23-30.071-19.712-43.315 11.827-19.917 10.769-44.732 5.837-66.662-12.373-46.729-33.007-91.238-60.194-131.209-66.116-99.004-170.001-171.401-285.082-201.233-79.94-20.156-164.847-24.201-245.146-3.686 62.635 21.197 126.515 38.741 188.45 62.054 65.417 24.183 131.243 48.947 190.993 85.436 69.376 43.52 135.834 98.185 174.438 171.895 9.591 23.484 24.183 45.909 22.699 72.414-16.93-15.991-29.833-35.652-46.746-51.661-102.519-107.366-233.011-184.525-370.159-239.104-58.419-23.996-119.159-41.54-179.063-61.269-21.367-5.615-45.244-11.162-66.406-1.809-27.887 11.998-53.402 28.86-77.943 46.541-23.723 18.739-47.701 37.444-68.454 59.494-4.233 4.813-9.216 11.503-5.513 18.057 14.473 30.379 39.049 54.255 61.474 78.797-29.594-3.652-58.846-11.469-88.849-10.223-16.247 2.731-33.041 7.885-45.21 19.558-11.861 16.708-15.957 37.376-21.982 56.627-4.13 17.988-10.411 35.925-9.933 54.562 10.428 40.107 25.31 79.599 48.077 114.432-11.247-0.222-22.972-1.929-33.673 2.577-11.366 9.421-16.555 24.969-14.575 39.407 17.92 105.574 66.799 206.336 141.619 283.29 17.903 18.347 39.287 32.734 60.297 47.189 66.953 45.38 144.657 75.349 225.28 83.695zM196.83 787.046c-43.281-41.66-83.831-89.19-104.448-146.449-4.523-9.847 5.598-19.644 15.155-20.139 31.283-1.331 60.058 12.134 89.207 21.248 7.509 2.628 15.258 4.813 22.153 8.892 23.245 13.090 47.889 23.433 71.27 36.284 49.527 25.054 96.137 55.381 141.756 86.886 16.811 11.469 32.734 24.166 48.521 36.983-5.871 8.38-13.551 15.309-19.251 23.808 32.256 5.444 64.819 8.977 97.126 14.165 26.061 3.362 51.917 8.533 78.182 10.223-0.87-24.098-7.919-47.377-10.121-71.339-5.308-34.611-10.377-69.342-17.698-103.595-8.738 6.212-16.418 13.909-25.702 19.302-3.857 1.946-7.492-1.417-10.394-3.584-20.207-18.381-44.254-31.71-65.417-48.896-115.132-82.569-243.9-148.924-382.583-180.821-14.37-2.645-22.716-16.521-30.293-27.546-10.974-19.575-20.873-41.079-21.897-63.829 2.816-9.728 15.223-10.581 23.364-12.151 39.953-1.98 80.606 1.109 119.245 11.844 35.789 11.878 70.417 27.187 103.953 44.373 63.659 34.185 126.447 69.973 188.928 106.257 47.343 29.15 92.041 62.993 130.884 102.878 26.846 26.897 54.221 54.204 73.233 87.433 16.213 17.818 29.713 37.871 41.95 58.59 8.738 15.718 13.278 34.748 9.028 52.514-6.485 11.844-18.586 19.319-29.116 27.204-50.569 35.721-112.896 48.384-173.278 55.62-132.233 14.746-267.742-35.191-363.759-126.157zM860.194 681.933c-29.303-65.57-69.12-126.43-118.101-179.012-24.951-28.57-54.221-52.855-83.098-77.312-16.128-12.561-33.178-23.91-50.347-34.987-38.485-23.467-80.367-40.448-120.866-60.023-48.367-23.245-96.802-46.473-146.466-66.884-18.415-7.236-36.813-14.848-56.286-18.893-19.541-5.257-39.765-8.038-58.931-14.592-9.114-7.919-16.606-17.442-24.525-26.505-12.544-14.899-26.061-29.508-34.202-47.445 17.203-7.083 35.977-9.626 54.494-8.789 38.093 0.99 76.851 2.099 113.715 12.766 72.789 20.173 142.814 49.766 208.845 86.374 81.015 45.158 158.498 96.751 230.878 154.812 14.251 11.281 26.351 25.020 41.062 35.755 25.549 22.033 50.091 45.431 71.987 71.117 11.759 18.995 23.245 38.434 31.283 59.341 7.953 23.518 9.216 51.712-5.035 73.079-11.571 20.634-32.495 33.775-54.409 41.199zM817.408 908.868c7.202 10.325 21.231 10.394 32.461 10.394 11.878 0.222 23.825 0.546 35.669-0.683 7.27-1.161 11.059-7.834 14.37-13.602 4.369 9.131 13.619 18.176 24.61 13.636 7.919-5.922 5.359-17.766 8.226-26.368 12.049 8.892 19.337 28.006 36.71 26.931 7.509 2.543 13.244-2.543 18.603-6.537-7.936-11.435-16.179-22.784-26.214-32.478-5.325-0.085-9.353 4.062-13.807 6.349 8.55-16.555 22.221-29.474 33.536-44.049 4.642-6.144 4.42-14.234 5.905-21.504-6.622-1.417-14.268-6.656-20.702-1.997-12.356 8.090-20.565 20.838-30.14 31.795-1.775-0.222-3.533-0.427-5.274-0.649-0.307-12.732 0.222-29.065-15.189-33.553-11.401-4.454-16.367 5.205-15.479 14.797-4.011-5.7-8.789-11.162-15.206-14.234-16.725-1.314-33.553-1.178-50.227 0.324-12.681 1.058-21.879 12.766-25.412 24.149-1.399 4.813 0.119 11.895 5.82 12.902 7.885 3.072 15.701-1.382 22.733-4.574 8.738-4.983 19.115-3.482 28.809-3.823-4.13 6.468-9.643 12.117-12.919 19.098 0.085 9.779 8.243 16.503 12.22 24.866-8.789-0.751-18.227 1.451-26.539-2.304-8.943-4.045-18.449-6.844-28.228-7.902-3.447 10.018-2.236 21.111 5.666 29.013zM881.783 867.721c5.888-8.465 12.442-16.452 19.115-24.32 0.29 16.828 0.171 33.655-0.051 50.483-6.366-8.721-12.766-17.408-19.063-26.163z\"/></g></svg></button>\n  </div>\n\n  <div class=\"stage\">\n    <canvas data-w3kpac=\"canvas\" width=\"448\" height=\"496\"></canvas>\n    <div class=\"overlay\" data-w3kpac=\"overlay\">\n      <h2 data-w3kpac=\"ovtitle\">LOST IN THE MAZE?</h2>\n      <p data-w3kpac=\"ovtext\">While you're here \u2014 eat the dots, dodge the ghosts. Each level is a new maze and a little faster.</p>\n      <div data-w3kpac=\"ovname\" style=\"display:none\">\n        <input data-w3kpac=\"ovinput\" type=\"text\" maxlength=\"13\" minlength=\"3\"\n               placeholder=\"your name\" autocomplete=\"off\" spellcheck=\"false\"\n               aria-label=\"Name for the high score board\">\n        <div data-w3kpac=\"overr\" class=\"ov-err\"></div>\n      </div>\n      <button class=\"btn-go\" data-w3kpac=\"ovbtn\">Play</button>\n    </div>\n  </div>\n\n  <div class=\"hint\">\n    Arrow keys or WASD to move \u00b7 swipe on mobile \u00b7 P to pause \u00b7 [ ] for speed\n  </div>\n\n  <div class=\"fs-hint\" data-w3kpac=\"fshint\">ESC or &#10005; to close</div>\n\n  <!-- Scoreboards live in a modal behind the trophy button so the page\n       stays compact \u2014 only the canvas and one HUD line outside it. -->\n  <div class=\"hs-modal ab-modal\" data-w3kpac=\"abmodal\">\n    <div class=\"hs-panel ab-panel\">\n      <div class=\"hs-head\">\n        <h2>w3K 404</h2>\n        <button class=\"hs-x\" data-w3kpac=\"abclose\" aria-label=\"Close\">&#10005;</button>\n      </div>\n      <p class=\"ab-line\">A playable Pac-Man for pages that do not exist.</p>\n      <dl class=\"ab-rows\">\n        <dt>Version</dt><dd data-w3kpac=\"abver\">&mdash;</dd>\n        <dt>Built by</dt><dd>w3K LLC</dd>\n        <dt>Author</dt><dd>ApoCaLypSe</dd>\n        <dt>Leaderboard</dt><dd data-w3kpac=\"abhs\">&mdash;</dd>\n      </dl>\n      <p class=\"ab-foot\">\n        <a href=\"https://w3k.dev\" target=\"_blank\" rel=\"noopener\">w3k.dev</a>\n        &middot; &copy; w3K LLC\n      </p>\n    </div>\n  </div>\n\n  <div class=\"hs-modal\" data-w3kpac=\"hsmodal\">\n    <div class=\"hs-panel\">\n      <div class=\"hs-head\">\n        <h2>\ud83c\udfc6 High scores</h2>\n        <button class=\"hs-x\" data-w3kpac=\"hsclose\" aria-label=\"Close\">\u2715</button>\n      </div>\n      <div class=\"boards\">\n        <div class=\"board\">\n          <h3>Top here</h3>\n          <div data-w3kpac=\"hslocal\"><div class=\"hs-empty\">loading\u2026</div></div>\n        </div>\n        <div class=\"board\">\n          <h3>Top everywhere</h3>\n          <div data-w3kpac=\"hsglobal\"><div class=\"hs-empty\">loading\u2026</div></div>\n        </div>\n      </div>\n    </div>\n  </div>\n";

  // Apply a host-supplied palette by overriding the CSS custom properties
  // the stylesheet is written against. Nothing here hardcodes a colour: a
  // light theme and a dark theme both work by handing over different values.
  function ensureStyle(opts) {
    var el = document.getElementById(STYLE_ID);
    if (!el) {
      el = document.createElement('style');
      el.id = STYLE_ID;
      document.head.appendChild(el);
    }

    var p = opts.palette || {};
    var accent = opts.accent || p.accent || '#00c4f0';

    // Map host palette -> the variables the stylesheet uses. Anything the
    // host does not supply keeps the built-in dark default.
    var vars = {
      '--card':    p.card,
      '--on-accent': p.onAccent,
      '--hud':     p.hud,
      '--bg':      p.board || p.bg,
      '--surface': p.surface,
      '--border':  p.border,
      '--text':    p.text,
      '--muted':   p.muted,
      '--accent':  accent
    };

    var overrides = '';
    for (var k in vars) {
      if (vars[k]) { overrides += k + ':' + vars[k] + ';'; }
    }

    el.textContent = CSS +
      (overrides ? '\n.w3kpac{' + overrides + '}' : '');
  }

  // Sample the page outside the mount so rerenders never sample our card.
  function pagePalette(mount) {
    var el = mount.parentElement, base;
    while (el && !base) {
      var match = /^rgba?\(([^)]+)\)/.exec(getComputedStyle(el).backgroundColor);
      if (match) {
        var parts = match[1].split(',').map(Number);
        if (parts.length < 4 || parts[3] === 1) base = parts.slice(0, 3);
      }
      el = el.parentElement;
    }
    if (!base) {
      var scheme = getComputedStyle(document.documentElement).colorScheme;
      var darkCanvas = scheme === 'dark' ||
        (scheme.indexOf('dark') !== -1 && matchMedia('(prefers-color-scheme: dark)').matches);
      base = darkCanvas ? [18, 18, 18] : [255, 255, 255];
    }
    var dark = (base[0] * .2126 + base[1] * .7152 + base[2] * .0722) < 128;
    var toward = dark ? 255 : 0;
    function mix(amount) {
      return 'rgb(' + base.map(function (c) { return Math.round(c + (toward - c) * amount); }).join(',') + ')';
    }
    return { card: 'transparent', bg: mix(0), board: mix(.015),
      path: mix(.035), surface: mix(.04), border: mix(.12),
      text: mix(.86), muted: mix(.57), hud: dark ? '#78b8ce' : '#326d80',
      onAccent: dark ? '#101820' : '#ffffff', accent: dark ? '#78b8ce' : '#326d80' };
  }


  function w3kPacman404(target, opts) {
    opts = opts || {};

    var mount;
    if (!target) { mount = document.createElement('div'); document.body.appendChild(mount); }
    else if (typeof target === 'string') { mount = document.querySelector(target); }
    else { mount = target; }
    if (!mount) throw new Error('w3kPacman404: target not found: ' + target);

    if (!opts.palette) opts = Object.assign({}, opts, { palette: pagePalette(mount) });
    ensureStyle(opts);

    mount.classList.add('w3kpac');
    mount.innerHTML = MARKUP;

    // Every lookup is scoped to this mount, so multiple instances never
    // collide and the host page's own element ids are never touched.
    function $(name) { return mount.querySelector('[data-w3kpac="' + name + '"]'); }

    if (opts.chrome === false) {
      $('msg').style.display = 'none';
    } else {
      if (opts.code)      $('code').textContent = opts.code;
      if (opts.title)     $('title').textContent = opts.title;
      if (opts.homeUrl)   $('home').setAttribute('href', opts.homeUrl);
      if (opts.homeLabel) $('home').textContent = opts.homeLabel;
      if (opts.path === '') $('path').style.display = 'none';
    }

    var stopped = false;

    // Show the path that 404'd, without trusting it as markup.
    $('path').textContent = (opts.path !== undefined ? opts.path : location.pathname);

    // ── Maze ──────────────────────────────────────────────────────────────────
    // # wall · . pellet · o power pellet · space empty · - ghost-house door
    // 28 x 31 tiles, the classic proportions.
    var RAW = [
      '############################',
      '#............##............#',
      '#.####.#####.##.#####.####.#',
      '#o####.#####.##.#####.####o#',
      '#.####.#####.##.#####.####.#',
      '#..........................#',
      '#.####.##.########.##.####.#',
      '#.####.##.########.##.####.#',
      '#......##....##....##......#',
      '######.##### ## #####.######',
      '     #.##### ## #####.#     ',
      '     #.##          ##.#     ',
      '     #.## ###--### ##.#     ',
      '######.## #      # ##.######',
      '      .   #      #   .      ',
      '######.## #      # ##.######',
      '     #.## ######## ##.#     ',
      '     #.##          ##.#     ',
      '     #.## ######## ##.#     ',
      '######.## ######## ##.######',
      '#............##............#',
      '#.####.#####.##.#####.####.#',
      '#.####.#####.##.#####.####.#',
      '#o..##.......  .......##..o#',
      '###.##.##.########.##.##.###',
      '###.##.##.########.##.##.###',
      '#......##....##....##......#',
      '#.##########.##.##########.#',
      '#.##########.##.##########.#',
      '#..........................#',
      '############################'
    ];

    // ── Maze generation ───────────────────────────────────────────────────────
    // Level 1 always uses the classic layout above; every level after gets a
    // generated one. Generation is seeded by level, so a given level is always
    // the same maze — reloading does not reroll your way out of a hard board.
    //
    // Guarantees enforced before a maze is accepted (see buildMaze):
    //   - left/right mirror symmetry, like the arcade
    //   - every open tile reachable from Pac-Man's start (no orphaned pellets)
    //   - no dead-end corridors (every open tile has 2+ open neighbours)
    //   - side tunnels on the middle row
    //   - a real ghost house with a 2-wide door, reachable from outside
    //   - 4 power pellets, one per corner region
    // A candidate failing any check is discarded and regenerated; after a bounded
    // number of attempts it falls back to the classic maze rather than shipping
    // a broken board.

    // Deterministic PRNG (mulberry32) so a seed reproduces a maze exactly.
    function rng(seed) {
      var a = seed >>> 0;
      return function () {
        a |= 0; a = (a + 0x6D2B79F5) | 0;
        var t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    }

    // Canvas palette. Every SURFACE colour drawn on the board comes from here,
    // so a host page (the WordPress plugin, say) can hand over a palette
    // sampled from its own theme instead of the w3K dark default.
    //
    // Deliberately NOT in here, and deliberately hardcoded:
    //   - the four ghost body colours, Pac-Man's yellow, the frightened blue
    //     and its white flash. These are the game's identity, not chrome —
    //     a green Blinky is not Blinky — and they were chosen to read against
    //     any background.
    //   - the ghost eye pupil (#1a2340), which must stay dark against the
    //     white sclera whatever the page behind it is doing.
    // Do not "fix" those by routing them through the palette.
    var W3K_404_VERSION = '1.5.9';

    var PAL = {
      board:  '#04070e',   // behind the maze
      path:   '#0a121f',   // walkable corridors
      wall:   '#1e6f9c',   // maze wall strokes
      pellet: '#8fa8bf',
      power:  '#00c4f0',
      door:   '#ff9ed8',
      flash:  '#ffffff'    // floating fruit score
    };

    // The defaults above ARE the dark palette. Keep a copy before a host
    // overwrites them: immersive mode is elevated off the page and always
    // renders dark, so it restores these while the windowed card keeps
    // whatever the host sampled from its theme.
    var DARK_PAL = {};
    for (var dk in PAL) { if (PAL.hasOwnProperty(dk)) DARK_PAL[dk] = PAL[dk]; }
    var THEME_PAL = null;

    // opts exists only in the embeddable build (the snippet passes host
    // options in); the standalone page has none and keeps the defaults.
    var hostOpts = (typeof opts !== 'undefined' && opts) ? opts : null;
    if (hostOpts && hostOpts.palette) {
      var hp = hostOpts.palette;
      if (hp.board)  PAL.board  = hp.board;
      if (hp.path)   PAL.path   = hp.path;
      if (hp.accent) PAL.wall   = hp.accent;
      if (hp.muted)  PAL.pellet = hp.muted;
      if (hp.accent) PAL.power  = hp.accent;
      if (hp.text)   PAL.flash  = hp.text;
      THEME_PAL = {};
      for (var tk in PAL) { if (PAL.hasOwnProperty(tk)) THEME_PAL[tk] = PAL[tk]; }
    }

    // Swap the canvas palette for immersive mode and back. The maze is painted
    // from PAL in draw(), not from CSS, so the stylesheet alone cannot darken
    // it — the board would stay light inside a dark modal.
    // The light counterpart of the engine's dark defaults. Only needed for
    // immersive mode, where the visitor can switch sides; the landing card
    // takes its palette from the host theme instead.
    var LIGHT_PAL = {
      board:  '#f6f8fa',
      path:   '#e7ecf1',
      wall:   '#0b7285',
      pellet: '#64748b',
      power:  '#0b7285',
      door:   '#c2185b',
      flash:  '#1a2027'
    };

    // Immersive mode's CSS variables, per side. Everything the card, HUD,
    // overlays and modals paint resolves through these, so one swap flips the
    // entire surface — that is why every hardcoded colour had to go first.
    var FS_VARS = {
      dark:  { bg: '#070b14', surface: '#0d1525', border: '#162036',
               text: '#c4d4e4', muted: '#5a7090' },
      light: { bg: '#f6f8fa', surface: '#eceff3', border: '#d3d9e0',
               text: '#1a2027', muted: '#64748b' }
    };

    var FS_KEY = 'w3kpac.fsScheme';
    function fsScheme() {
      try {
        var v = localStorage.getItem(FS_KEY);
        if (v === 'light' || v === 'dark') return v;
      } catch (e) {}
      return 'dark';            // elevated off the page: dark by default
    }

    function usePalette(which) {
      var src;
      if (which === 'theme') {
        src = THEME_PAL || DARK_PAL;
      } else {
        src = (which === 'light') ? LIGHT_PAL : DARK_PAL;
      }
      for (var k in src) { if (src.hasOwnProperty(k)) PAL[k] = src[k]; }
      if (typeof draw === 'function' && typeof grid !== 'undefined' && grid) draw();
    }

    // Paint immersive mode in the chosen side and remember it.
    function applyFsScheme(which) {
      var v = FS_VARS[which] || FS_VARS.dark;
      if (fsRoot && fsRoot.style) {
        fsRoot.style.setProperty('--card', v.bg);
        fsRoot.style.setProperty('--bg', v.bg);
        fsRoot.style.setProperty('--surface', v.surface);
        fsRoot.style.setProperty('--border', v.border);
        fsRoot.style.setProperty('--text', v.text);
        fsRoot.style.setProperty('--muted', v.muted);
      }
      usePalette(which);
      try { localStorage.setItem(FS_KEY, which); } catch (e) {}
      var tb = $('thmbtn');
      if (tb) {
        tb.textContent = which === 'dark' ? '\u25D1' : '\u25D0';
        tb.setAttribute('title', which === 'dark' ? 'Switch to light' : 'Switch to dark');
      }
    }

    // Clear the inline overrides so the landing card goes back to the host
    // theme's sampled palette. Removing them is not the same as setting them
    // to the theme values: the card must inherit, not be pinned.
    function clearFsScheme() {
      if (fsRoot && fsRoot.style) {
        ['--card', '--bg', '--surface', '--border', '--text', '--muted']
          .forEach(function (n) { fsRoot.style.removeProperty(n); });
      }
      usePalette('theme');
    }

    var COLS = 28, ROWS = 31, TILE = 16;

    // Rows the ghost house occupies; generation leaves this block alone and
    // stamps the house in afterwards.
    var HOUSE_TOP = 12, HOUSE_BOT = 16, HOUSE_L = 10, HOUSE_R = 17;

    function blankGrid() {
      var g = [];
      for (var y = 0; y < ROWS; y++) {
        var row = [];
        for (var x = 0; x < COLS; x++) row.push('#');
        g.push(row);
      }
      return g;
    }

    // Carve a symmetric maze into the left half and mirror it.
    function carve(rand) {
      var g = blankGrid();
      var halfW = COLS / 2;            // 14

      // Carve on a 2-tile lattice so corridors are always 1 wide with walls
      // between them — the look of the original, and it keeps turns on-grid.
      function open(x, y) {
        if (x < 1 || x >= halfW || y < 1 || y >= ROWS - 1) return;
        g[y][x] = '.';
        g[y][COLS - 1 - x] = '.';      // mirror
      }

      // Random walk on odd coordinates, connecting as it goes.
      var visited = {};
      function key(x, y) { return x + ',' + y; }
      var stack = [[1, 1]];
      visited[key(1, 1)] = true;
      open(1, 1);

      while (stack.length) {
        var cur = stack[stack.length - 1];
        var cx = cur[0], cy = cur[1];
        var dirs = [[0, -2], [0, 2], [-2, 0], [2, 0]];
        // shuffle
        for (var i = dirs.length - 1; i > 0; i--) {
          var j = Math.floor(rand() * (i + 1));
          var tmp = dirs[i]; dirs[i] = dirs[j]; dirs[j] = tmp;
        }
        var moved = false;
        for (var d = 0; d < dirs.length; d++) {
          var nx = cx + dirs[d][0], ny = cy + dirs[d][1];
          if (nx < 1 || nx >= halfW || ny < 1 || ny >= ROWS - 1) continue;
          if (visited[key(nx, ny)]) continue;
          // don't carve into the ghost-house block
          if (ny >= HOUSE_TOP - 1 && ny <= HOUSE_BOT + 1 && nx >= HOUSE_L - 1) continue;
          visited[key(nx, ny)] = true;
          open(cx + dirs[d][0] / 2, cy + dirs[d][1] / 2);
          open(nx, ny);
          stack.push([nx, ny]);
          moved = true;
          break;
        }
        if (!moved) stack.pop();
      }

      // Braid: knock out dead ends by opening one extra wall beside them. This
      // is what turns a perfect maze (one path, many dead ends — miserable to
      // be chased through) into the looping corridors Pac-Man needs.
      //
      // Repeated, because opening a wall can expose a NEW dead end one tile
      // along; a single pass leaves stubs behind. Bounded so a pathological
      // board cannot spin here.
      for (var pass = 0; pass < 6; pass++) {
        var fixed = 0;
        for (var by = 1; by < ROWS - 1; by++) {
          for (var bx = 1; bx < halfW; bx++) {
            if (g[by][bx] === '#') continue;
            if (by >= HOUSE_TOP - 1 && by <= HOUSE_BOT + 1 && bx >= HOUSE_L - 1) continue;
            var opens = 0, cands = [];
            [[0,-1],[0,1],[-1,0],[1,0]].forEach(function (dd) {
              var tx = bx + dd[0], ty = by + dd[1];
              if (ty < 1 || ty >= ROWS - 1 || tx < 1 || tx >= halfW) return;
              if (g[ty][tx] !== '#') opens++; else cands.push([tx, ty]);
            });
            if (opens <= 1 && cands.length) {
              // Prefer opening toward a neighbour that is ALREADY corridor two
              // tiles out, so braiding joins existing passages into loops
              // rather than hollowing out fresh space.
              var best = null;
              for (var ci = 0; ci < cands.length; ci++) {
                var tx2 = cands[ci][0] + (cands[ci][0] - bx);
                var ty2 = cands[ci][1] + (cands[ci][1] - by);
                if (ty2 > 0 && ty2 < ROWS - 1 && tx2 > 0 && tx2 < halfW &&
                    g[ty2][tx2] !== '#') { best = cands[ci]; break; }
              }
              if (!best) best = cands[Math.floor(rand() * cands.length)];
              open(best[0], best[1]);
              fixed++;
            }
          }
        }
        if (!fixed) break;
      }

      return g;
    }

    // Stamp the ghost house and its door into the middle of the board.
    function stampHouse(g) {
      for (var y = HOUSE_TOP; y <= HOUSE_BOT; y++)
        for (var x = HOUSE_L; x <= HOUSE_R; x++)
          g[y][x] = '#';
      // hollow interior
      for (var y2 = HOUSE_TOP + 1; y2 < HOUSE_BOT; y2++)
        for (var x2 = HOUSE_L + 1; x2 < HOUSE_R; x2++)
          g[y2][x2] = ' ';
      // door, matching the classic position
      g[HOUSE_TOP][13] = '-';
      g[HOUSE_TOP][14] = '-';
      // The tiles above the door must be open so ghosts can get out — and they
      // must CONNECT to the rest of the maze, or those two tiles are an island
      // holding pellets nobody can ever reach and the board is unwinnable.
      // Carve straight up from the door until the corridor meets open maze.
      if (HOUSE_TOP - 1 >= 1) {
        for (var cy = HOUSE_TOP - 1; cy >= 1; cy--) {
          var already = (g[cy][13] !== '#') && (g[cy][14] !== '#');
          g[cy][13] = '.';
          g[cy][14] = '.';
          if (already && cy < HOUSE_TOP - 1) break;   // reached existing corridor
        }
      }
      return g;
    }

    // Side tunnels: a clear corridor straight across the board on the house's
    // middle row, wrapping left-to-right.
    //
    // This row must be open along its WHOLE width outside the house, and the
    // two tiles beside the house must be open too. Previously the corridor ran
    // into the house block, so a player wrapping in from one side walked
    // straight into the house wall and froze there — off-screen, unreachable,
    // with the game only ending when a ghost happened by. Exactly what Andrew
    // hit on level 2.
    function stampTunnels(g) {
      var ty = HOUSE_TOP + 2;

      // Left arm and right arm, fully open to the edge.
      for (var x = 0; x < HOUSE_L; x++) g[ty][x] = (x === 0) ? ' ' : '.';
      for (var x2 = HOUSE_R + 1; x2 < COLS; x2++) g[ty][x2] = (x2 === COLS - 1) ? ' ' : '.';

      // The house occupies the middle of this row, so the corridor cannot pass
      // through it. Route around: open the row directly above the house band
      // across its width, and connect both arms up into it.
      var by = HOUSE_TOP - 1;
      if (by >= 1) {
        for (var bx = HOUSE_L - 1; bx <= HOUSE_R + 1 && bx < COLS - 1; bx++) {
          if (bx < 1) continue;
          if (g[by][bx] === '#') g[by][bx] = '.';
        }
        // vertical links from the tunnel row up to that bypass row
        for (var ly = by; ly <= ty; ly++) {
          if (HOUSE_L - 1 >= 1 && g[ly][HOUSE_L - 1] === '#') g[ly][HOUSE_L - 1] = '.';
          if (HOUSE_R + 1 < COLS - 1 && g[ly][HOUSE_R + 1] === '#') g[ly][HOUSE_R + 1] = '.';
        }
      }
      return g;
    }

    // Flood fill from Pac-Man's start; returns the set of reachable open tiles.
    function reachable(g, sx, sy) {
      var seen = {}, q = [[sx, sy]];
      seen[sx + ',' + sy] = true;
      while (q.length) {
        var c = q.pop(), x = c[0], y = c[1];
        [[0,-1],[0,1],[-1,0],[1,0]].forEach(function (d) {
          var nx = x + d[0], ny = y + d[1];
          if (ny < 0 || ny >= ROWS) return;
          if (nx < 0 || nx >= COLS) return;          // tunnels handled separately
          if (g[ny][nx] === '#' || g[ny][nx] === '-') return;
          var k = nx + ',' + ny;
          if (seen[k]) return;
          seen[k] = true; q.push([nx, ny]);
        });
      }
      return seen;
    }

    // Pac-Man's start tile for a generated maze: the open tile nearest the
    // classic (13,23) so the board still plays from the bottom-middle.
    function findStart(g) {
      var best = null, bestD = Infinity;
      for (var y = 1; y < ROWS - 1; y++) {
        for (var x = 1; x < COLS - 1; x++) {
          if (g[y][x] === '#' || g[y][x] === '-') continue;
          if (y >= HOUSE_TOP && y <= HOUSE_BOT && x >= HOUSE_L && x <= HOUSE_R) continue;
          var d = Math.abs(x - 13) + Math.abs(y - 23);
          if (d < bestD) { bestD = d; best = [x, y]; }
        }
      }
      return best;
    }

    // How much of the 28x31 board a level actually uses. Some levels are
    // deliberately compact — a small maze is a nice change of pace and clears
    // fast. The ghost house is fixed at the centre, so the inset is bounded to
    // leave room around it.
    function levelInset(seed) {
      var r = rng(seed ^ 0x5bd1e995);
      var roll = r();
      if (roll < 0.20) return { x: 6, y: 6 };   // small  — about a third the area
      if (roll < 0.40) return { x: 3, y: 3 };   // medium — about two thirds
      return { x: 0, y: 0 };                    // full size
    }

    function buildMaze(seed) {
      var inset = levelInset(seed);
      for (var attempt = 0; attempt < 40; attempt++) {
        var rand = rng(seed + attempt * 7919);
        var g = carve(rand);
        stampHouse(g);
        stampTunnels(g);

        // Shrink the playfield by walling off an outer ring. Done BEFORE the
        // validity checks so connectivity, route-home and dead-end removal all
        // run against the board that will actually be played.
        if (inset.x || inset.y) {
          for (var iy = 0; iy < ROWS; iy++) {
            for (var ix = 0; ix < COLS; ix++) {
              var outside = ix < inset.x || ix >= COLS - inset.x ||
                            iy < inset.y || iy >= ROWS - inset.y;
              // Never wall off the house or the tunnel row.
              var protectd = (iy >= HOUSE_TOP - 1 && iy <= HOUSE_BOT + 1 &&
                              ix >= HOUSE_L - 1 && ix <= HOUSE_R + 1) ||
                             iy === HOUSE_TOP + 2;
              if (outside && !protectd) g[iy][ix] = '#';
            }
          }
          // Re-seal the new border and re-open the tunnel mouths on its edge.
          var ty2 = HOUSE_TOP + 2;
          for (var tx2 = 0; tx2 < COLS; tx2++) {
            if (tx2 < inset.x || tx2 >= COLS - inset.x) g[ty2][tx2] = '.';
          }
          g[ty2][0] = ' '; g[ty2][COLS - 1] = ' ';
        }

        // Final dead-end removal over the FINISHED board. The braid inside
        // carve() only sees the left half and runs before the house and
        // tunnels are stamped, so stubs survive along the mirror seam and
        // beside the stamped geometry. Fix them here, symmetrically.
        for (var fp = 0; fp < 8; fp++) {
          var changed = 0;
          for (var fy = 1; fy < ROWS - 1; fy++) {
            for (var fx = 1; fx < COLS - 1; fx++) {
              if (g[fy][fx] === '#' || g[fy][fx] === '-') continue;
              if (fy >= HOUSE_TOP && fy <= HOUSE_BOT && fx >= HOUSE_L && fx <= HOUSE_R) continue;
              var nOpen = 0, walls = [];
              [[0,-1],[0,1],[-1,0],[1,0]].forEach(function (dd) {
                var tx = fx + dd[0], ty = fy + dd[1];
                if (ty < 1 || ty >= ROWS - 1) return;
                if (tx < 0 || tx >= COLS) { nOpen++; return; }
                if (g[ty][tx] !== '#') nOpen++;
                else if (tx > 0 && tx < COLS - 1) walls.push([tx, ty]);
              });
              if (nOpen <= 1 && walls.length) {
                var wpick = walls[Math.floor(rand() * walls.length)];
                // keep the board mirrored
                if (g[wpick[1]][wpick[0]] === '#') {
                  g[wpick[1]][wpick[0]] = '.';
                  var mx = COLS - 1 - wpick[0];
                  if (g[wpick[1]][mx] === '#' &&
                      !(wpick[1] >= HOUSE_TOP && wpick[1] <= HOUSE_BOT && mx >= HOUSE_L && mx <= HOUSE_R))
                    g[wpick[1]][mx] = '.';
                  changed++;
                }
              }
            }
          }
          if (!changed) break;
        }

        var start = findStart(g);
        if (!start) continue;

        var seen = reachable(g, start[0], start[1]);
        var openCount = 0, unreachable = 0;
        for (var y = 0; y < ROWS; y++) {
          for (var x = 0; x < COLS; x++) {
            if (g[y][x] === '#' || g[y][x] === '-') continue;
            if (y >= HOUSE_TOP && y <= HOUSE_BOT && x >= HOUSE_L && x <= HOUSE_R) continue;
            openCount++;
            if (!seen[x + ',' + y]) unreachable++;
          }
        }
        // Reject boards that are too sparse, too dense, or have orphans.
        // The classic maze is 244 pellets; a much denser board turns each
        // level into a slog rather than a lap.
        var areaScale = ((COLS - 2 * inset.x) * (ROWS - 2 * inset.y)) / (COLS * ROWS);
        if (openCount < 150 * areaScale || openCount > 430) continue;
        if (unreachable > 0) continue;

        // Reject any board still carrying dead-end stubs — being chased into
        // one with no way out is the single worst thing a generated maze can
        // do to the player.
        var stubs = 0;
        for (var dy2 = 1; dy2 < ROWS - 1 && stubs === 0; dy2++) {
          for (var dx2 = 1; dx2 < COLS - 1; dx2++) {
            if (g[dy2][dx2] === '#' || g[dy2][dx2] === '-') continue;
            if (dy2 >= HOUSE_TOP && dy2 <= HOUSE_BOT && dx2 >= HOUSE_L && dx2 <= HOUSE_R) continue;
            var nb = 0;
            [[0,-1],[0,1],[-1,0],[1,0]].forEach(function (dd) {
              var tx = dx2 + dd[0], ty = dy2 + dd[1];
              if (ty < 0 || ty >= ROWS) return;
              if (tx < 0 || tx >= COLS) { nb++; return; }   // tunnel mouth counts
              if (g[ty][tx] !== '#' && g[ty][tx] !== '-') nb++;
            });
            if (nb <= 1) { stubs++; break; }
          }
        }
        if (stubs > 0) continue;

        // Ghosts must be able to reach the door from inside the house.
        if (g[HOUSE_TOP - 1][13] === '#') continue;

        // Power pellets: one per corner region, on a reachable tile.
        var corners = [[1, 1], [COLS - 2, 1], [1, ROWS - 2], [COLS - 2, ROWS - 2]];
        var placed = 0;
        corners.forEach(function (c) {
          var bx = null, bd = Infinity;
          for (var y = 1; y < ROWS - 1; y++) {
            for (var x = 1; x < COLS - 1; x++) {
              if (g[y][x] !== '.') continue;
              if (!seen[x + ',' + y]) continue;
              var d = Math.abs(x - c[0]) + Math.abs(y - c[1]);
              if (d < bd) { bd = d; bx = [x, y]; }
            }
          }
          if (bx) { g[bx[1]][bx[0]] = 'o'; placed++; }
        });
        if (placed < 4) continue;

        // HARD GUARANTEE: every tile a ghost can actually REACH must have a
        // route back to the house.
        //
        // This is the check that makes generated mazes provably safe rather
        // than merely tested. Without it a board can ship where an eaten
        // ghost's eyes can never get home, and that ghost is gone for the
        // rest of the level — the bug Andrew hit. Note it deliberately tests
        // reachability, not merely "is not a wall": tiles outside the maze
        // proper are unroutable but no ghost can stand on them, and rejecting
        // boards for those would reject every board including the classic.
        var ghostSeen = {}, gq = [[13, 14]];
        ghostSeen['13,14'] = true;
        while (gq.length) {
          var gc = gq.shift();
          var gsteps = [[0, -1], [0, 1], [-1, 0], [1, 0]];
          for (var gi = 0; gi < gsteps.length; gi++) {
            var gx = gc[0] + gsteps[gi][0], gy = gc[1] + gsteps[gi][1];
            if (gx < 0) gx = COLS - 1; else if (gx > COLS - 1) gx = 0;
            if (gy < 0 || gy >= ROWS) continue;
            if (g[gy][gx] === '#') continue;
            var gk = gx + ',' + gy;
            if (ghostSeen[gk]) continue;
            ghostSeen[gk] = true;
            gq.push([gx, gy]);
          }
        }

        // Route home from the door, over the same passability rule.
        var homeDist = {}, hq = [[13, 14]];
        homeDist['13,14'] = 0;
        while (hq.length) {
          var hc = hq.shift(), hd = homeDist[hc[0] + ',' + hc[1]];
          var hsteps = [[0, -1], [0, 1], [-1, 0], [1, 0]];
          for (var hi = 0; hi < hsteps.length; hi++) {
            var hx = hc[0] + hsteps[hi][0], hy = hc[1] + hsteps[hi][1];
            if (hx < 0) hx = COLS - 1; else if (hx > COLS - 1) hx = 0;
            if (hy < 0 || hy >= ROWS) continue;
            if (g[hy][hx] === '#') continue;
            var hk = hx + ',' + hy;
            if (homeDist[hk] !== undefined) continue;
            homeDist[hk] = hd + 1;
            hq.push([hx, hy]);
          }
        }

        var stranded = 0;
        for (var rk in ghostSeen) {
          if (homeDist[rk] === undefined) { stranded++; break; }
        }
        if (stranded > 0) continue;   // reject: eyes could be lost on this board

        // Keep Pac-Man's start free of a pellet so the count is honest.
        g[start[1]][start[0]] = ' ';
        return { grid: g, start: start };
      }
      return null;   // caller falls back to the classic maze
    }

    var canvas = $('canvas');
    var ctx = canvas.getContext('2d');

    var grid, pelletsLeft;

    var startTile = { x: 13, y: 23 };

    function resetMaze() {
      if (level === 1) {
        grid = RAW.map(function (row) { return row.split(''); });
        startTile = { x: 13, y: 23 };
      } else {
        var built = buildMaze(level * 104729);
        if (built) {
          grid = built.grid;
          startTile = { x: built.start[0], y: built.start[1] };
        } else {
          // Generator could not produce a valid board — never ship a broken
          // maze, fall back to the classic one.
          grid = RAW.map(function (row) { return row.split(''); });
          startTile = { x: 13, y: 23 };
        }
      }
      pelletsLeft = 0;
      for (var y = 0; y < ROWS; y++)
        for (var x = 0; x < COLS; x++)
          if (grid[y][x] === '.' || grid[y][x] === 'o') pelletsLeft++;
      levelPellets = pelletsLeft;
      homeRoute = null;
      fruit = null;
      fruitTimer = 0;
      fruitsShown = 0;
    }

    function tileAt(x, y) {
      if (y < 0 || y >= ROWS) return '#';
      if (x < 0 || x >= COLS) return ' ';   // tunnel mouths
      return grid[y][x];
    }
    function isWall(x, y) {
      var t = tileAt(x, y);
      return t === '#' || t === '-';
    }
    // Ghosts may pass the house door; Pac-Man may not.
    function isWallForGhost(x, y) { return tileAt(x, y) === '#'; }

    // ── Entities ──────────────────────────────────────────────────────────────
    var DIRS = {
      up:    { x:  0, y: -1 },
      down:  { x:  0, y:  1 },
      left:  { x: -1, y:  0 },
      right: { x:  1, y:  0 }
    };

    var pac, ghosts, score, high, lives, state, frightTimer, modeTimer, modeIdx, eatChain;
    var fruit, fruitTimer, fruitsShown, flash, levelPellets;

    // ── Speed ─────────────────────────────────────────────────────────────────
    // A single multiplier scales Pac-Man and the ghosts together, so the chase
    // stays balanced at every setting. Base speeds are per-frame tile deltas at
    // 60fps; 1.0 was the original 0.11 (6.6 tiles/sec), which read as frantic.
    // "Normal" is now 0.7 of that.
    //
    // HARD LIMIT: the largest resulting step must stay below centred()'s
    // tolerance (0.15), or an entity can skip over a tile centre entirely and
    // silently lose the ability to turn or eat. Ghosts get a 2.2x boost when
    // returning to the house eaten, so the ceiling is set from that case.
    // Starting difficulty. Each entry is the level-1 multiplier; levels ramp
    // up from whichever is chosen. Andrew's scale: the old "Slow" became the
    // new Normal, so a genuinely slower Slow sits below it.
    var SPEEDS = [
      { key: 'slow',   label: 'S',  title: 'Slow',        mult: 0.30 },
      { key: 'normal', label: 'N',  title: 'Normal',      mult: 0.45 },
      { key: 'fast',   label: 'F',  title: 'Fast',        mult: 0.70 },
      { key: 'faster', label: 'F+', title: 'Faster',      mult: 1.00 },
      { key: 'insane', label: 'I',  title: 'Insane',      mult: 1.30 }
    ];

    // Per-level ramp, tuned so the game becomes unplayable at LEVEL 666 —
    // whichever speed you started on.
    //
    // "Impossible" is defined concretely rather than by feel: at IMPOSSIBLE_TPS
    // tiles per second a tile is crossed in ~83ms, comfortably inside human
    // reaction time (~250ms), so you physically cannot steer at a junction any
    // more. Every starting setting interpolates from its own pace to that same
    // wall over 665 levels, so S is a long gentle climb and I is already
    // most of the way there — but both arrive at 666.
    //
    // The curve is eased (exponent < 1 early, so growth is slowest at the
    // start) rather than linear, so the first few dozen levels barely change
    // and the difficulty gathers in the back half.
    var LEVEL_LAST = 666;
    var IMPOSSIBLE_TPS = 12.0;
    var RAMP_EASE = 1.6;     // >1 = slow early, steeper later
    var level = 1;

    // Multiplier that would put Pac-Man exactly at the impossible threshold.
    function impossibleMult() { return IMPOSSIBLE_TPS / (BASE_PAC * 60); }

    // The multiplier actually in force: the chosen start eased toward the
    // impossible threshold, reaching it at LEVEL_LAST and continuing past it
    // for anyone who somehow gets there.
    function liveMult() {
      var start = SPEEDS[speedIdx].mult;
      var end = impossibleMult();
      if (end <= start) return start * (1 + (level - 1) * 0.001);
      var t = (level - 1) / (LEVEL_LAST - 1);
      if (t > 1) return end * (1 + (t - 1) * 0.5);   // past 666: keep climbing
      return start + (end - start) * Math.pow(t, RAMP_EASE);
    }
    var BASE_PAC = 0.11, BASE_GHOST = 0.085, EATEN_BOOST = 2.2;
    var speedIdx = 1;

    try {
      var saved = localStorage.getItem('w3k-pac-speed');
      for (var si = 0; si < SPEEDS.length; si++)
        if (SPEEDS[si].key === saved) speedIdx = si;
    } catch (e) {}

    function speedMult() { return liveMult(); }

    // How long the ghosts stay edible, in FRAMES.
    //
    // This has to be reasoned about in seconds, not frames: the ghosts cover
    // ground in proportion to the speed multiplier, so a fixed frame count
    // feels generous when slow and gone-in-an-instant when fast. The duration
    // is therefore divided by the live multiplier — at 2x speed they cross the
    // maze twice as fast, so half the time buys the same amount of chase.
    //
    // The result is clamped so it never drops below FRIGHT_MIN_S no matter how
    // fast the level gets: past a certain point the ramp should make ghosts
    // deadly through SPEED, not by making power pellets worthless.
    // 20s at the slow end: at 2 tiles/sec a shorter window barely covers two
    // corridors, so the power pellet was not worth taking. The division by the
    // speed multiplier then walks it down as the game gets faster, and the
    // floor keeps it usable no matter how far the level ramp runs.
    var FRIGHT_MAX_S = 20, FRIGHT_MIN_S = 3;

    function frightFrames() {
      // Scale from the S setting (0.30): at that pace the player gets the full
      // window, and it shortens proportionally as the game speeds up.
      var secs = FRIGHT_MAX_S * (0.30 / speedMult());
      if (secs > FRIGHT_MAX_S) secs = FRIGHT_MAX_S;
      if (secs < FRIGHT_MIN_S) secs = FRIGHT_MIN_S;
      return Math.round(secs * 60);
    }

    function applySpeeds() {
      var m = speedMult();
      if (pac) pac.speed = BASE_PAC * m;
      if (ghosts) ghosts.forEach(function (g) { g.speed = BASE_GHOST * m; });
    }

    function setSpeed(i) {
      speedIdx = Math.max(0, Math.min(SPEEDS.length - 1, i));
      try { localStorage.setItem('w3k-pac-speed', SPEEDS[speedIdx].key); } catch (e) {}
      applySpeeds();
      renderSpeed();
    }

    high = parseInt(localStorage.getItem('w3k-pac-high') || '0', 10) || 0;

    // scatter/chase schedule, in frames at 60fps
    // Arcade scatter/chase schedule, in frames at 60fps (Pac-Man Dossier).
    // Ghosts START in scatter. The long third chase and the one-frame fourth
    // scatter on later levels are genuine arcade behaviour, not a typo.
    var MODE_TABLE = {
      //        scatter chase  scatter chase  scatter chase    scatter chase
      lvl1:   [   420,  1200,   420,  1200,   300,  1200,     300,  1e9 ],
      lvl2_4: [   420,  1200,   420,  1200,   300, 61980,       1,  1e9 ],
      lvl5up: [   300,  1200,   300,  1200,   300, 62220,       1,  1e9 ]
    };

    function modeTable() {
      if (level === 1) return MODE_TABLE.lvl1;
      if (level <= 4) return MODE_TABLE.lvl2_4;
      return MODE_TABLE.lvl5up;
    }

    function newPac() {
      return { x: startTile.x, y: startTile.y, dir: 'left', want: 'left', speed: BASE_PAC * speedMult(), mouth: 0, dead: 0, lastTurnTile: '' };
    }

    function newGhosts() {
      // color, scatter corner, starting tile, and how long it waits in the house
      var defs = [
        { name: 'blinky', color: '#ff5555', sx: 26, sy: -1, x: 13, y: 11, release: 0 },
        { name: 'pinky',  color: '#ff9ed8', sx: 1,  sy: -1, x: 13, y: 14, release: 60 },
        { name: 'inky',   color: '#00c4f0', sx: 26, sy: 31, x: 11, y: 14, release: 240 },
        { name: 'clyde',  color: '#f0a040', sx: 1,  sy: 31, x: 15, y: 14, release: 480 }
      ];
      return defs.map(function (d) {
        return {
          name: d.name, color: d.color, scatterX: d.sx, scatterY: d.sy,
          homeX: d.x, homeY: d.y, x: d.x, y: d.y,
          dir: 'up', speed: BASE_GHOST * speedMult(), frightened: 0, eaten: false, release: d.release, lastTile: '', sigReverse: false, leaving: true
        };
      });
    }

    function resetPositions() {
      pac = newPac();
      ghosts = newGhosts();
      frightTimer = 0; modeTimer = 0; modeIdx = 0; eatChain = 0;
    }

    function newGame() {
      // Only fetch a token if we do not already hold an unspent one. Minting on
      // every restart burned the rate budget for no benefit — the token is
      // consumed at submission, not at game start.
      if (!hsSession) hsStart();
      playClockReset();
      playClockStart();
      level = 1;
      resetMaze(); resetPositions();
      applySpeeds();
      score = 0; lives = 3; state = 'play';
      updateHUD();
    }

    function renderSpeed() {
      var host = $('speedbtns');
      if (!host) return;
      if (!host.firstChild) {
        SPEEDS.forEach(function (sp, i) {
          var b = document.createElement('button');
          b.type = 'button';
          b.className = 'spdbtn';
          b.textContent = sp.label;
          b.title = sp.title + ' — starting speed (levels ramp up from here)';
          b.setAttribute('data-i', i);
          b.addEventListener('click', function () { setSpeed(i); });
          host.appendChild(b);
        });
      }
      Array.prototype.forEach.call(host.children, function (b, i) {
        b.classList.toggle('on', i === speedIdx);
      });
    }

    function updateHUD() {
      var lv = $('level');
      if (lv) lv.textContent = level;
      $('score').textContent = score;
      $('high').textContent = high;
      var lv = $('lives');
      if (lives <= 0) lv.textContent = '—';
      else if (lives <= 6) lv.textContent = '●'.repeat(lives);
      else lv.textContent = '●\u00d7' + lives;   // ●x12 once dots stop being readable
    }

    // ── Movement ──────────────────────────────────────────────────────────────
    // An entity may turn only when it is centred on a tile, which is what makes
    // the movement feel like the original rather than free-roaming.
    // Tolerance must exceed the largest per-frame step, or a fast entity jumps
    // straight over the centre point and never registers as centred — silently
    // losing the ability to turn or eat. It is derived from the current speed
    // rather than hardcoded, so every speed setting stays correct; the worst
    // case is an eaten ghost racing home at EATEN_BOOST.
    // The window must be just wide enough that a moving entity lands inside it
    // on ~one frame per tile — proportional to the step, not a constant.
    //
    // A fixed tolerance breaks at BOTH ends: too small and a fast entity jumps
    // the centre entirely (losing turning and eating); too large and a slow
    // entity sits inside the window for many frames, so the once-per-tile
    // guard latches at the moment it ENTERS the window rather than at the
    // centre, snapping it backwards and stalling it. Scaling with the step
    // keeps the window ~1.2 frames wide at every speed.
    // Sized from the SLOWEST mover, not the fastest.
    //
    // The window has to be narrow enough that even the slowest entity is inside
    // it for about one frame. A frightened ghost moves at FRIGHT_SLOW of normal
    // speed — roughly a third of an eaten ghost's — so sizing the window off the
    // eaten speed made it ~4 frames wide for a frightened one. The once-per-tile
    // guard then latched on the frame it ENTERED the window rather than at the
    // centre, and moveEntity kept clamping it to that tile: the ghost froze
    // solid, and eating it left the eyes stranded there because the same guard
    // blocked every subsequent decision.
    //
    // Sized this way the fastest mover (eaten, EATEN_BOOST) can overshoot the
    // window in one frame, so centred() alone is not enough for it — hence the
    // crossedCentre() fallback below, which catches an entity that stepped OVER
    // a tile centre without ever landing inside the window.
    var FRIGHT_SLOW = 0.62;

    function tolerance() {
      var slowest = BASE_GHOST * FRIGHT_SLOW * speedMult();
      return slowest * 0.6;
    }

    // True when a step from one position to another passed over a tile centre,
    // even if neither end was inside tolerance(). This keeps fast entities
    // honest now that the window is sized for slow ones: an eaten ghost can
    // jump the window in a single frame, and without this it would sail past
    // junctions the same way frightened ghosts used to freeze in them.
    function crossedCentre(from, to) {
      // No movement on this axis means no centre was crossed on it. Returning
      // true for a stationary coordinate that happens to sit on an integer —
      // which is the normal case for the axis an entity is NOT moving along —
      // fired the decision on every frame and re-pinned lastTile forever.
      if (from === to) return false;
      var a = Math.min(from, to), b = Math.max(from, to);
      // A centre lies in (a, b] if the next integer at or above a is <= b.
      return Math.ceil(a) <= b;
    }
    function centred(v) { return Math.abs(v - Math.round(v)) < tolerance(); }

    function canGo(cx, cy, dir, ghost) {
      var d = DIRS[dir];
      var nx = Math.round(cx) + d.x, ny = Math.round(cy) + d.y;
      return ghost ? !isWallForGhost(nx, ny) : !isWall(nx, ny);
    }

    function moveEntity(e, ghost) {
      var d = DIRS[e.dir];
      var speed = e.speed;

      if (ghost && e.frightened > 0 && !e.eaten) speed *= 0.62;
      if (ghost && e.eaten) speed *= 2.2;

      var nx = e.x + d.x * speed, ny = e.y + d.y * speed;

      // Look at the tile being ENTERED — the one ahead of the current tile —
      // not Math.round(nx). Rounding the new position tests whichever tile the
      // entity is merely nearest to, so a wall one tile ahead reads as blocking
      // while the entity is still mid-tile; it then got snapped to a tile
      // centre, advanced again, and snapped again, jittering against every
      // wall instead of stopping. Ghosts stuck for the same reason: canGo()
      // approved a direction that moveEntity then refused to move in.
      var cx = Math.round(e.x), cy = Math.round(e.y);
      var ahead = ghost ? isWallForGhost(cx + d.x, cy + d.y)
                        : isWall(cx + d.x, cy + d.y);

      // Remember the pre-move position so stepGhost/stepPac can tell whether
      // this frame stepped OVER a tile centre without landing inside the
      // centred() window — see crossedCentre().
      e.prevX = e.x; e.prevY = e.y;

      if (ahead) {
        // Advance only as far as this tile's centre, then stop flush.
        var limX = (d.x > 0) ? Math.min(nx, cx) : (d.x < 0 ? Math.max(nx, cx) : nx);
        var limY = (d.y > 0) ? Math.min(ny, cy) : (d.y < 0 ? Math.max(ny, cy) : ny);
        e.x = limX; e.y = limY;
      } else {
        e.x = nx; e.y = ny;
      }

      // Side tunnels wrap. Land ON the far edge column, not outside it: the
      // next frame's wall test looks at round(x)+dir, so arriving at COLS (or
      // -1) aimed the entity straight into the border frame and stranded it.
      if (e.x < 0) e.x = COLS - 1;
      else if (e.x > COLS - 1) e.x = 0;
    }

    // ── High scores ───────────────────────────────────────────────────────────
    // Scores go to the central board on files.w3k.dev. No credential is sent:
    // the server derives which board to write from the Origin header, so a page
    // can only ever write its own site's file. See highscore.go.
    var HS_ENDPOINT = (opts.scoreboard === undefined) ? 'https://files.w3k.dev/_hs' : opts.scoreboard;
    var hsLocal = [], hsGlobal = [], hsBusy = false;

    // Session token for the current run. Fetched when a game starts, spent on
    // submission. The server refuses a score without one, which is what stops
    // a plain curl from landing on the board.
    var hsSession = null;

    // Milliseconds of ACTIVE play in the current run — the clock stops while
    // paused, between levels, and while the name prompt is up. Sent with the
    // score so the server judges the run on time actually spent playing rather
    // than wall-clock, which a long pause would otherwise inflate.
    var playedMs = 0, playedFrom = 0;

    function playClockStart() { if (!playedFrom) playedFrom = Date.now(); }
    function playClockStop() {
      if (playedFrom) { playedMs += Date.now() - playedFrom; playedFrom = 0; }
    }
    function playClockReset() { playedMs = 0; playedFrom = 0; }
    function playedSeconds() {
      var t = playedMs + (playedFrom ? Date.now() - playedFrom : 0);
      return Math.round(t / 1000);
    }

    // Fetch a session token. Returns a promise so a submission can wait for
    // one rather than failing outright — the token is fetched at game start,
    // but a slow network, a page opened before the server was reachable, or a
    // run that spans a token's lifetime must not cost the player their score.
    function hsStart() {
      if (!HS_ENDPOINT) return Promise.resolve(null);
      try {
        return fetch(HS_ENDPOINT + '/start', { method: 'GET', mode: 'cors', credentials: 'omit' })
          .then(function (r) {
            // 429 is "wait", not "offline" — report it distinctly so the
            // player is not told the scoreboard is unreachable when it is
            // merely busy.
            if (r.status === 429) return { busy: true };
            return r.ok ? r.json() : null;
          })
          .then(function (d) {
            if (d && d.busy) return { busy: true };
            if (d && d.nonce) { hsSession = d; return d; }
            return null;
          })
          .catch(function () { return null; });
      } catch (e) { return Promise.resolve(null); }
    }

    function hsFetch() {
      if (!HS_ENDPOINT) return;
      try {
        fetch(HS_ENDPOINT, { method: 'GET', mode: 'cors', credentials: 'omit' })
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (d) {
            if (!d) return;
            hsLocal = d.scores || [];
            hsGlobal = d.global || [];
            renderBoards();
          })
          .catch(function () { /* offline or blocked — boards just stay empty */ });
      } catch (e) {}
    }

    function hsSubmit(name, sc, lvl, spd, done, isRetry) {
      if (hsBusy) return;

      // No token in hand — mint one, then submit. hsTokenMin means a token must
      // be a few seconds old, so this path waits briefly rather than failing.
      if (!hsSession) {
        hsBusy = true;
        hsStart().then(function (d) {
          hsBusy = false;
          if (d && d.busy) {
            done('The scoreboard is busy — wait a moment and press Retry.');
            return;
          }
          if (!d) { done('offline'); return; }
          setTimeout(function () { hsSubmit(name, sc, lvl, spd, done, true); }, 8500);
        });
        return;
      }

      hsBusy = true;
      try {
        fetch(HS_ENDPOINT, {
          method: 'POST',
          mode: 'cors',
          credentials: 'omit',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name, score: sc, level: lvl, speed: spd,
            playedS: playedSeconds(),
            nonce:  hsSession ? hsSession.nonce  : '',
            sig:    hsSession ? hsSession.sig    : '',
            issued: hsSession ? hsSession.issued : 0
          })
        })
          .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
          .then(function (res) {
            hsBusy = false;
            var errText = (res.d && res.d.error) || '';
            var rateLimited = /slow down/i.test(errText);
            var wasSession = !res.ok && /verified/.test(errText);

            // A rate limit is not a session failure. Retrying it spends more
            // budget and deepens the hole, so surface it as something to wait
            // out and KEEP the token — it has not been consumed.
            if (rateLimited) {
              hsBusy = false;
              done('The scoreboard is busy — wait a moment and press Retry.');
              return;
            }

            hsSession = null;   // single-use; next game fetches a new one
            if (wasSession && !isRetry) {
              // Token expired or was already spent — mint a fresh one and try
              // once more so a long game does not lose its score.
              hsSubmit(name, sc, lvl, spd, done, true);
              return;
            }
            if (res.ok) {
              hsLocal = res.d.scores || hsLocal;
              hsGlobal = res.d.global || hsGlobal;
              renderBoards();
              done(null, res.d);
            } else {
              done(res.d && res.d.error ? res.d.error : 'could not save');
            }
          })
          .catch(function (e) { hsBusy = false; done('offline'); });
      } catch (e) { hsBusy = false; done('offline'); }
    }

    // Would this run make the local board?
    function isTopScore(sc) {
      if (sc <= 0) return false;
      if (hsLocal.length < 10) return true;
      return sc > hsLocal[hsLocal.length - 1].score;
    }

    function openBoards() {
      // Refresh on open — the modal is the only place scores are shown now,
      // so it should never display a stale board.
      hsFetch();
      $('hsmodal').classList.add('open');
    }
    // Is the scoreboard modal showing? Escape must close that innermost layer
    // before it means "leave immersive mode".
    function hsModalOpen() {
      return $('hsmodal').classList.contains('open');
    }
    function closeBoards() {
      $('hsmodal').classList.remove('open');
    }

    // ── About ─────────────────────────────────────────────────────────────
    // The build stamps the release into W3K_404_VERSION; see build.py. Shown
    // here so a deployed copy can state which build it is without anyone
    // having to read the source.
    function openAbout() {
      var v = $('abver');
      if (v) v.textContent = 'v' + W3K_404_VERSION;
      var h = $('abhs');
      if (h) {
        h.textContent = HS_ENDPOINT
          ? HS_ENDPOINT.replace(/^https?:\/\//, '').replace(/\/_hs$/, '')
          : 'disabled';
      }
      $('abmodal').classList.add('open');
    }
    function aboutOpen() {
      return $('abmodal').classList.contains('open');
    }
    function closeAbout() {
      $('abmodal').classList.remove('open');
    }

    function renderBoards() {
      renderList($('hslocal'), hsLocal, false);
      renderList($('hsglobal'), hsGlobal, true);
    }

    function renderList(host, rows, showDomain) {
      if (!host) return;
      host.innerHTML = '';
      if (!rows.length) {
        var e = document.createElement('div');
        e.className = 'hs-empty';
        e.textContent = 'no scores yet';
        host.appendChild(e);
        return;
      }
      rows.slice(0, 10).forEach(function (row, i) {
        var li = document.createElement('div');
        li.className = 'hs-row';
        var rank = document.createElement('span'); rank.className = 'hs-rank';
        rank.textContent = (i + 1) + '.';
        var nm = document.createElement('span'); nm.className = 'hs-name';
        // textContent, never innerHTML — these strings come from other players.
        nm.textContent = row.name;
        if (showDomain && row.domain) nm.title = row.domain;
        var sc = document.createElement('span'); sc.className = 'hs-score';
        sc.textContent = row.score;
        li.appendChild(rank); li.appendChild(nm); li.appendChild(sc);
        if (showDomain && row.domain) {
          var dm = document.createElement('span'); dm.className = 'hs-dom';
          dm.textContent = row.domain;
          li.appendChild(dm);
        }
        host.appendChild(li);
      });
    }

    // ── Fruit ─────────────────────────────────────────────────────────────────
    // The arcade shows a bonus item twice per level, under the ghost house.
    // Value climbs with level, so late boards are worth chasing even though
    // they are lethal.
    var FRUITS = [
      { name: 'cherry',     color: '#ff4d4d', stem: '#4ecf98', value: 100 },
      { name: 'strawberry', color: '#ff5d8f', stem: '#4ecf98', value: 300 },
      { name: 'orange',     color: '#ff9b3d', stem: '#4ecf98', value: 500 },
      { name: 'apple',      color: '#e8433f', stem: '#4ecf98', value: 700 },
      { name: 'melon',      color: '#5fd35f', stem: '#4ecf98', value: 1000 },
      { name: 'galaxian',   color: '#5bc8ff', stem: '#f0c000', value: 2000 },
      { name: 'bell',       color: '#f7d94c', stem: '#c4d4e4', value: 3000 },
      { name: 'key',        color: '#9fb4c8', stem: '#f0c000', value: 5000 }
    ];

    function fruitForLevel() {
      return FRUITS[Math.min(level - 1, FRUITS.length - 1)];
    }

    // How long fruit stays on the board, in FRAMES.
    //
    // Same reasoning as frightFrames(): a fixed frame count is a different
    // amount of REACHABLE board at each speed. At 2 tiles/sec the old ~9s was
    // not enough to cross the maze and collect it, so the fruit may as well not
    // have spawned. 40s at the slow end, scaling down as the game speeds up,
    // with a floor so it is always at least briefly gettable.
    var FRUIT_MAX_S = 40, FRUIT_MIN_S = 6;

    function fruitFrames() {
      var secs = FRUIT_MAX_S * (0.30 / speedMult());
      if (secs > FRUIT_MAX_S) secs = FRUIT_MAX_S;
      if (secs < FRUIT_MIN_S) secs = FRUIT_MIN_S;
      return Math.round(secs * 60);
    }

    // Where fruit appears: just below the ghost house, on a real open tile.
    function fruitTile() {
      var wantY = HOUSE_BOT + 2, wantX = 13;
      for (var r = 0; r < 8; r++) {
        for (var dy = -r; dy <= r; dy++) {
          for (var dx = -r; dx <= r; dx++) {
            var x = wantX + dx, y = wantY + dy;
            if (y < 1 || y >= ROWS - 1 || x < 1 || x >= COLS - 1) continue;
            var t = grid[y][x];
            if (t === '#' || t === '-') continue;
            if (y >= HOUSE_TOP && y <= HOUSE_BOT && x >= HOUSE_L && x <= HOUSE_R) continue;
            return { x: x, y: y };
          }
        }
      }
      return null;
    }

    // Two appearances per level, at 70 and 30 pellets remaining — the same
    // cadence as the original.
    function maybeSpawnFruit(totalPellets) {
      var eaten = totalPellets - pelletsLeft;
      var marks = [Math.round(totalPellets * 0.30), Math.round(totalPellets * 0.65)];
      if (fruitsShown < marks.length && eaten >= marks[fruitsShown]) {
        fruitsShown++;
        var t = fruitTile();
        if (t) {
          // Each fruit within a level is worth double the one before it, so
          // the second appearance is the one worth chasing. fruitsShown was
          // already incremented above, hence the -1.
          var base = fruitForLevel();
          var mult = Math.pow(2, fruitsShown - 1);
          fruit = {
            x: t.x, y: t.y,
            def: { name: base.name, color: base.color, stem: base.stem,
                   value: base.value * mult }
          };
          fruitTimer = fruitFrames();
        }
      }
    }

    function stepFruit() {
      if (!fruit) return;
      if (--fruitTimer <= 0) { fruit = null; return; }
      if (Math.abs(pac.x - fruit.x) < 0.7 && Math.abs(pac.y - fruit.y) < 0.7) {
        score += fruit.def.value;
        flash = { text: '+' + fruit.def.value, x: fruit.x, y: fruit.y, t: 70 };
        fruit = null;
        updateHUD();
      }
    }

    function stepPac() {
      if (pac.dead) return;
      // Honour a queued turn as soon as it becomes legal.
      // Snap to the centre only when actually changing direction, and only
      // once per tile — snapping every centred frame would cancel out the
      // movement accumulated inside the centred window.
      var pacTile = Math.round(pac.x) + ',' + Math.round(pac.y);
      var pacAtTile = (centred(pac.x) && centred(pac.y)) ||
                      (pac.prevX !== undefined &&
                       (crossedCentre(pac.prevX, pac.x) || crossedCentre(pac.prevY, pac.y)));
      var pacWedged = pac.prevX !== undefined && pac.prevX === pac.x && pac.prevY === pac.y;
      if (pac.want !== pac.dir && pacAtTile
          && (pacWedged || pac.lastTurnTile !== pacTile)
          && canGo(pac.x, pac.y, pac.want, false)) {
        pac.lastTurnTile = pacTile;
        pac.dir = pac.want;
        pac.x = Math.round(pac.x); pac.y = Math.round(pac.y);
      }
      moveEntity(pac, false);
      pac.mouth += 0.22 * (speedMult() / 0.7);

      // Eat every tile PASSED THROUGH this frame, not just the one Pac-Man
      // happens to be centred on.
      //
      // Gating this on centred() meant he had to land inside a window only
      // ~0.57 frames wide, so he skipped roughly half the pellets he ran over
      // — visibly passing straight across dots. Sweeping the tiles between the
      // previous position and the current one makes eating exact at any speed,
      // and it cannot miss however fast the level ramp gets.
      var fromX = (pac.prevX === undefined) ? pac.x : pac.prevX;
      var fromY = (pac.prevY === undefined) ? pac.y : pac.prevY;
      var t0x = Math.round(fromX), t0y = Math.round(fromY);
      var t1x = Math.round(pac.x), t1y = Math.round(pac.y);

      var sweep = [];
      if (t0x === t1x && t0y === t1y) {
        sweep.push([t1x, t1y]);
      } else if (t0y === t1y) {
        var stepX = t1x > t0x ? 1 : -1;
        // A tunnel wrap jumps the whole width; only the landing tile counts.
        if (Math.abs(t1x - t0x) > 2) sweep.push([t1x, t1y]);
        else for (var sx = t0x; sx !== t1x + stepX; sx += stepX) sweep.push([sx, t1y]);
      } else if (t0x === t1x) {
        var stepY = t1y > t0y ? 1 : -1;
        for (var sy = t0y; sy !== t1y + stepY; sy += stepY) sweep.push([t1x, sy]);
      } else {
        sweep.push([t0x, t0y]);
        sweep.push([t1x, t1y]);
      }

      for (var si = 0; si < sweep.length; si++) {
        eatTile(sweep[si][0], sweep[si][1]);
      }
    }

    // Consume whatever sits on one tile. Split out of stepPac so the sweep
    // above can apply it to every tile crossed in a frame.
    function eatTile(tx, ty) {
      if (ty >= 0 && ty < ROWS && tx >= 0 && tx < COLS) {
        var t = grid[ty][tx];
        if (t === '.') { grid[ty][tx] = ' '; score += 10; pelletsLeft--; updateHUD(); }
        else if (t === 'o') {
          grid[ty][tx] = ' '; score += 50; pelletsLeft--; eatChain = 0;
          var frightLen = frightFrames();
          frightTimer = frightLen;
          ghosts.forEach(function (g) { if (!g.eaten) { g.frightened = frightLen; g.sigReverse = true; } });
          updateHUD();
        }
        if (pelletsLeft <= 0) nextLevel();
      }
    }

    function reverse(d) {
      return d === 'up' ? 'down' : d === 'down' ? 'up' : d === 'left' ? 'right' : 'left';
    }

    // Ghost targeting — the part that makes them feel individual rather than
    // four copies chasing the same tile.
    // True while the ghost is still inside the house box. The door only spans
    // x=13..14, so a ghost parked at x=11 or x=15 sits under solid wall and can
    // never leave while it is chasing Pac-Man — it has to aim for the door
    // first. Without this, Inky and Clyde jitter in the house forever.
    // True while a ghost is still working its way out of the house.
    //
    // This is a LATCHED state, not a position test, and that matters. A pure
    // zone check oscillates on its own boundary: a ghost one pixel above the
    // zone is judged "out", re-targets a scatter corner that may lie back
    // below, turns around, re-enters the zone, targets the exit again, and
    // bounces there forever. That is exactly what pinned Inky and Clyde in a
    // two-tile pocket above the door on generated mazes.
    //
    // Instead the ghost is marked as leaving when it starts inside the box, and
    // the flag is cleared once — permanently for that trip — when it gets
    // clearly above the door. Being re-eaten sets it again via resetPositions
    // and the eaten branch.
    function inHouseZone(g) {
      return g.y >= 11 && g.y <= 15 && g.x >= 10 && g.x <= 17;
    }

    function inHouse(g) {
      if (g.leaving === undefined) g.leaving = inHouseZone(g);

      if (g.leaving) {
        // Cleared the door and the corridor above it. Latching this OFF (rather
        // than re-testing position) is what stops a ghost oscillating on the
        // zone boundary: one pixel above the zone it would be judged "out",
        // take a scatter target that may lie back below, turn around, re-enter,
        // and bounce there forever.
        if (g.y <= 9.5) g.leaving = false;
      } else if (inHouseZone(g)) {
        // Back inside the box — either eyes that just arrived, or a ghost that
        // re-entered. It must run the exit routine again, otherwise it takes a
        // scatter target it cannot reach through the walls and mills about
        // inside. This re-arm was missing and pinned Inky and Clyde in the box
        // on generated boards.
        g.leaving = true;
      }
      return g.leaving;
    }

    // ── Route home for eaten ghosts ───────────────────────────────────────────
    // Greedy "step toward the target" is how the arcade steers LIVE ghosts, and
    // it is correct there: a chasing ghost has no destination it is obliged to
    // reach, so orbiting the player is acceptable behaviour. Eyes are the
    // opposite — they MUST arrive, or the ghost never respawns.
    //
    // With greedy steering they frequently did not: in a maze region where every
    // non-reversing move increases distance to the house, the eyes loop forever
    // (observed: 20,4 -> 24,7 -> 18,5 -> 20,2 -> 24,5 -> 18,7 -> ... indefinitely).
    // So eyes get a real shortest path instead: a BFS from the house over the
    // ghost-passable grid, giving every tile its next hop. Computed once per
    // maze and cached, since the grid does not change during a level.
    var homeRoute = null, homeRouteKey = '';

    function buildHomeRoute() {
      var key = level + ':' + ROWS + 'x' + COLS;
      if (homeRoute && homeRouteKey === key) return homeRoute;

      var HX = 13, HY = 14;
      var dist = {};
      var q = [[HX, HY]];
      dist[HX + ',' + HY] = 0;

      // Flood out from the house across every tile a ghost may occupy. Ghosts
      // ignore the door, so isWallForGhost is the right passability test.
      while (q.length) {
        var c = q.shift(), cx = c[0], cy = c[1], d = dist[cx + ',' + cy];
        var steps = [[0, -1], [0, 1], [-1, 0], [1, 0]];
        for (var i = 0; i < steps.length; i++) {
          var nx = cx + steps[i][0], ny = cy + steps[i][1];
          // Honour the side tunnels so eyes can route through them.
          if (nx < 0) nx = COLS - 1;
          else if (nx > COLS - 1) nx = 0;
          if (ny < 0 || ny >= ROWS) continue;
          if (isWallForGhost(nx, ny)) continue;
          var k = nx + ',' + ny;
          if (dist[k] !== undefined) continue;
          dist[k] = d + 1;
          q.push([nx, ny]);
        }
      }

      homeRoute = dist;
      homeRouteKey = key;
      return homeRoute;
    }

    // The direction from (x,y) that most reduces BFS distance to the house.
    // Returns null when the tile is unreachable, in which case the caller falls
    // back to greedy targeting rather than freezing.
    function homeStep(x, y) {
      var route = buildHomeRoute();
      var here = route[x + ',' + y];
      var best = null, bestD = (here === undefined) ? Infinity : here;
      ['up', 'down', 'left', 'right'].forEach(function (d) {
        var dd = DIRS[d];
        var nx = x + dd.x, ny = y + dd.y;
        if (nx < 0) nx = COLS - 1; else if (nx > COLS - 1) nx = 0;
        if (ny < 0 || ny >= ROWS) return;
        var v = route[nx + ',' + ny];
        if (v !== undefined && v < bestD) { bestD = v; best = d; }
      });
      return best;
    }

    function ghostTarget(g) {
      if (g.eaten) return { x: 13, y: 14 };                    // back to the house
      // Leaving the house is a TWO-STAGE trip, because the door only spans
      // x=13..14 while ghosts start at x=11, 13 and 15. A single target
      // straight up aims the corner ghosts into the box wall, and they grind
      // there — Inky and Clyde never left on generated mazes.
      //
      // Stage 1: get under the door. Stage 2: go up through it.
      if (inHouse(g)) {
        if (g.y > 12.5 && Math.abs(g.x - 13.5) > 0.8) {
          return { x: 13.5, y: g.y };    // slide sideways to the doorway first
        }
        return { x: 13, y: 9 };          // then straight up and out
      }
      var scatter = (modeIdx % 2 === 0);
      if (scatter) return { x: g.scatterX, y: g.scatterY };

      var pd = DIRS[pac.dir];
      if (g.name === 'blinky') return { x: pac.x, y: pac.y };

      if (g.name === 'pinky') {
        // The original's overflow bug: aiming UP also shifts the target 4
        // tiles LEFT. Faithfully reproduced — it is why Pinky can be dodged
        // by facing up, and the game plays differently without it.
        var qx = pac.x + pd.x * 4, qy = pac.y + pd.y * 4;
        if (pac.dir === 'up') qx -= 4;
        return { x: qx, y: qy };
      }

      if (g.name === 'inky') {
        // Inky doubles the vector from Blinky through a point 2 ahead of
        // Pac-Man — and inherits the same up-overflow bug.
        var b = ghosts[0];
        var px = pac.x + pd.x * 2, py = pac.y + pd.y * 2;
        if (pac.dir === 'up') px -= 2;
        return { x: px + (px - b.x), y: py + (py - b.y) };
      }
      // clyde: chases until close, then bolts for his corner
      // Measured from one tile AHEAD of Clyde, and compared squared (64 = 8^2).
      var cd = DIRS[g.dir] || { x: 0, y: 0 };
      var cdx = pac.x - (g.x + cd.x), cdy = pac.y - (g.y + cd.y);
      return (cdx * cdx + cdy * cdy) >= 64
        ? { x: pac.x, y: pac.y }
        : { x: g.scatterX, y: g.scatterY };
    }

    function stepGhost(g) {
      if (g.release > 0) { g.release--; return; }

      if (g.frightened > 0) g.frightened--;
      if (g.eaten && Math.abs(g.x - 13) < 0.6 && Math.abs(g.y - 14) < 0.6) {
        g.eaten = false; g.frightened = 0;
      }

      // Decide once per TILE, not once per centred frame. centred() spans a
      // window either side of the centre, so re-deciding (and re-snapping to
      // the centre) on every frame inside that window pinned each ghost in
      // place, flip-flopping between two choices and never accumulating any
      // movement — they vibrated instead of roaming.
      var tileKey = Math.round(g.x) + ',' + Math.round(g.y);
      var atTile = (centred(g.x) && centred(g.y)) ||
                   (g.prevX !== undefined &&
                    (crossedCentre(g.prevX, g.x) || crossedCentre(g.prevY, g.y)));

      // A ghost that did not move this frame is wedged against a wall: its
      // current heading is blocked. The once-per-tile guard must NOT apply
      // then, or it can never pick a new direction and stays there forever —
      // and if it is eaten in that state the eyes are stranded too, because
      // the same guard blocks every later decision. This was the last of the
      // stuck-ghost cases: flush against a wall, facing into it, already
      // "decided" for this tile.
      var wedged = g.prevX !== undefined && g.prevX === g.x && g.prevY === g.y;

      if (atTile && (wedged || g.lastTile !== tileKey)) {
        g.lastTile = tileKey;
        g.x = Math.round(g.x); g.y = Math.round(g.y);

        // A queued reversal is applied HERE, at a tile centre, never the
        // moment it is signalled. Reversing mid-tile leaves an entity off the
        // grid, which is its own way of stranding it.
        if (g.sigReverse) { g.dir = reverse(g.dir); g.sigReverse = false; }
        var house = inHouse(g);
        var opts = ['up', 'down', 'left', 'right'].filter(function (d) {
          // No doubling back in the maze proper — but inside the house a ghost
          // may need to reverse to line up with the door.
          if (!house && d === reverse(g.dir)) return false;
          return canGo(g.x, g.y, d, true);
        });
        if (!opts.length) opts = [reverse(g.dir)];

        if (g.eaten && !house) {
          // Eyes follow the precomputed shortest route home. Fall back to the
          // greedy choice only if this tile is somehow unreachable.
          var hs = homeStep(Math.round(g.x), Math.round(g.y));
          if (hs && canGo(g.x, g.y, hs, true)) {
            g.dir = hs;
          } else {
            var t0 = ghostTarget(g), b0 = null, bd0 = Infinity;
            ['up', 'left', 'down', 'right'].forEach(function (d) {
              if (opts.indexOf(d) === -1) return;
              var dd = DIRS[d];
              var ex0 = (g.x + dd.x) - t0.x, ey0 = (g.y + dd.y) - t0.y;
              var dist0 = ex0 * ex0 + ey0 * ey0;
              if (dist0 < bd0) { bd0 = dist0; b0 = d; }
            });
            g.dir = b0 || g.dir;
          }
        } else if (g.frightened > 0 && !g.eaten && !house) {
          g.dir = opts[Math.floor(Math.random() * opts.length)];
        } else {
          // Squared Euclidean, no sqrt — and iterate in up > left > down >
          // right order with a strict <, so the arcade's tie-break falls out
          // of the ordering instead of needing its own code.
          var t = ghostTarget(g), best = null, bestD = Infinity;
          ['up', 'left', 'down', 'right'].forEach(function (d) {
            if (opts.indexOf(d) === -1) return;
            var dd = DIRS[d];
            var ex = (g.x + dd.x) - t.x, ey = (g.y + dd.y) - t.y;
            var dist = ex * ex + ey * ey;
            if (dist < bestD) { bestD = dist; best = d; }
          });
          g.dir = best || g.dir;
        }
      }
      moveEntity(g, true);
    }

    function collide() {
      ghosts.forEach(function (g) {
        if (g.release > 0 || g.eaten) return;
        if (Math.hypot(g.x - pac.x, g.y - pac.y) < 0.7) {
          if (g.frightened > 0) {
            g.eaten = true; g.frightened = 0;
            eatChain++;
            score += 200 * Math.pow(2, Math.min(eatChain - 1, 3));
            updateHUD();
          } else if (!pac.dead) {
            pac.dead = 1;
          }
        }
      });
    }

    function loseLife() {
      lives--; updateHUD();
      if (lives <= 0) { gameOver(); return; }
      resetPositions();
      state = 'play';
    }

    function saveHigh() {
      if (score > high) {
        high = score; updateHUD();
        try { localStorage.setItem('w3k-pac-high', String(high)); } catch (e) {}
      }
    }

    function gameOver() {
      playClockStop();
      state = 'over'; saveHigh();
      if (isTopScore(score)) {
        showNameEntry();
      } else {
        showOverlay('GAME OVER', 'lose',
          'The ghosts win this round. Your files are still safe at the root.', 'Try again');
      }
    }

    // Name prompt, shown only when the run actually places. The name is kept
    // in localStorage so a returning player does not retype it.
    function showNameEntry() {
      var t = $('ovtitle');
      t.textContent = 'TOP SCORE — ' + score; t.className = 'win';
      $('ovtext').textContent =
        'Level ' + level + '. Enter a name for the board (3-13 characters).';
      $('ovbtn').textContent = 'Submit';
      $('ovname').style.display = '';
      $('overr').textContent = '';
      var inp = $('ovinput');
      try { inp.value = localStorage.getItem('w3k-pac-name') || ''; } catch (e) { inp.value = ''; }
      $('overlay').classList.remove('hide');
      setTimeout(function () { inp.focus(); inp.select(); }, 30);
      state = 'naming';
    }

    function submitName() {
      var inp = $('ovinput');
      var err = $('overr');
      var nm = (inp.value || '').trim();
      if (nm.length < 3 || nm.length > 13) {
        err.textContent = 'Name must be 3-13 characters.';
        inp.focus();
        return;
      }
      try { localStorage.setItem('w3k-pac-name', nm); } catch (e) {}
      err.textContent = 'saving\u2026';
      hsSubmit(nm, score, level, SPEEDS[speedIdx].label, function (e, d) {
        if (e) {
          // Never lose the player's run to a network hiccup — let them retry
          // or walk away, and say plainly what happened.
          err.textContent = (e === 'offline')
            ? 'Could not reach the scoreboard. Your score is still shown here.'
            : e;
          $('ovbtn').textContent = 'Retry';
          return;
        }
        $('ovname').style.display = 'none';
        showOverlay('RANK #' + (d.rank || '?'), 'win',
          nm + ' \u2014 ' + score + ' points, level ' + level + '.', 'Play again');
        state = 'over';
      });
    }
    // Board cleared: advance. There is no final level — each one is a tick
    // faster than the last, so it eventually becomes unplayable by design.
    function nextLevel() {
      playClockStop();

      // A life for every board cleared. Uncapped on purpose: the speed ramp
      // is the thing that ends a run, not attrition, and banking lives is
      // what makes a deep run possible at all.
      lives++;
      level++;
      state = 'levelup';
      saveHigh();
      showOverlay('LEVEL ' + level, 'win',
        'Maze cleared — extra life earned. A new layout, and a little faster.',
        'Continue');
    }

    function startLevel() {
      // Refresh the session so a long run always submits with a recent token.
      if (!hsSession) hsStart();
      playClockStart();
      resetMaze();
      resetPositions();
      applySpeeds();
      updateHUD();
      state = 'play';
    }

    var overlay = $('overlay');
    function showOverlay(title, cls, text, btn) {
      var t = $('ovtitle');
      t.textContent = title; t.className = cls || '';
      $('ovtext').textContent = text;
      $('ovbtn').textContent = btn;
      overlay.classList.remove('hide');
    }
    function hideOverlay() { overlay.classList.add('hide'); }

    // ── Phone fullscreen ──────────────────────────────────────────────────────
    // On a phone the board is a small part of a tall screen. Hitting Play
    // promotes the container to a viewport-filling overlay and the canvas
    // scales up with it.
    //
    // This is CSS-only sizing on purpose. The canvas keeps its intrinsic
    // 448x496 coordinate space and the browser scales the rendered result, so
    // every tile position, speed and collision test is byte-identical to the
    // windowed game. Touching canvas.width here would rescale the game's own
    // geometry and silently break movement.
    //
    // The container differs per build: the embeddable build wraps the markup in
    // the mount (.w3kpac), the standalone page puts it in <main>. The stage's
    // parent is the right element in both, so it is derived rather than hunted
    // for by selector.
    var fsRoot = canvas.closest ? canvas.closest('.stage').parentElement : null;
    var fsOn = false;
    var fsSurface = null;
    var fsOrder = null;

    function fsAvailable() {
      // Everything except a genuinely tiny or non-visual context. A phone gets
      // an edge-to-edge screen and a desktop a centred modal; which one is
      // pure CSS. Both exist for the same reason: the board is a fraction of
      // the viewport inside a host's content column.
      return !!fsRoot && !!window.matchMedia;
    }

    // The desktop modal needs a sized surface to float over the backdrop, but
    // the windowed layout must not gain a wrapper it does not use. So the
    // surface is created on entry and unwrapped on exit, leaving the original
    // DOM byte-identical — a markup-level wrapper would have changed the
    // HUD/stage/overlay nesting that the windowed CSS depends on.
    function wrapSurface() {
      if (fsSurface) return;
      fsSurface = document.createElement('div');
      fsSurface.className = 'fs-surface';
      // Remember the ORIGINAL child order so exit can rebuild it exactly.
      // Reinserting "everything before the surface" is not the same thing:
      // the exit button is deliberately left on the root (it pins to the
      // viewport corner, not the modal), so a naive unwrap moved every other
      // node behind it and the mount came back subtly reordered.
      fsOrder = [];
      for (var i = 0; i < fsRoot.childNodes.length; i++) {
        fsOrder.push(fsRoot.childNodes[i]);
      }
      // On a phone the game IS the screen, so the ✕ stays on the root and pins
      // to the viewport corner. On desktop the game is a card, so the ✕ goes
      // INSIDE the surface — in the viewport corner it reads as unrelated
      // page chrome a long way from the thing it closes.
      var card = window.matchMedia('(min-width: 821px), (pointer: fine)').matches;
      for (var j = 0; j < fsOrder.length; j++) {
        var n = fsOrder[j];
        if (!card && n.nodeType === 1 && n.classList &&
            n.classList.contains('fs-exit')) continue;
        fsSurface.appendChild(n);
      }
      fsRoot.appendChild(fsSurface);
    }

    function unwrapSurface() {
      if (!fsSurface) return;
      if (fsSurface.parentNode) fsSurface.parentNode.removeChild(fsSurface);
      // Replay the recorded order, so the mount is byte-identical to how the
      // host rendered it. Verified by structural fingerprint before/after.
      for (var i = 0; i < fsOrder.length; i++) {
        fsRoot.appendChild(fsOrder[i]);
      }
      fsSurface = null;
      fsOrder = null;
    }

    function enterFs() {
      if (fsOn || !fsAvailable()) return;
      fsOn = true;
      wrapSurface();
      applyFsScheme(fsScheme());
      fsRoot.classList.add('is-fs');
      document.documentElement.classList.add('w3kpac-fs-lock');
      document.body.classList.add('w3kpac-fs-lock');
      requestAnimationFrame(function () { window.scrollTo(0, 0); });
    }

    function exitFs() {
      if (!fsOn) return;
      fsOn = false;
      clearFsScheme();
      fsRoot.classList.remove('is-fs');
      document.documentElement.classList.remove('w3kpac-fs-lock');
      document.body.classList.remove('w3kpac-fs-lock');
      unwrapSurface();
    }

    // Leaving immersive mode mid-run must never cost a life, so both the ✕ and
    // Escape run the same sequence the P key uses. Stopping the play clock
    // before changing state matters: it feeds the anti-cheat elapsed window,
    // and paused time must not count as played.
    function leaveImmersive() {
      exitFs();
      if (state === 'play') {
        playClockStop();
        state = 'pause';
        showOverlay('PAUSED', '', 'Take your time.', 'Resume');
      }
    }

    // Clicking the dimmed area outside the card closes it, as any modal
    // should. Bound on the root and guarded on target === root so a click
    // that lands on the board or HUD never counts.
    if (fsRoot) {
      fsRoot.addEventListener('click', function (e) {
        if (!fsOn) return;
        if (e.target !== fsRoot) return;
        leaveImmersive();
      });
    }

    var thmBtn = $('thmbtn');
    if (thmBtn) {
      thmBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        applyFsScheme(fsScheme() === 'dark' ? 'light' : 'dark');
      });
    }

    var fsExitBtn = $('fsexit');
    if (fsExitBtn) {
      fsExitBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        leaveImmersive();
      });
    }

    $('ovbtn').addEventListener('click', function () {
      if (state === 'naming') { submitName(); return; }
      hideOverlay();
      $('ovname').style.display = 'none';
      // A run is starting or resuming: take the whole screen on a phone.
      enterFs();
      if (state === 'levelup') startLevel();
      else if (state === 'pause') { playClockStart(); state = 'play'; }
      else newGame();
    });

    // ── Render ────────────────────────────────────────────────────────────────
    function draw() {
      ctx.fillStyle = PAL.board;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Shade the walkable corridors so the path reads distinctly from the
      // walls rather than being bare page background. Purely cosmetic — this
      // is a fill in draw() and touches no positions, collision or state.
      for (var cy = 0; cy < ROWS; cy++) {
        for (var cx = 0; cx < COLS; cx++) {
          if (grid[cy][cx] === '#') continue;
          ctx.fillStyle = PAL.path;
          ctx.fillRect(cx * TILE, cy * TILE, TILE, TILE);
        }
      }

      for (var y = 0; y < ROWS; y++) {
        for (var x = 0; x < COLS; x++) {
          var t = grid[y][x], px = x * TILE, py = y * TILE;
          if (t === '#') {
            // Rounded wall block in the w3K accent, slightly inset so the maze
            // reads as connected tubes rather than a solid mass.
            // Draw walls as thin edges facing the open corridors, the way the
            // original does — a filled block per wall tile makes the WALLS the
            // dominant shape and the maze reads inside-out.
            ctx.strokeStyle = PAL.wall;
            ctx.lineWidth = 2;
            ctx.beginPath();
            if (!isWall(x, y - 1)) { ctx.moveTo(px, py + 1); ctx.lineTo(px + TILE, py + 1); }
            if (!isWall(x, y + 1)) { ctx.moveTo(px, py + TILE - 1); ctx.lineTo(px + TILE, py + TILE - 1); }
            if (!isWall(x - 1, y)) { ctx.moveTo(px + 1, py); ctx.lineTo(px + 1, py + TILE); }
            if (!isWall(x + 1, y)) { ctx.moveTo(px + TILE - 1, py); ctx.lineTo(px + TILE - 1, py + TILE); }
            ctx.stroke();
          } else if (t === '-') {
            ctx.fillStyle = PAL.door;
            ctx.fillRect(px + 1, py + TILE / 2 - 1, TILE - 2, 2);
          } else if (t === '.') {
            ctx.fillStyle = PAL.pellet;
            ctx.fillRect(px + TILE / 2 - 1.5, py + TILE / 2 - 1.5, 3, 3);
          } else if (t === 'o') {
            ctx.fillStyle = PAL.power;
            ctx.beginPath();
            ctx.arc(px + TILE / 2, py + TILE / 2, 4.5, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }

      // Fruit — a simple two-tone berry so every entry is legible at 16px
      // without shipping sprite assets.
      if (fruit) {
        var fx = fruit.x * TILE + TILE / 2, fy = fruit.y * TILE + TILE / 2;
        ctx.fillStyle = fruit.def.color;
        ctx.beginPath();
        ctx.arc(fx - 2.4, fy + 2, 4.1, 0, Math.PI * 2);
        ctx.arc(fx + 2.4, fy + 2, 4.1, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = fruit.def.stem;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(fx, fy + 1);
        ctx.lineTo(fx + 2, fy - 5.5);
        ctx.stroke();
      }

      // Floating score from a collected fruit.
      if (flash) {
        ctx.fillStyle = PAL.flash;
        ctx.font = 'bold 11px monospace';
        ctx.textAlign = 'center';
        ctx.globalAlpha = Math.max(0, Math.min(1, flash.t / 40));
        ctx.fillText(flash.text, flash.x * TILE + TILE / 2,
                     flash.y * TILE + TILE / 2 - (70 - flash.t) * 0.18);
        ctx.globalAlpha = 1;
        ctx.textAlign = 'left';
      }

      // Pac-Man
      var cx = pac.x * TILE + TILE / 2, cy = pac.y * TILE + TILE / 2;
      var base = { up: -Math.PI / 2, down: Math.PI / 2, left: Math.PI, right: 0 }[pac.dir];
      var gap = pac.dead ? 0.9 : Math.abs(Math.sin(pac.mouth)) * 0.32;
      ctx.fillStyle = '#f0c000';
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, TILE / 2 - 1, base + gap, base - gap + Math.PI * 2);
      ctx.closePath();
      ctx.fill();

      // Ghosts
      ghosts.forEach(function (g) {
        var gx = g.x * TILE + TILE / 2, gy = g.y * TILE + TILE / 2, r = TILE / 2 - 1;
        if (g.eaten) {
          drawEyes(gx, gy, g.dir);
          return;
        }
        var body = g.color;
        if (g.frightened > 0) {
          // flash white in the last second so the player knows time is up
          // Arcade frightened blue and its end-of-timer white flash: fixed on
          // purpose, these read as "edible" to anyone who has played Pac-Man.
          body = (g.frightened < frightFrames() * 0.3 && Math.floor(g.frightened / 8) % 2) ? '#ffffff' : '#2a3f8f';
        }
        ctx.fillStyle = body;
        ctx.beginPath();
        ctx.arc(gx, gy - 1, r, Math.PI, 0);
        ctx.lineTo(gx + r, gy + r - 1);
        // skirt
        for (var i = 0; i < 3; i++) {
          ctx.lineTo(gx + r - (i * 2 + 1) * (r / 3), gy + r - 1 - (i % 2 ? 0 : 3));
        }
        ctx.lineTo(gx - r, gy + r - 1);
        ctx.closePath();
        ctx.fill();
        if (g.frightened > 0) {
          ctx.fillStyle = '#fff';
          ctx.fillRect(gx - 3.5, gy - 2, 2, 2);
          ctx.fillRect(gx + 1.5, gy - 2, 2, 2);
        } else {
          drawEyes(gx, gy, g.dir);
        }
      });
    }

    function drawEyes(gx, gy, dir) {
      var d = DIRS[dir] || DIRS.left;
      [-3.2, 3.2].forEach(function (off) {
        ctx.fillStyle = '#fff';
        ctx.beginPath(); ctx.arc(gx + off, gy - 2, 2.6, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#1a2340';   // pupil: stays dark against the white eye
        ctx.beginPath(); ctx.arc(gx + off + d.x * 1.1, gy - 2 + d.y * 1.1, 1.3, 0, Math.PI * 2); ctx.fill();
      });
    }

    // ── Loop ──────────────────────────────────────────────────────────────────
    function tick() {
      if (state === 'play') {
        if (pac.dead) {
          pac.dead++;
          if (pac.dead > 70) loseLife();
        } else {
          stepPac();
          ghosts.forEach(stepGhost);
          collide();
          maybeSpawnFruit(levelPellets);
          stepFruit();
          if (flash && --flash.t <= 0) flash = null;
          if (frightTimer > 0) frightTimer--;
          // The scatter/chase clock STOPS while an energizer is active — arcade
          // behaviour, and it noticeably changes how the board feels after a
          // power pellet. A mode change also reverses every ghost.
          if (frightTimer <= 0) {
            var tbl = modeTable();
            modeTimer++;
            if (modeTimer > tbl[modeIdx]) {
              modeTimer = 0;
              modeIdx = Math.min(modeIdx + 1, tbl.length - 1);
              ghosts.forEach(function (g) { if (!g.eaten) g.sigReverse = true; });
            }
          }
        }
      }
      draw();
      if (!stopped) rafId = requestAnimationFrame(tick);
    }

    // ── Input ─────────────────────────────────────────────────────────────────
    var KEYS = {
      ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right',
      w: 'up', a: 'left', s: 'down', d: 'right',
      W: 'up', A: 'left', S: 'down', D: 'right'
    };
    function onKey(e) {
      if (e.key === 'Escape') {
        // The scoreboard modal is the innermost layer, so it closes first and
        // only then does Escape mean "leave immersive mode". Checking fsOn
        // before this line made Escape skip the board entirely.
        if (aboutOpen()) { closeAbout(); return; }
        if (hsModalOpen()) { closeBoards(); return; }
        if (fsOn) { e.preventDefault(); leaveImmersive(); return; }
        closeBoards();
        return;
      }

      // While a text field is focused every key belongs to it — otherwise
      // typing "WASD" into a name steers Pac-Man and "p" pauses the game.
      var ae = document.activeElement;
      if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA')) return;
      if (state === 'naming') return;

      if (e.key === 'p' || e.key === 'P') {
        if (state === 'play') { playClockStop(); state = 'pause'; showOverlay('PAUSED', '', 'Take your time.', 'Resume'); }
        else if (state === 'pause') { hideOverlay(); playClockStart(); state = 'play'; }
        return;
      }
      if (e.key === '[') { setSpeed(speedIdx - 1); return; }
      if (e.key === ']') { setSpeed(speedIdx + 1); return; }
      var d = KEYS[e.key];
      if (!d) return;
      // Swallow arrows whenever the game owns the screen, not only while
      // state === 'play'. Gating on 'play' alone meant that dying, changing
      // level or pausing handed the arrow keys back to the page mid-session
      // and it lurched up and down under the player — the "scroll sticking".
      // Outside immersive mode the old rule still holds, so a windowed game
      // the visitor has not started never traps their scrolling.
      if (fsOn || state === 'play') e.preventDefault();
      pac.want = d;
    }
    window.addEventListener('keydown', onKey);

    // Swipe
    var t0 = null;
    canvas.addEventListener('touchstart', function (e) {
      t0 = e.changedTouches[0];
    }, { passive: true });
    canvas.addEventListener('touchend', function (e) {
      if (!t0) return;
      var t1 = e.changedTouches[0];
      var dx = t1.clientX - t0.clientX, dy = t1.clientY - t0.clientY;
      if (Math.abs(dx) < 18 && Math.abs(dy) < 18) return;
      pac.want = Math.abs(dx) > Math.abs(dy)
        ? (dx > 0 ? 'right' : 'left')
        : (dy > 0 ? 'down' : 'up');
      t0 = null;
    }, { passive: true });

    // ── Start ─────────────────────────────────────────────────────────────────
    var inpEl = $('ovinput');
    if (inpEl) inpEl.addEventListener('keydown', function (e) {
      // Enter submits; the key must not reach the game's movement handler.
      if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); submitName(); }
      e.stopPropagation();
    });

    // Bound here rather than via inline onclick: everything in this file is
    // scoped inside the IIFE, so an inline handler cannot see these names.
    var abBtnEl = $('abbtn');
    if (abBtnEl) abBtnEl.addEventListener('click', openAbout);
    var abCloseEl = $('abclose');
    if (abCloseEl) abCloseEl.addEventListener('click', closeAbout);
    var abModalEl = $('abmodal');
    if (abModalEl) abModalEl.addEventListener('click', function (e) {
      if (e.target === abModalEl) closeAbout();
    });

    var rafId = 0;
    var hsBtnEl = $('hsbtn');
    if (hsBtnEl) hsBtnEl.addEventListener('click', openBoards);
    var hsCloseEl = $('hsclose');
    if (hsCloseEl) hsCloseEl.addEventListener('click', closeBoards);
    var hsModalEl = $('hsmodal');
    if (hsModalEl) hsModalEl.addEventListener('click', function (e) {
      if (e.target === hsModalEl) closeBoards();
    });

    hsFetch();
    newGame();
    renderSpeed();
    state = 'idle';          // wait behind the overlay until Play is pressed
    updateHUD();
    tick();

    return function teardown() {
      stopped = true;
      if (rafId) cancelAnimationFrame(rafId);
      window.removeEventListener('keydown', onKey);
    };
  }

  root.w3kPacman404 = w3kPacman404;
  if (typeof module !== 'undefined' && module.exports) module.exports = w3kPacman404;

  // Auto-mount for <script src="w3k-pacman-404.js" data-auto>
  try {
    var cur = document.currentScript;
    var auto = (cur && cur.hasAttribute && cur.hasAttribute('data-auto')) ||
               document.querySelector('script[data-auto][src*="w3k-pacman-404"]');
    if (auto) {
      if (document.readyState === 'loading')
        document.addEventListener('DOMContentLoaded', function () { w3kPacman404(); });
      else w3kPacman404();
    }
  } catch (e) { /* non-DOM context: ignore */ }

})(typeof window !== 'undefined' ? window : this);
