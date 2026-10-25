/* catch-the-thief beacon: collects automation tells in the page.
 * Sends nothing personal: no keystroke contents, no field values, only counts
 * and timings. Include with <script src="/_ctt/beacon.js" defer></script>. */
(function () {
  if (window.__ctt) return; window.__ctt = 1;
  var EP = '/_ctt/b';
  var t0 = performance.now(), keys = 0, moves = 0, clicks = 0, untrusted = 0, fills = 0, touch = 0;
  var lastKey = -1e9;

  function env() {
    var n = navigator, s = {};
    s.webdriver = !!n.webdriver;
    s.headlessUA = /Headless/i.test(n.userAgent);
    s.zeroOuter = window.outerWidth === 0 || window.outerHeight === 0;
    s.langs = (n.languages || []).length;
    // When an automation tool has the DevTools Runtime domain enabled, logging an
    // Error serialises it and touches its stack getter.
    var cdp = false;
    try {
      var e = new Error();
      Object.defineProperty(e, 'stack', { configurable: true, get: function () { cdp = true; return ''; } });
      console.debug(e);
    } catch (_) {}
    s.cdp = cdp;
    return s;
  }

  function payload(kind) {
    return JSON.stringify({ k: kind, env: env(), dt: Math.round(performance.now() - t0),
      keys: keys, moves: moves, clicks: clicks, untrusted: untrusted, fills: fills, touch: touch,
      path: location.pathname });
  }

  function send(kind) {
    return fetch(EP, { method: 'POST', body: payload(kind), credentials: 'same-origin', keepalive: true,
      headers: { 'Content-Type': 'application/json' } }).catch(function () {});
  }

  var o = { capture: true, passive: true };
  addEventListener('keydown', function (e) { keys++; lastKey = performance.now(); if (!e.isTrusted) untrusted++; }, o);
  addEventListener('mousemove', function (e) { moves++; if (!e.isTrusted) untrusted++; }, o);
  addEventListener('touchstart', function () { touch++; }, o);
  addEventListener('click', function (e) { clicks++; if (!e.isTrusted) untrusted++; }, o);
  addEventListener('input', function (e) {
    // a value changed with no key pressed just before it: pasted, autofilled or injected
    if (performance.now() - lastKey > 150 && e.inputType !== 'insertFromPaste') fills++;
    if (!e.isTrusted) untrusted++;
  }, o);

  addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || f.dataset.cttSent) return;
    e.preventDefault();
    f.dataset.cttSent = '1';
    var sub = e.submitter;
    send('submit').then(function () {
      if (f.requestSubmit) f.requestSubmit(sub && sub.form === f ? sub : undefined); else f.submit();
    });
  }, true);

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { send('load'); });
  else send('load');
})();
