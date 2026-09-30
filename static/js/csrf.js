/**
 * static/js/csrf.js
 *
 * Flask-WTF's CSRFProtect rejects every POST/PUT/PATCH/DELETE that
 * doesn't carry a valid CSRF token — including AJAX/fetch calls made by
 * the app's own JS, which is why "semua POST tidak bisa berfungsi"
 * after CSRFProtect was turned on.
 *
 * Fix: read the token from the <meta name="csrf-token"> tag (must be
 * present in base.html — see the head snippet below) and attach it as
 * the X-CSRFToken header on every same-origin, state-changing request.
 * This is the exact pattern documented by Flask-WTF for AJAX:
 * https://flask-wtf.readthedocs.io/en/latest/csrf/
 *
 * Implemented as a global patch of window.fetch (and XMLHttpRequest, for
 * safety in case any code path still uses raw XHR / jQuery-style $.ajax)
 * so NONE of the existing per-page JS files
 * (dynamic_forms.js, decoder_builder.js, etc.) need to be edited
 * individually. Load this script before all other page scripts:
 *
 *   <head>
 *     ...
 *     <meta name="csrf-token" content="{{ csrf_token() }}">
 *   </head>
 *   <body>
 *     ...
 *     <script src="{{ url_for('static', filename='js/csrf.js') }}"></script>
 *     <script src="{{ url_for('static', filename='js/dynamic_forms.js') }}"></script>
 *     ... (all other page scripts AFTER csrf.js)
 *   </body>
 */
(function () {
  'use strict';

  var CSRF_HEADER = 'X-CSRFToken';
  var UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

  function getToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : null;
  }

  function isUnsafe(method) {
    return UNSAFE_METHODS.indexOf((method || 'GET').toUpperCase()) !== -1;
  }

  // A request is "same-origin" if it has no scheme/host of its own
  // (relative path) or its resolved URL's origin matches window.location.
  // We only ever want to attach the token to requests going back to this
  // app — never to a third-party URL, which would leak the token.
  function isSameOrigin(url) {
    try {
      var resolved = new URL(url, window.location.href);
      return resolved.origin === window.location.origin;
    } catch (e) {
      // Relative/malformed URLs that the URL() constructor still choked
      // on are exceedingly rare in practice; treat as same-origin rather
      // than silently dropping the CSRF header on a legitimate app call.
      return true;
    }
  }

  // ── fetch() ────────────────────────────────────────────────────────
  if (window.fetch) {
    var originalFetch = window.fetch;
    window.fetch = function (input, init) {
      init = init || {};
      var method = init.method || (input && input.method) || 'GET';
      var url = typeof input === 'string' ? input : (input && input.url) || '';

      if (isUnsafe(method) && isSameOrigin(url)) {
        var token = getToken();
        if (token) {
          // Normalise headers into a real Headers instance so we can
          // safely add ours without clobbering whatever the caller
          // already set (Headers object, plain object, or array form
          // are all valid inputs to init.headers).
          var headers = new Headers(init.headers || {});
          if (!headers.has(CSRF_HEADER)) {
            headers.set(CSRF_HEADER, token);
          }
          init = Object.assign({}, init, { headers: headers });
        }
      }
      return originalFetch.call(this, input, init);
    };
  }

  // ── XMLHttpRequest ────────────────────────────────────────────────
  // Defensive coverage in case any code (jQuery $.ajax, older inline
  // scripts) issues requests via XHR instead of fetch.
  if (window.XMLHttpRequest) {
    var originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__csrfMethod = method;
      this.__csrfUrl = url;
      return originalOpen.apply(this, arguments);
    };

    var originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function (body) {
      if (isUnsafe(this.__csrfMethod) && isSameOrigin(this.__csrfUrl)) {
        var token = getToken();
        if (token) {
          this.setRequestHeader(CSRF_HEADER, token);
        }
      }
      return originalSend.apply(this, arguments);
    };
  }
})();