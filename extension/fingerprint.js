// Claude Gateway — fingerprint normaliser (runs in the page's MAIN world, document_start).
//
// Makes the page see a "clean" neutral browser profile regardless of the real machine:
//   * time zone  -> UTC           (Date, Intl, toLocale*String)
//   * language   -> en-US         (navigator.language(s), Intl default locale, toLocale*)
//   * geolocation-> permission denied (never reveals a position)
//   * WebRTC     -> removed        (cannot leak local / real IP addresses)
//
// Honest limits (also documented in SECURITY.md): this covers the page and same-origin
// frames, NOT Web/Service Workers, and it cannot hide your IP (the gateway does that).
(function () {
  "use strict";

  var TZ = "UTC";
  var LOCALE = "en-US";
  var LANGS = ["en-US", "en"];

  var defineProperty = Object.defineProperty;
  var apply = Reflect.apply;

  // ------------------------------------------------ keep patched fns looking native
  var nativeSrc = new WeakMap();
  var origFnToString = Function.prototype.toString;
  var fakeFnToString = function toString() {
    var s = nativeSrc.get(this);
    return s !== undefined ? s : apply(origFnToString, this, []);
  };
  nativeSrc.set(fakeFnToString, "function toString() { [native code] }");
  defineProperty(Function.prototype, "toString", { value: fakeFnToString, writable: true, configurable: true });

  function native(fn, name) {
    nativeSrc.set(fn, "function " + name + "() { [native code] }");
    return fn;
  }
  function patch(obj, name, value) {
    if (!obj) return;
    var d = Object.getOwnPropertyDescriptor(obj, name);
    if (!d || !d.configurable) return;
    defineProperty(obj, name, { value: native(value, name), writable: d.writable, enumerable: d.enumerable, configurable: true });
  }
  function patchGetter(obj, name, getter) {
    if (!obj) return;
    var d = Object.getOwnPropertyDescriptor(obj, name);
    if (!d || !d.configurable) return;
    defineProperty(obj, name, { get: native(getter, "get " + name), set: undefined, enumerable: d.enumerable, configurable: true });
  }

  // ------------------------------------------------------------------- language
  var NavProto = typeof Navigator !== "undefined" ? Navigator.prototype : null;
  patchGetter(NavProto, "language", function () { return LOCALE; });
  patchGetter(NavProto, "languages", function () { return LANGS.slice(); });

  function loc(l) { return l === undefined ? LOCALE : l; }
  function withTz(o) {
    if (o === undefined || o === null) return { timeZone: TZ };
    if (typeof o !== "object") return o;
    if (o.timeZone !== undefined) return o;
    return Object.assign({}, o, { timeZone: TZ });
  }

  // Intl constructors: default locale -> en-US (and default timeZone -> UTC for DateTimeFormat)
  ["DateTimeFormat", "NumberFormat", "Collator", "PluralRules", "RelativeTimeFormat",
    "ListFormat", "Segmenter", "DisplayNames", "DurationFormat"].forEach(function (name) {
    var Orig = typeof Intl !== "undefined" && Intl[name];
    if (typeof Orig !== "function") return;
    function fix(args) {
      var a = Array.prototype.slice.call(args);
      a[0] = loc(a[0]);
      if (name === "DateTimeFormat") a[1] = withTz(a[1]);
      return a;
    }
    var P = new Proxy(Orig, {
      construct: function (t, a, nt) { return Reflect.construct(t, fix(a), nt === P ? t : nt); },
      apply: function (t, th, a) { return apply(t, th, fix(a)); }
    });
    defineProperty(Intl, name, { value: P, writable: true, configurable: true, enumerable: false });
    defineProperty(Orig.prototype, "constructor", { value: P, writable: true, configurable: true });
  });

  // toLocale*String and friends
  var DP = Date.prototype;
  ["toLocaleString", "toLocaleDateString", "toLocaleTimeString"].forEach(function (n) {
    var o = DP[n];
    patch(DP, n, function (l, opt) { return apply(o, this, [loc(l), withTz(opt)]); });
  });
  (function () {
    var o = Number.prototype.toLocaleString;
    patch(Number.prototype, "toLocaleString", function (l, opt) { return apply(o, this, [loc(l), opt]); });
    if (typeof BigInt !== "undefined") {
      var ob = BigInt.prototype.toLocaleString;
      patch(BigInt.prototype, "toLocaleString", function (l, opt) { return apply(ob, this, [loc(l), opt]); });
    }
    var oc = String.prototype.localeCompare;
    patch(String.prototype, "localeCompare", function (that, l, opt) { return apply(oc, this, [that, loc(l), opt]); });
    var ou = String.prototype.toLocaleUpperCase, ol = String.prototype.toLocaleLowerCase;
    patch(String.prototype, "toLocaleUpperCase", function (l) { return apply(ou, this, [loc(l)]); });
    patch(String.prototype, "toLocaleLowerCase", function (l) { return apply(ol, this, [loc(l)]); });
    patch(Array.prototype, "toLocaleString", function (l, opt) {
      return Array.prototype.map.call(this, function (x) { return x == null ? "" : x.toLocaleString(l, opt); }).join(",");
    });
  })();

  // ------------------------------------------------------------------- time zone
  var getters = {
    getFullYear: "getUTCFullYear", getMonth: "getUTCMonth", getDate: "getUTCDate", getDay: "getUTCDay",
    getHours: "getUTCHours", getMinutes: "getUTCMinutes", getSeconds: "getUTCSeconds", getMilliseconds: "getUTCMilliseconds"
  };
  Object.keys(getters).forEach(function (k) {
    var u = DP[getters[k]];
    patch(DP, k, function () { return apply(u, this, []); });
  });
  var uYear = DP.getUTCFullYear;
  patch(DP, "getYear", function () { return apply(uYear, this, []) - 1900; });
  patch(DP, "getTimezoneOffset", function () { var t = this.getTime(); return t !== t ? NaN : 0; });

  var setters = {
    setFullYear: "setUTCFullYear", setMonth: "setUTCMonth", setDate: "setUTCDate",
    setHours: "setUTCHours", setMinutes: "setUTCMinutes", setSeconds: "setUTCSeconds", setMilliseconds: "setUTCMilliseconds"
  };
  Object.keys(setters).forEach(function (k) {
    var u = DP[setters[k]];
    patch(DP, k, function () { return apply(u, this, arguments); });
  });

  var toUTC = DP.toUTCString;
  var TZ_NAME = "GMT+0000 (Coordinated Universal Time)";
  function parts(d) {                       // "Thu, 08 Oct 2026 12:00:00 GMT"
    var s = apply(toUTC, d, []);
    if (s === "Invalid Date") return null;
    var m = /^(\w+), (\d+) (\w+) (-?\d+) (\d\d:\d\d:\d\d) GMT$/.exec(s);
    return m ? { wd: m[1], d: m[2], mon: m[3], y: m[4], t: m[5] } : null;
  }
  patch(DP, "toString", function () { var p = parts(this); return p ? p.wd + " " + p.mon + " " + p.d + " " + p.y + " " + p.t + " " + TZ_NAME : "Invalid Date"; });
  patch(DP, "toDateString", function () { var p = parts(this); return p ? p.wd + " " + p.mon + " " + p.d + " " + p.y : "Invalid Date"; });
  patch(DP, "toTimeString", function () { var p = parts(this); return p ? p.t + " " + TZ_NAME : "Invalid Date"; });

  // `new Date(y, m, ...)` and zone-less ISO strings are "local time" -> treat as UTC
  var OrigDate = Date;
  var ISO_LOCAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;
  function fixDateArgs(a) {
    if (a.length >= 2) {
      var allNum = true;
      for (var i = 0; i < a.length; i++) if (typeof a[i] === "symbol") allNum = false;
      return allNum ? [apply(OrigDate.UTC, OrigDate, a)] : a;
    }
    if (a.length === 1 && typeof a[0] === "string" && ISO_LOCAL.test(a[0])) return [a[0] + "Z"];
    return a;
  }
  var DateProxy = new Proxy(OrigDate, {
    construct: function (t, a, nt) { return Reflect.construct(t, fixDateArgs(a), nt === DateProxy ? t : nt); },
    apply: function () { return apply(DP.toString, new OrigDate(), []); }
  });
  var origParse = OrigDate.parse;
  patch(OrigDate, "parse", function (s) { return apply(origParse, OrigDate, [typeof s === "string" && ISO_LOCAL.test(s) ? s + "Z" : s]); });
  defineProperty(DP, "constructor", { value: DateProxy, writable: true, configurable: true });
  try { defineProperty(window, "Date", { value: DateProxy, writable: true, configurable: true, enumerable: false }); } catch (e) { /* ignore */ }

  // ----------------------------------------------------------------- geolocation
  function denied() {
    return { code: 1, message: "User denied Geolocation", PERMISSION_DENIED: 1, POSITION_UNAVAILABLE: 2, TIMEOUT: 3 };
  }
  if (typeof Geolocation !== "undefined") {
    patch(Geolocation.prototype, "getCurrentPosition", function (ok, err) {
      if (typeof err === "function") setTimeout(function () { err(denied()); }, 0);
    });
    var wid = 0;
    patch(Geolocation.prototype, "watchPosition", function (ok, err) {
      if (typeof err === "function") setTimeout(function () { err(denied()); }, 0);
      return ++wid;
    });
    patch(Geolocation.prototype, "clearWatch", function () {});
  }
  if (typeof Permissions !== "undefined") {
    var oq = Permissions.prototype.query;
    patch(Permissions.prototype, "query", function (desc) {
      var p = apply(oq, this, arguments);
      if (desc && desc.name === "geolocation") {
        return p.then(function (st) { try { defineProperty(st, "state", { value: "denied" }); } catch (e) { /* ignore */ } return st; });
      }
      return p;
    });
  }

  // ---------------------------------------------------------------------- WebRTC
  ["RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection", "RTCSessionDescription", "RTCIceCandidate"].forEach(function (n) {
    try { delete window[n]; } catch (e) { /* ignore */ }
  });
})();
