(self.webpackChunk_N_E = self.webpackChunk_N_E || []).push([
  [67],
  {
    7504: function (e, n, t) {
      "use strict";
      var r, o;
      e.exports =
        (null == (r = t.g.process) ? void 0 : r.env) &&
        "object" == typeof (null == (o = t.g.process) ? void 0 : o.env)
          ? t.g.process
          : t(2170);
    },
    7490: function (e, n, t) {
      (window.__NEXT_P = window.__NEXT_P || []).push([
        "/billing",
        function () {
          return t(7318);
        },
      ]);
    },
    8006: function (e, n, t) {
      "use strict";
      t.d(n, {
        m: function () {
          return u;
        },
      });
      var r = t(5250),
        o = t(79),
        i = t(7805);
      function u() {
        let e = (0, i.h)(),
          [n, t] = (0, o.useState)(null),
          [u, c] = (0, o.useState)(null);
        async function s() {
          let n = await e.post("/billing/stripe/session");
          (t(n.sessionId), n.url && (window.location.href = n.url));
        }
        async function a() {
          let n = await e.post("/billing/paypal/order");
          (c(n.orderId),
            n.approvalUrl && (window.location.href = n.approvalUrl));
        }
        return (0, r.jsxs)("div", {
          style: {
            marginTop: "2rem",
            padding: "1rem",
            borderRadius: "12px",
            background: "#0b0b12",
          },
          children: [
            (0, r.jsx)("h3", { children: "Billing" }),
            (0, r.jsx)("button", {
              onClick: s,
              style: {
                padding: "0.6rem 1.2rem",
                borderRadius: "999px",
                background: "linear-gradient(135deg,#a1e3ff,#2eefff)",
                color: "#050509",
                border: "none",
                fontWeight: 600,
                cursor: "pointer",
              },
              children: "Purchase w/ Stripe",
            }),
            (0, r.jsx)("button", {
              onClick: a,
              style: {
                marginLeft: "1rem",
                padding: "0.6rem 1.2rem",
                borderRadius: "999px",
                background: "linear-gradient(135deg,#ffe600,#ffad00)",
                color: "#050509",
                border: "none",
                fontWeight: 600,
                cursor: "pointer",
              },
              children: "Purchase w/ PayPal",
            }),
            n &&
              (0, r.jsxs)("p", {
                style: { marginTop: "1rem" },
                children: ["Stripe session: ", n],
              }),
            u &&
              (0, r.jsxs)("p", {
                style: { marginTop: "0.5rem" },
                children: ["PayPal order: ", u],
              }),
          ],
        });
      }
    },
    7805: function (e, n, t) {
      "use strict";
      t.d(n, {
        h: function () {
          return o;
        },
      });
      var r = t(7504);
      function o() {
        let e = r.env.NEXT_PUBLIC_API_BASE || "/api";
        function n(e) {
          let n = { ...(e || {}) };
          {
            let e = window.localStorage.getItem("authToken");
            e && (n.Authorization = "Bearer ".concat(e));
          }
          return n;
        }
        return {
          get: async function (t) {
            let r = await fetch(e + t, { headers: n() });
            if (!r.ok) throw Error(await r.text());
            return r.json();
          },
          post: async function (t, r) {
            let o = await fetch(e + t, {
              method: "POST",
              headers: n({ "Content-Type": "application/json" }),
              body: r ? JSON.stringify(r) : void 0,
            });
            if (!o.ok) throw Error(await o.text());
            return o.json();
          },
        };
      }
    },
    7318: function (e, n, t) {
      "use strict";
      (t.r(n),
        t.d(n, {
          default: function () {
            return i;
          },
        }));
      var r = t(5250),
        o = t(8006);
      function i() {
        return (0, r.jsxs)("main", {
          style: { padding: "2rem" },
          children: [
            (0, r.jsx)("h1", { children: "Billing" }),
            (0, r.jsx)(o.m, {}),
          ],
        });
      }
    },
    2170: function (e) {
      !(function () {
        var n = {
            229: function (e) {
              var n,
                t,
                r,
                o = (e.exports = {});
              function i() {
                throw Error("setTimeout has not been defined");
              }
              function u() {
                throw Error("clearTimeout has not been defined");
              }
              function c(e) {
                if (n === setTimeout) return setTimeout(e, 0);
                if ((n === i || !n) && setTimeout)
                  return ((n = setTimeout), setTimeout(e, 0));
                try {
                  return n(e, 0);
                } catch (t) {
                  try {
                    return n.call(null, e, 0);
                  } catch (t) {
                    return n.call(this, e, 0);
                  }
                }
              }
              !(function () {
                try {
                  n = "function" == typeof setTimeout ? setTimeout : i;
                } catch (e) {
                  n = i;
                }
                try {
                  t = "function" == typeof clearTimeout ? clearTimeout : u;
                } catch (e) {
                  t = u;
                }
              })();
              var s = [],
                a = !1,
                l = -1;
              function f() {
                a &&
                  r &&
                  ((a = !1),
                  r.length ? (s = r.concat(s)) : (l = -1),
                  s.length && d());
              }
              function d() {
                if (!a) {
                  var e = c(f);
                  a = !0;
                  for (var n = s.length; n; ) {
                    for (r = s, s = []; ++l < n; ) r && r[l].run();
                    ((l = -1), (n = s.length));
                  }
                  ((r = null),
                    (a = !1),
                    (function (e) {
                      if (t === clearTimeout) return clearTimeout(e);
                      if ((t === u || !t) && clearTimeout)
                        return ((t = clearTimeout), clearTimeout(e));
                      try {
                        t(e);
                      } catch (n) {
                        try {
                          return t.call(null, e);
                        } catch (n) {
                          return t.call(this, e);
                        }
                      }
                    })(e));
                }
              }
              function p(e, n) {
                ((this.fun = e), (this.array = n));
              }
              function h() {}
              ((o.nextTick = function (e) {
                var n = Array(arguments.length - 1);
                if (arguments.length > 1)
                  for (var t = 1; t < arguments.length; t++)
                    n[t - 1] = arguments[t];
                (s.push(new p(e, n)), 1 !== s.length || a || c(d));
              }),
                (p.prototype.run = function () {
                  this.fun.apply(null, this.array);
                }),
                (o.title = "browser"),
                (o.browser = !0),
                (o.env = {}),
                (o.argv = []),
                (o.version = ""),
                (o.versions = {}),
                (o.on = h),
                (o.addListener = h),
                (o.once = h),
                (o.off = h),
                (o.removeListener = h),
                (o.removeAllListeners = h),
                (o.emit = h),
                (o.prependListener = h),
                (o.prependOnceListener = h),
                (o.listeners = function (e) {
                  return [];
                }),
                (o.binding = function (e) {
                  throw Error("process.binding is not supported");
                }),
                (o.cwd = function () {
                  return "/";
                }),
                (o.chdir = function (e) {
                  throw Error("process.chdir is not supported");
                }),
                (o.umask = function () {
                  return 0;
                }));
            },
          },
          t = {};
        function r(e) {
          var o = t[e];
          if (void 0 !== o) return o.exports;
          var i = (t[e] = { exports: {} }),
            u = !0;
          try {
            (n[e](i, i.exports, r), (u = !1));
          } finally {
            u && delete t[e];
          }
          return i.exports;
        }
        r.ab = "//";
        var o = r(229);
        e.exports = o;
      })();
    },
  },
  function (e) {
    (e.O(0, [888, 774, 179], function () {
      return e((e.s = 7490));
    }),
      (_N_E = e.O()));
  },
]);
