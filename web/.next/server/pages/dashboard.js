(() => {
  var e = {};
  ((e.id = 26),
    (e.ids = [26, 888, 660]),
    (e.modules = {
      6558: (e, r) => {
        "use strict";
        Object.defineProperty(r, "l", {
          enumerable: !0,
          get: function () {
            return function e(r, t) {
              return t in r
                ? r[t]
                : "then" in r && "function" == typeof r.then
                  ? r.then((r) => e(r, t))
                  : "function" == typeof r && "default" === t
                    ? r
                    : void 0;
            };
          },
        });
      },
      5669: (e, r, t) => {
        "use strict";
        (t.r(r),
          t.d(r, {
            config: () => x,
            default: () => b,
            getServerSideProps: () => S,
            getStaticPaths: () => P,
            getStaticProps: () => h,
            reportWebVitals: () => y,
            routeModule: () => k,
            unstable_getServerProps: () => _,
            unstable_getServerSideProps: () => A,
            unstable_getStaticParams: () => w,
            unstable_getStaticPaths: () => v,
            unstable_getStaticProps: () => j,
          }));
        var n = {};
        (t.r(n), t.d(n, { default: () => m }));
        var i = t(9513),
          a = t(276),
          s = t(6558),
          o = t(7172),
          l = t.n(o),
          d = t(2017),
          u = t(997),
          c = t(6689),
          p = t(5177);
        function g() {
          let e = (0, p.h)(),
            [r, t] = (0, c.useState)(""),
            [n, i] = (0, c.useState)(null),
            [a, s] = (0, c.useState)(!1);
          async function o() {
            if (r.trim()) {
              s(!0);
              try {
                let t = await e.post("/voice/command", { text: r });
                i(t);
              } catch (e) {
                i({ error: e instanceof Error ? e.message : String(e) });
              } finally {
                s(!1);
              }
            }
          }
          return (0, u.jsxs)("div", {
            style: {
              marginTop: "2rem",
              padding: "1rem",
              borderRadius: "12px",
              background: "#0b0b12",
            },
            children: [
              u.jsx("h3", {
                style: { marginTop: 0 },
                children: "Voice / Command Input",
              }),
              u.jsx("textarea", {
                value: r,
                onChange: (e) => t(e.target.value),
                rows: 3,
                style: {
                  width: "100%",
                  borderRadius: "8px",
                  padding: "0.6rem",
                  background: "#111",
                  color: "#fff",
                  border: "1px solid #222",
                },
              }),
              u.jsx("button", {
                onClick: o,
                disabled: a,
                style: {
                  marginTop: "0.8rem",
                  padding: "0.6rem 1.2rem",
                  borderRadius: "999px",
                  background: "linear-gradient(135deg,#ffcc33,#ff3366)",
                  fontWeight: 600,
                  color: "#050509",
                  border: "none",
                  cursor: "pointer",
                },
                children: a ? "Sending…" : "Send to AI",
              }),
              n &&
                u.jsx("pre", {
                  style: {
                    marginTop: "1rem",
                    padding: "1rem",
                    background: "#111",
                    borderRadius: "8px",
                    fontSize: "0.85rem",
                  },
                  children: JSON.stringify(n, null, 2),
                }),
            ],
          });
        }
        var f = t(7716);
        function m() {
          let [e, r] = (0, c.useState)(null),
            [t, n] = (0, c.useState)(!0);
          return (0, u.jsxs)("main", {
            style: { padding: "2rem" },
            children: [
              u.jsx("h1", {
                style: { fontSize: "2rem" },
                children: "Control Tower",
              }),
              t && u.jsx("p", { children: "Loading status…" }),
              !t &&
                u.jsx("pre", {
                  style: {
                    background: "#0b0b12",
                    padding: "1rem",
                    borderRadius: "12px",
                    border: "1px solid rgba(255,255,255,0.05)",
                  },
                  children: JSON.stringify(e, null, 2),
                }),
              u.jsx(g, {}),
              u.jsx(f.m, {}),
            ],
          });
        }
        let b = (0, s.l)(n, "default"),
          h = (0, s.l)(n, "getStaticProps"),
          P = (0, s.l)(n, "getStaticPaths"),
          S = (0, s.l)(n, "getServerSideProps"),
          x = (0, s.l)(n, "config"),
          y = (0, s.l)(n, "reportWebVitals"),
          j = (0, s.l)(n, "unstable_getStaticProps"),
          v = (0, s.l)(n, "unstable_getStaticPaths"),
          w = (0, s.l)(n, "unstable_getStaticParams"),
          _ = (0, s.l)(n, "unstable_getServerProps"),
          A = (0, s.l)(n, "unstable_getServerSideProps"),
          k = new i.PagesRouteModule({
            definition: {
              kind: a.x.PAGES,
              page: "/dashboard",
              pathname: "/dashboard",
              bundlePath: "",
              filename: "",
            },
            components: { App: d.default, Document: l() },
            userland: n,
          });
      },
      7716: (e, r, t) => {
        "use strict";
        t.d(r, { m: () => s });
        var n = t(997),
          i = t(6689),
          a = t(5177);
        function s() {
          let e = (0, a.h)(),
            [r, t] = (0, i.useState)(null),
            [s, o] = (0, i.useState)(null);
          async function l() {
            let r = await e.post("/billing/stripe/session");
            (t(r.sessionId), r.url && (window.location.href = r.url));
          }
          async function d() {
            let r = await e.post("/billing/paypal/order");
            (o(r.orderId),
              r.approvalUrl && (window.location.href = r.approvalUrl));
          }
          return (0, n.jsxs)("div", {
            style: {
              marginTop: "2rem",
              padding: "1rem",
              borderRadius: "12px",
              background: "#0b0b12",
            },
            children: [
              n.jsx("h3", { children: "Billing" }),
              n.jsx("button", {
                onClick: l,
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
              n.jsx("button", {
                onClick: d,
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
              r &&
                (0, n.jsxs)("p", {
                  style: { marginTop: "1rem" },
                  children: ["Stripe session: ", r],
                }),
              s &&
                (0, n.jsxs)("p", {
                  style: { marginTop: "0.5rem" },
                  children: ["PayPal order: ", s],
                }),
            ],
          });
        }
      },
      5177: (e, r, t) => {
        "use strict";
        function n() {
          let e = process.env.NEXT_PUBLIC_API_BASE || "/api";
          return {
            get: async function (r) {
              let t = await fetch(e + r, { headers: {} });
              if (!t.ok) throw Error(await t.text());
              return t.json();
            },
            post: async function (r, t) {
              let n = await fetch(e + r, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: t ? JSON.stringify(t) : void 0,
              });
              if (!n.ok) throw Error(await n.text());
              return n.json();
            },
          };
        }
        t.d(r, { h: () => n });
      },
      2017: (e, r, t) => {
        "use strict";
        (t.r(r), t.d(r, { default: () => i }));
        var n = t(997);
        function i({ Component: e, pageProps: r }) {
          return n.jsx("div", {
            style: {
              fontFamily: "system-ui, -apple-system, BlinkMacSystemFont",
            },
            children: n.jsx(e, { ...r }),
          });
        }
        t(8047);
      },
      8047: () => {},
      276: (e, r) => {
        "use strict";
        var t;
        (Object.defineProperty(r, "x", {
          enumerable: !0,
          get: function () {
            return t;
          },
        }),
          (function (e) {
            ((e.PAGES = "PAGES"),
              (e.PAGES_API = "PAGES_API"),
              (e.APP_PAGE = "APP_PAGE"),
              (e.APP_ROUTE = "APP_ROUTE"));
          })(t || (t = {})));
      },
      2785: (e) => {
        "use strict";
        e.exports = require("next/dist/compiled/next-server/pages.runtime.prod.js");
      },
      6689: (e) => {
        "use strict";
        e.exports = require("react");
      },
      997: (e) => {
        "use strict";
        e.exports = require("react/jsx-runtime");
      },
      5315: (e) => {
        "use strict";
        e.exports = require("path");
      },
    }));
  var r = require("../webpack-runtime.js");
  r.C(e);
  var t = (e) => r((r.s = e)),
    n = r.X(0, [172], () => t(5669));
  module.exports = n;
})();
