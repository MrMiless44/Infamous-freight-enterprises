(() => {
  var e = {};
  ((e.id = 67),
    (e.ids = [67, 888, 660]),
    (e.modules = {
      6558: (e, t) => {
        "use strict";
        Object.defineProperty(t, "l", {
          enumerable: !0,
          get: function () {
            return function e(t, r) {
              return r in t
                ? t[r]
                : "then" in t && "function" == typeof t.then
                  ? t.then((t) => e(t, r))
                  : "function" == typeof t && "default" === r
                    ? t
                    : void 0;
            };
          },
        });
      },
      4163: (e, t, r) => {
        "use strict";
        (r.r(t),
          r.d(t, {
            config: () => m,
            default: () => f,
            getServerSideProps: () => h,
            getStaticPaths: () => P,
            getStaticProps: () => g,
            reportWebVitals: () => b,
            routeModule: () => _,
            unstable_getServerProps: () => v,
            unstable_getServerSideProps: () => j,
            unstable_getStaticParams: () => y,
            unstable_getStaticPaths: () => x,
            unstable_getStaticProps: () => S,
          }));
        var n = {};
        (r.r(n), r.d(n, { default: () => p }));
        var i = r(9513),
          s = r(276),
          a = r(6558),
          o = r(7172),
          l = r.n(o),
          u = r(2017),
          d = r(997),
          c = r(7716);
        function p() {
          return (0, d.jsxs)("main", {
            style: { padding: "2rem" },
            children: [d.jsx("h1", { children: "Billing" }), d.jsx(c.m, {})],
          });
        }
        let f = (0, a.l)(n, "default"),
          g = (0, a.l)(n, "getStaticProps"),
          P = (0, a.l)(n, "getStaticPaths"),
          h = (0, a.l)(n, "getServerSideProps"),
          m = (0, a.l)(n, "config"),
          b = (0, a.l)(n, "reportWebVitals"),
          S = (0, a.l)(n, "unstable_getStaticProps"),
          x = (0, a.l)(n, "unstable_getStaticPaths"),
          y = (0, a.l)(n, "unstable_getStaticParams"),
          v = (0, a.l)(n, "unstable_getServerProps"),
          j = (0, a.l)(n, "unstable_getServerSideProps"),
          _ = new i.PagesRouteModule({
            definition: {
              kind: s.x.PAGES,
              page: "/billing",
              pathname: "/billing",
              bundlePath: "",
              filename: "",
            },
            components: { App: u.default, Document: l() },
            userland: n,
          });
      },
      7716: (e, t, r) => {
        "use strict";
        r.d(t, { m: () => a });
        var n = r(997),
          i = r(6689),
          s = r(5177);
        function a() {
          let e = (0, s.h)(),
            [t, r] = (0, i.useState)(null),
            [a, o] = (0, i.useState)(null);
          async function l() {
            let t = await e.post("/billing/stripe/session");
            (r(t.sessionId), t.url && (window.location.href = t.url));
          }
          async function u() {
            let t = await e.post("/billing/paypal/order");
            (o(t.orderId),
              t.approvalUrl && (window.location.href = t.approvalUrl));
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
                onClick: u,
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
              t &&
                (0, n.jsxs)("p", {
                  style: { marginTop: "1rem" },
                  children: ["Stripe session: ", t],
                }),
              a &&
                (0, n.jsxs)("p", {
                  style: { marginTop: "0.5rem" },
                  children: ["PayPal order: ", a],
                }),
            ],
          });
        }
      },
      5177: (e, t, r) => {
        "use strict";
        function n() {
          let e = process.env.NEXT_PUBLIC_API_BASE || "/api";
          return {
            get: async function (t) {
              let r = await fetch(e + t, { headers: {} });
              if (!r.ok) throw Error(await r.text());
              return r.json();
            },
            post: async function (t, r) {
              let n = await fetch(e + t, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: r ? JSON.stringify(r) : void 0,
              });
              if (!n.ok) throw Error(await n.text());
              return n.json();
            },
          };
        }
        r.d(t, { h: () => n });
      },
      2017: (e, t, r) => {
        "use strict";
        (r.r(t), r.d(t, { default: () => i }));
        var n = r(997);
        function i({ Component: e, pageProps: t }) {
          return n.jsx("div", {
            style: {
              fontFamily: "system-ui, -apple-system, BlinkMacSystemFont",
            },
            children: n.jsx(e, { ...t }),
          });
        }
        r(8047);
      },
      8047: () => {},
      276: (e, t) => {
        "use strict";
        var r;
        (Object.defineProperty(t, "x", {
          enumerable: !0,
          get: function () {
            return r;
          },
        }),
          (function (e) {
            ((e.PAGES = "PAGES"),
              (e.PAGES_API = "PAGES_API"),
              (e.APP_PAGE = "APP_PAGE"),
              (e.APP_ROUTE = "APP_ROUTE"));
          })(r || (r = {})));
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
  var t = require("../webpack-runtime.js");
  t.C(e);
  var r = (e) => t((t.s = e)),
    n = t.X(0, [172], () => r(4163));
  module.exports = n;
})();
