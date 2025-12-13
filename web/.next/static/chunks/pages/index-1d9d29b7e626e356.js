(self.webpackChunk_N_E = self.webpackChunk_N_E || []).push([
  [405],
  {
    7504: function (e, t, r) {
      "use strict";
      var n, o;
      e.exports =
        (null == (n = r.g.process) ? void 0 : n.env) &&
        "object" == typeof (null == (o = r.g.process) ? void 0 : o.env)
          ? r.g.process
          : r(2170);
    },
    3354: function (e, t, r) {
      (window.__NEXT_P = window.__NEXT_P || []).push([
        "/",
        function () {
          return r(5740);
        },
      ]);
    },
    1273: function (e, t) {
      "use strict";
      var r, n, o, i;
      (Object.defineProperty(t, "__esModule", { value: !0 }),
        (function (e, t) {
          for (var r in t)
            Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
        })(t, {
          ACTION_FAST_REFRESH: function () {
            return f;
          },
          ACTION_NAVIGATE: function () {
            return u;
          },
          ACTION_PREFETCH: function () {
            return c;
          },
          ACTION_REFRESH: function () {
            return l;
          },
          ACTION_RESTORE: function () {
            return a;
          },
          ACTION_SERVER_ACTION: function () {
            return d;
          },
          ACTION_SERVER_PATCH: function () {
            return s;
          },
          PrefetchCacheEntryStatus: function () {
            return n;
          },
          PrefetchKind: function () {
            return r;
          },
          isThenable: function () {
            return p;
          },
        }));
      let l = "refresh",
        u = "navigate",
        a = "restore",
        s = "server-patch",
        c = "prefetch",
        f = "fast-refresh",
        d = "server-action";
      function p(e) {
        return (
          e &&
          ("object" == typeof e || "function" == typeof e) &&
          "function" == typeof e.then
        );
      }
      (((o = r || (r = {})).AUTO = "auto"),
        (o.FULL = "full"),
        (o.TEMPORARY = "temporary"),
        ((i = n || (n = {})).fresh = "fresh"),
        (i.reusable = "reusable"),
        (i.expired = "expired"),
        (i.stale = "stale"),
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default)));
    },
    7074: function (e, t, r) {
      "use strict";
      function n(e, t, r, n) {
        return !1;
      }
      (Object.defineProperty(t, "__esModule", { value: !0 }),
        Object.defineProperty(t, "getDomainLocale", {
          enumerable: !0,
          get: function () {
            return n;
          },
        }),
        r(2239),
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default)));
    },
    3913: function (e, t, r) {
      "use strict";
      (Object.defineProperty(t, "__esModule", { value: !0 }),
        Object.defineProperty(t, "default", {
          enumerable: !0,
          get: function () {
            return x;
          },
        }));
      let n = r(5336),
        o = r(5250),
        i = n._(r(79)),
        l = r(529),
        u = r(4585),
        a = r(7643),
        s = r(3840),
        c = r(9794),
        f = r(749),
        d = r(6677),
        p = r(3455),
        h = r(7074),
        g = r(4499),
        m = r(1273),
        y = new Set();
      function b(e, t, r, n, o, i) {
        if (i || (0, u.isLocalURL)(t)) {
          if (!n.bypassPrefetchedCheck) {
            let o =
              t +
              "%" +
              r +
              "%" +
              (void 0 !== n.locale
                ? n.locale
                : "locale" in e
                  ? e.locale
                  : void 0);
            if (y.has(o)) return;
            y.add(o);
          }
          (async () => (i ? e.prefetch(t, o) : e.prefetch(t, r, n)))().catch(
            (e) => {},
          );
        }
      }
      function v(e) {
        return "string" == typeof e ? e : (0, a.formatUrl)(e);
      }
      let x = i.default.forwardRef(function (e, t) {
        let r, n;
        let {
          href: a,
          as: y,
          children: x,
          prefetch: _ = null,
          passHref: T,
          replace: j,
          shallow: E,
          scroll: C,
          locale: O,
          onClick: P,
          onMouseEnter: k,
          onTouchStart: A,
          legacyBehavior: R = !1,
          ...w
        } = e;
        ((r = x),
          R &&
            ("string" == typeof r || "number" == typeof r) &&
            (r = (0, o.jsx)("a", { children: r })));
        let I = i.default.useContext(f.RouterContext),
          M = i.default.useContext(d.AppRouterContext),
          L = null != I ? I : M,
          S = !I,
          N = !1 !== _,
          U = null === _ ? m.PrefetchKind.AUTO : m.PrefetchKind.FULL,
          { href: H, as: D } = i.default.useMemo(() => {
            if (!I) {
              let e = v(a);
              return { href: e, as: y ? v(y) : e };
            }
            let [e, t] = (0, l.resolveHref)(I, a, !0);
            return { href: e, as: y ? (0, l.resolveHref)(I, y) : t || e };
          }, [I, a, y]),
          F = i.default.useRef(H),
          z = i.default.useRef(D);
        R && (n = i.default.Children.only(r));
        let K = R ? n && "object" == typeof n && n.ref : t,
          [B, W, V] = (0, p.useIntersection)({ rootMargin: "200px" }),
          X = i.default.useCallback(
            (e) => {
              ((z.current !== D || F.current !== H) &&
                (V(), (z.current = D), (F.current = H)),
                B(e),
                K &&
                  ("function" == typeof K
                    ? K(e)
                    : "object" == typeof K && (K.current = e)));
            },
            [D, K, H, V, B],
          );
        i.default.useEffect(() => {
          L && W && N && b(L, H, D, { locale: O }, { kind: U }, S);
        }, [D, H, W, O, N, null == I ? void 0 : I.locale, L, S, U]);
        let G = {
          ref: X,
          onClick(e) {
            (R || "function" != typeof P || P(e),
              R &&
                n.props &&
                "function" == typeof n.props.onClick &&
                n.props.onClick(e),
              L &&
                !e.defaultPrevented &&
                (function (e, t, r, n, o, l, a, s, c) {
                  let { nodeName: f } = e.currentTarget;
                  if (
                    "A" === f.toUpperCase() &&
                    ((function (e) {
                      let t = e.currentTarget.getAttribute("target");
                      return (
                        (t && "_self" !== t) ||
                        e.metaKey ||
                        e.ctrlKey ||
                        e.shiftKey ||
                        e.altKey ||
                        (e.nativeEvent && 2 === e.nativeEvent.which)
                      );
                    })(e) ||
                      (!c && !(0, u.isLocalURL)(r)))
                  )
                    return;
                  e.preventDefault();
                  let d = () => {
                    let e = null == a || a;
                    "beforePopState" in t
                      ? t[o ? "replace" : "push"](r, n, {
                          shallow: l,
                          locale: s,
                          scroll: e,
                        })
                      : t[o ? "replace" : "push"](n || r, { scroll: e });
                  };
                  c ? i.default.startTransition(d) : d();
                })(e, L, H, D, j, E, C, O, S));
          },
          onMouseEnter(e) {
            (R || "function" != typeof k || k(e),
              R &&
                n.props &&
                "function" == typeof n.props.onMouseEnter &&
                n.props.onMouseEnter(e),
              L &&
                (N || !S) &&
                b(
                  L,
                  H,
                  D,
                  { locale: O, priority: !0, bypassPrefetchedCheck: !0 },
                  { kind: U },
                  S,
                ));
          },
          onTouchStart: function (e) {
            (R || "function" != typeof A || A(e),
              R &&
                n.props &&
                "function" == typeof n.props.onTouchStart &&
                n.props.onTouchStart(e),
              L &&
                (N || !S) &&
                b(
                  L,
                  H,
                  D,
                  { locale: O, priority: !0, bypassPrefetchedCheck: !0 },
                  { kind: U },
                  S,
                ));
          },
        };
        if ((0, s.isAbsoluteUrl)(D)) G.href = D;
        else if (!R || T || ("a" === n.type && !("href" in n.props))) {
          let e = void 0 !== O ? O : null == I ? void 0 : I.locale,
            t =
              (null == I ? void 0 : I.isLocaleDomain) &&
              (0, h.getDomainLocale)(
                D,
                e,
                null == I ? void 0 : I.locales,
                null == I ? void 0 : I.domainLocales,
              );
          G.href =
            t ||
            (0, g.addBasePath)(
              (0, c.addLocale)(D, e, null == I ? void 0 : I.defaultLocale),
            );
        }
        return R
          ? i.default.cloneElement(n, G)
          : (0, o.jsx)("a", { ...w, ...G, children: r });
      });
      ("function" == typeof t.default ||
        ("object" == typeof t.default && null !== t.default)) &&
        void 0 === t.default.__esModule &&
        (Object.defineProperty(t.default, "__esModule", { value: !0 }),
        Object.assign(t.default, t),
        (e.exports = t.default));
    },
    3455: function (e, t, r) {
      "use strict";
      (Object.defineProperty(t, "__esModule", { value: !0 }),
        Object.defineProperty(t, "useIntersection", {
          enumerable: !0,
          get: function () {
            return a;
          },
        }));
      let n = r(79),
        o = r(5367),
        i = "function" == typeof IntersectionObserver,
        l = new Map(),
        u = [];
      function a(e) {
        let { rootRef: t, rootMargin: r, disabled: a } = e,
          s = a || !i,
          [c, f] = (0, n.useState)(!1),
          d = (0, n.useRef)(null),
          p = (0, n.useCallback)((e) => {
            d.current = e;
          }, []);
        return (
          (0, n.useEffect)(() => {
            if (i) {
              if (s || c) return;
              let e = d.current;
              if (e && e.tagName)
                return (function (e, t, r) {
                  let {
                    id: n,
                    observer: o,
                    elements: i,
                  } = (function (e) {
                    let t;
                    let r = {
                        root: e.root || null,
                        margin: e.rootMargin || "",
                      },
                      n = u.find(
                        (e) => e.root === r.root && e.margin === r.margin,
                      );
                    if (n && (t = l.get(n))) return t;
                    let o = new Map();
                    return (
                      (t = {
                        id: r,
                        observer: new IntersectionObserver((e) => {
                          e.forEach((e) => {
                            let t = o.get(e.target),
                              r = e.isIntersecting || e.intersectionRatio > 0;
                            t && r && t(r);
                          });
                        }, e),
                        elements: o,
                      }),
                      u.push(r),
                      l.set(r, t),
                      t
                    );
                  })(r);
                  return (
                    i.set(e, t),
                    o.observe(e),
                    function () {
                      if ((i.delete(e), o.unobserve(e), 0 === i.size)) {
                        (o.disconnect(), l.delete(n));
                        let e = u.findIndex(
                          (e) => e.root === n.root && e.margin === n.margin,
                        );
                        e > -1 && u.splice(e, 1);
                      }
                    }
                  );
                })(e, (e) => e && f(e), {
                  root: null == t ? void 0 : t.current,
                  rootMargin: r,
                });
            } else if (!c) {
              let e = (0, o.requestIdleCallback)(() => f(!0));
              return () => (0, o.cancelIdleCallback)(e);
            }
          }, [s, r, t, c, d.current]),
          [
            p,
            c,
            (0, n.useCallback)(() => {
              f(!1);
            }, []),
          ]
        );
      }
      ("function" == typeof t.default ||
        ("object" == typeof t.default && null !== t.default)) &&
        void 0 === t.default.__esModule &&
        (Object.defineProperty(t.default, "__esModule", { value: !0 }),
        Object.assign(t.default, t),
        (e.exports = t.default));
    },
    5740: function (e, t, r) {
      "use strict";
      (r.r(t),
        r.d(t, {
          default: function () {
            return s;
          },
        }));
      var n = r(5250),
        o = r(3255),
        i = r.n(o);
      r(79);
      let l = [
        {
          id: "genesis",
          title: "Genesis Core",
          subtitle: "Logistics AI Navigator",
          description:
            "Optimizes routes, loads, ETAs and capacity across fleets.",
          color: "linear-gradient(135deg,#ffcc33,#ff3366)",
        },
        {
          id: "aurum",
          title: "Aurum Dispatch",
          subtitle: "Dispatcher Co-pilot",
          description:
            "Monitors lanes, suggests bids and protects margins in real time.",
          color: "linear-gradient(135deg,#ff9966,#ff5e62)",
        },
        {
          id: "noir",
          title: "Noir Guardian",
          subtitle: "Risk and Compliance",
          description:
            "Watches for anomalies, fraud and safety risks across the network.",
          color: "linear-gradient(135deg,#3a1c71,#d76d77)",
        },
      ];
      function u() {
        return (0, n.jsx)("div", {
          style: {
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
            gap: "1.5rem",
            marginTop: "2rem",
          },
          children: l.map((e) =>
            (0, n.jsxs)(
              "div",
              {
                style: {
                  borderRadius: "18px",
                  padding: "1.5rem",
                  background: "#050509",
                  border: "1px solid rgba(255,255,255,0.07)",
                  boxShadow: "0 18px 45px rgba(0,0,0,0.6)",
                  position: "relative",
                  overflow: "hidden",
                },
                children: [
                  (0, n.jsx)("div", {
                    style: {
                      position: "absolute",
                      inset: "-40%",
                      background: e.color,
                      opacity: 0.2,
                      filter: "blur(30px)",
                    },
                  }),
                  (0, n.jsxs)("div", {
                    style: { position: "relative" },
                    children: [
                      (0, n.jsx)("div", {
                        style: {
                          width: "54px",
                          height: "54px",
                          borderRadius: "14px",
                          background: e.color,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "1.4rem",
                          fontWeight: 700,
                          marginBottom: "0.9rem",
                          color: "#050509",
                        },
                        children: e.title[0],
                      }),
                      (0, n.jsx)("h3", {
                        style: {
                          margin: 0,
                          fontSize: "1.2rem",
                          fontWeight: 700,
                        },
                        children: e.title,
                      }),
                      (0, n.jsx)("p", {
                        style: {
                          margin: "0.2rem 0 0.9rem",
                          fontSize: "0.85rem",
                          letterSpacing: "0.06em",
                          textTransform: "uppercase",
                          color: "rgba(255,255,255,0.6)",
                        },
                        children: e.subtitle,
                      }),
                      (0, n.jsx)("p", {
                        style: {
                          margin: 0,
                          fontSize: "0.9rem",
                          color: "rgba(255,255,255,0.75)",
                          lineHeight: 1.5,
                        },
                        children: e.description,
                      }),
                    ],
                  }),
                ],
              },
              e.id,
            ),
          ),
        });
      }
      var a = r(7504);
      function s() {
        let e = a.env.NEXT_PUBLIC_APP_NAME || "Infamous Freight AI";
        return (0, n.jsxs)("main", {
          style: {
            minHeight: "100vh",
            padding: "3rem",
            maxWidth: "960px",
            margin: "0 auto",
          },
          children: [
            (0, n.jsxs)("header", {
              children: [
                (0, n.jsx)("p", {
                  style: {
                    letterSpacing: "0.2em",
                    textTransform: "uppercase",
                    opacity: 0.7,
                  },
                  children: a.env.NEXT_PUBLIC_ENV || "Development",
                }),
                (0, n.jsx)("h1", {
                  style: { fontSize: "3rem", marginBottom: "0.5rem" },
                  children: e,
                }),
                (0, n.jsx)("p", {
                  style: { maxWidth: "540px", lineHeight: 1.6 },
                  children:
                    "Command the Infamous Freight synthetic intelligence stack. Voice automation, billing orchestration, fleet telemetry, and AI copilots converge in a single control tower.",
                }),
                (0, n.jsxs)("div", {
                  style: { marginTop: "1.5rem", display: "flex", gap: "1rem" },
                  children: [
                    (0, n.jsx)(i(), {
                      href: "/dashboard",
                      style: {
                        padding: "0.8rem 1.8rem",
                        borderRadius: "999px",
                        background: "linear-gradient(135deg,#ffcc33,#ff3366)",
                        color: "#050509",
                        fontWeight: 600,
                      },
                      children: "Launch Dashboard",
                    }),
                    (0, n.jsx)(i(), {
                      href: "/billing",
                      style: {
                        padding: "0.8rem 1.8rem",
                        borderRadius: "999px",
                        border: "1px solid rgba(255,255,255,0.3)",
                        color: "#f9fafb",
                      },
                      children: "Billing",
                    }),
                  ],
                }),
              ],
            }),
            (0, n.jsx)(u, {}),
          ],
        });
      }
    },
    2170: function (e) {
      !(function () {
        var t = {
            229: function (e) {
              var t,
                r,
                n,
                o = (e.exports = {});
              function i() {
                throw Error("setTimeout has not been defined");
              }
              function l() {
                throw Error("clearTimeout has not been defined");
              }
              function u(e) {
                if (t === setTimeout) return setTimeout(e, 0);
                if ((t === i || !t) && setTimeout)
                  return ((t = setTimeout), setTimeout(e, 0));
                try {
                  return t(e, 0);
                } catch (r) {
                  try {
                    return t.call(null, e, 0);
                  } catch (r) {
                    return t.call(this, e, 0);
                  }
                }
              }
              !(function () {
                try {
                  t = "function" == typeof setTimeout ? setTimeout : i;
                } catch (e) {
                  t = i;
                }
                try {
                  r = "function" == typeof clearTimeout ? clearTimeout : l;
                } catch (e) {
                  r = l;
                }
              })();
              var a = [],
                s = !1,
                c = -1;
              function f() {
                s &&
                  n &&
                  ((s = !1),
                  n.length ? (a = n.concat(a)) : (c = -1),
                  a.length && d());
              }
              function d() {
                if (!s) {
                  var e = u(f);
                  s = !0;
                  for (var t = a.length; t; ) {
                    for (n = a, a = []; ++c < t; ) n && n[c].run();
                    ((c = -1), (t = a.length));
                  }
                  ((n = null),
                    (s = !1),
                    (function (e) {
                      if (r === clearTimeout) return clearTimeout(e);
                      if ((r === l || !r) && clearTimeout)
                        return ((r = clearTimeout), clearTimeout(e));
                      try {
                        r(e);
                      } catch (t) {
                        try {
                          return r.call(null, e);
                        } catch (t) {
                          return r.call(this, e);
                        }
                      }
                    })(e));
                }
              }
              function p(e, t) {
                ((this.fun = e), (this.array = t));
              }
              function h() {}
              ((o.nextTick = function (e) {
                var t = Array(arguments.length - 1);
                if (arguments.length > 1)
                  for (var r = 1; r < arguments.length; r++)
                    t[r - 1] = arguments[r];
                (a.push(new p(e, t)), 1 !== a.length || s || u(d));
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
          r = {};
        function n(e) {
          var o = r[e];
          if (void 0 !== o) return o.exports;
          var i = (r[e] = { exports: {} }),
            l = !0;
          try {
            (t[e](i, i.exports, n), (l = !1));
          } finally {
            l && delete r[e];
          }
          return i.exports;
        }
        n.ab = "//";
        var o = n(229);
        e.exports = o;
      })();
    },
    3255: function (e, t, r) {
      e.exports = r(3913);
    },
  },
  function (e) {
    (e.O(0, [888, 774, 179], function () {
      return e((e.s = 3354));
    }),
      (_N_E = e.O()));
  },
]);
