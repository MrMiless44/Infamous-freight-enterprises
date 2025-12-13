(() => {
  var e = {};
  ((e.id = 405),
    (e.ids = [405, 888, 660]),
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
      6531: (e, t, r) => {
        "use strict";
        (r.r(t),
          r.d(t, {
            config: () => E,
            default: () => h,
            getServerSideProps: () => b,
            getStaticPaths: () => P,
            getStaticProps: () => m,
            reportWebVitals: () => y,
            routeModule: () => x,
            unstable_getServerProps: () => O,
            unstable_getServerSideProps: () => A,
            unstable_getStaticParams: () => S,
            unstable_getStaticPaths: () => v,
            unstable_getStaticProps: () => R,
          }));
        var n = {};
        (r.r(n), r.d(n, { default: () => g }));
        var o = r(9513),
          a = r(276),
          i = r(6558),
          u = r(7172),
          s = r.n(u),
          l = r(2017),
          c = r(997),
          f = r(3255),
          d = r.n(f);
        r(6689);
        let p = [
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
        function _() {
          return c.jsx("div", {
            style: {
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
              gap: "1.5rem",
              marginTop: "2rem",
            },
            children: p.map((e) =>
              (0, c.jsxs)(
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
                    c.jsx("div", {
                      style: {
                        position: "absolute",
                        inset: "-40%",
                        background: e.color,
                        opacity: 0.2,
                        filter: "blur(30px)",
                      },
                    }),
                    (0, c.jsxs)("div", {
                      style: { position: "relative" },
                      children: [
                        c.jsx("div", {
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
                        c.jsx("h3", {
                          style: {
                            margin: 0,
                            fontSize: "1.2rem",
                            fontWeight: 700,
                          },
                          children: e.title,
                        }),
                        c.jsx("p", {
                          style: {
                            margin: "0.2rem 0 0.9rem",
                            fontSize: "0.85rem",
                            letterSpacing: "0.06em",
                            textTransform: "uppercase",
                            color: "rgba(255,255,255,0.6)",
                          },
                          children: e.subtitle,
                        }),
                        c.jsx("p", {
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
        function g() {
          let e = process.env.NEXT_PUBLIC_APP_NAME || "Infamous Freight AI";
          return (0, c.jsxs)("main", {
            style: {
              minHeight: "100vh",
              padding: "3rem",
              maxWidth: "960px",
              margin: "0 auto",
            },
            children: [
              (0, c.jsxs)("header", {
                children: [
                  c.jsx("p", {
                    style: {
                      letterSpacing: "0.2em",
                      textTransform: "uppercase",
                      opacity: 0.7,
                    },
                    children: process.env.NEXT_PUBLIC_ENV || "Development",
                  }),
                  c.jsx("h1", {
                    style: { fontSize: "3rem", marginBottom: "0.5rem" },
                    children: e,
                  }),
                  c.jsx("p", {
                    style: { maxWidth: "540px", lineHeight: 1.6 },
                    children:
                      "Command the Infamous Freight synthetic intelligence stack. Voice automation, billing orchestration, fleet telemetry, and AI copilots converge in a single control tower.",
                  }),
                  (0, c.jsxs)("div", {
                    style: {
                      marginTop: "1.5rem",
                      display: "flex",
                      gap: "1rem",
                    },
                    children: [
                      c.jsx(d(), {
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
                      c.jsx(d(), {
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
              c.jsx(_, {}),
            ],
          });
        }
        let h = (0, i.l)(n, "default"),
          m = (0, i.l)(n, "getStaticProps"),
          P = (0, i.l)(n, "getStaticPaths"),
          b = (0, i.l)(n, "getServerSideProps"),
          E = (0, i.l)(n, "config"),
          y = (0, i.l)(n, "reportWebVitals"),
          R = (0, i.l)(n, "unstable_getStaticProps"),
          v = (0, i.l)(n, "unstable_getStaticPaths"),
          S = (0, i.l)(n, "unstable_getStaticParams"),
          O = (0, i.l)(n, "unstable_getServerProps"),
          A = (0, i.l)(n, "unstable_getServerSideProps"),
          x = new o.PagesRouteModule({
            definition: {
              kind: a.x.PAGES,
              page: "/index",
              pathname: "/",
              bundlePath: "",
              filename: "",
            },
            components: { App: l.default, Document: s() },
            userland: n,
          });
      },
      8774: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "addBasePath", {
            enumerable: !0,
            get: function () {
              return a;
            },
          }));
        let n = r(8416),
          o = r(9605);
        function a(e, t) {
          return (0, o.normalizePathTrailingSlash)((0, n.addPathPrefix)(e, ""));
        }
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      1668: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "addLocale", {
            enumerable: !0,
            get: function () {
              return n;
            },
          }),
          r(9605));
        let n = function (e) {
          for (
            var t = arguments.length, r = Array(t > 1 ? t - 1 : 0), n = 1;
            n < t;
            n++
          )
            r[n - 1] = arguments[n];
          return e;
        };
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      8811: (e, t) => {
        "use strict";
        var r, n;
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          (function (e, t) {
            for (var r in t)
              Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
          })(t, {
            ACTION_FAST_REFRESH: function () {
              return l;
            },
            ACTION_NAVIGATE: function () {
              return a;
            },
            ACTION_PREFETCH: function () {
              return s;
            },
            ACTION_REFRESH: function () {
              return o;
            },
            ACTION_RESTORE: function () {
              return i;
            },
            ACTION_SERVER_ACTION: function () {
              return c;
            },
            ACTION_SERVER_PATCH: function () {
              return u;
            },
            PrefetchCacheEntryStatus: function () {
              return n;
            },
            PrefetchKind: function () {
              return r;
            },
            isThenable: function () {
              return f;
            },
          }));
        let o = "refresh",
          a = "navigate",
          i = "restore",
          u = "server-patch",
          s = "prefetch",
          l = "fast-refresh",
          c = "server-action";
        function f(e) {
          return (
            e &&
            ("object" == typeof e || "function" == typeof e) &&
            "function" == typeof e.then
          );
        }
        ((function (e) {
          ((e.AUTO = "auto"), (e.FULL = "full"), (e.TEMPORARY = "temporary"));
        })(r || (r = {})),
          (function (e) {
            ((e.fresh = "fresh"),
              (e.reusable = "reusable"),
              (e.expired = "expired"),
              (e.stale = "stale"));
          })(n || (n = {})),
          ("function" == typeof t.default ||
            ("object" == typeof t.default && null !== t.default)) &&
            void 0 === t.default.__esModule &&
            (Object.defineProperty(t.default, "__esModule", { value: !0 }),
            Object.assign(t.default, t),
            (e.exports = t.default)));
      },
      4385: (e, t, r) => {
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
          r(9605),
          ("function" == typeof t.default ||
            ("object" == typeof t.default && null !== t.default)) &&
            void 0 === t.default.__esModule &&
            (Object.defineProperty(t.default, "__esModule", { value: !0 }),
            Object.assign(t.default, t),
            (e.exports = t.default)));
      },
      9171: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "hasBasePath", {
            enumerable: !0,
            get: function () {
              return o;
            },
          }));
        let n = r(3326);
        function o(e) {
          return (0, n.pathHasPrefix)(e, "");
        }
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      6529: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "default", {
            enumerable: !0,
            get: function () {
              return P;
            },
          }));
        let n = r(4824),
          o = r(997),
          a = n._(r(6689)),
          i = r(4845),
          u = r(2459),
          s = r(7405),
          l = r(9623),
          c = r(1668),
          f = r(1729),
          d = r(2407),
          p = r(9862),
          _ = r(4385),
          g = r(8774),
          h = r(8811);
        function m(e) {
          return "string" == typeof e ? e : (0, s.formatUrl)(e);
        }
        let P = a.default.forwardRef(function (e, t) {
          let r, n;
          let {
            href: s,
            as: P,
            children: b,
            prefetch: E = null,
            passHref: y,
            replace: R,
            shallow: v,
            scroll: S,
            locale: O,
            onClick: A,
            onMouseEnter: x,
            onTouchStart: T,
            legacyBehavior: j = !1,
            ...I
          } = e;
          ((r = b),
            j &&
              ("string" == typeof r || "number" == typeof r) &&
              (r = (0, o.jsx)("a", { children: r })));
          let C = a.default.useContext(f.RouterContext),
            M = a.default.useContext(d.AppRouterContext),
            N = null != C ? C : M,
            L = !C,
            D = !1 !== E,
            w = null === E ? h.PrefetchKind.AUTO : h.PrefetchKind.FULL,
            { href: U, as: k } = a.default.useMemo(() => {
              if (!C) {
                let e = m(s);
                return { href: e, as: P ? m(P) : e };
              }
              let [e, t] = (0, i.resolveHref)(C, s, !0);
              return { href: e, as: P ? (0, i.resolveHref)(C, P) : t || e };
            }, [C, s, P]),
            F = a.default.useRef(U),
            X = a.default.useRef(k);
          j && (n = a.default.Children.only(r));
          let G = j ? n && "object" == typeof n && n.ref : t,
            [H, W, V] = (0, p.useIntersection)({ rootMargin: "200px" }),
            B = a.default.useCallback(
              (e) => {
                ((X.current !== k || F.current !== U) &&
                  (V(), (X.current = k), (F.current = U)),
                  H(e),
                  G &&
                    ("function" == typeof G
                      ? G(e)
                      : "object" == typeof G && (G.current = e)));
              },
              [k, G, U, V, H],
            );
          a.default.useEffect(() => {}, [
            k,
            U,
            W,
            O,
            D,
            null == C ? void 0 : C.locale,
            N,
            L,
            w,
          ]);
          let K = {
            ref: B,
            onClick(e) {
              (j || "function" != typeof A || A(e),
                j &&
                  n.props &&
                  "function" == typeof n.props.onClick &&
                  n.props.onClick(e),
                N &&
                  !e.defaultPrevented &&
                  (function (e, t, r, n, o, i, s, l, c) {
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
                      let e = null == s || s;
                      "beforePopState" in t
                        ? t[o ? "replace" : "push"](r, n, {
                            shallow: i,
                            locale: l,
                            scroll: e,
                          })
                        : t[o ? "replace" : "push"](n || r, { scroll: e });
                    };
                    c ? a.default.startTransition(d) : d();
                  })(e, N, U, k, R, v, S, O, L));
            },
            onMouseEnter(e) {
              (j || "function" != typeof x || x(e),
                j &&
                  n.props &&
                  "function" == typeof n.props.onMouseEnter &&
                  n.props.onMouseEnter(e));
            },
            onTouchStart: function (e) {
              (j || "function" != typeof T || T(e),
                j &&
                  n.props &&
                  "function" == typeof n.props.onTouchStart &&
                  n.props.onTouchStart(e));
            },
          };
          if ((0, l.isAbsoluteUrl)(k)) K.href = k;
          else if (!j || y || ("a" === n.type && !("href" in n.props))) {
            let e = void 0 !== O ? O : null == C ? void 0 : C.locale,
              t =
                (null == C ? void 0 : C.isLocaleDomain) &&
                (0, _.getDomainLocale)(
                  k,
                  e,
                  null == C ? void 0 : C.locales,
                  null == C ? void 0 : C.domainLocales,
                );
            K.href =
              t ||
              (0, g.addBasePath)(
                (0, c.addLocale)(k, e, null == C ? void 0 : C.defaultLocale),
              );
          }
          return j
            ? a.default.cloneElement(n, K)
            : (0, o.jsx)("a", { ...I, ...K, children: r });
        });
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      9605: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "normalizePathTrailingSlash", {
            enumerable: !0,
            get: function () {
              return a;
            },
          }));
        let n = r(5537),
          o = r(7318),
          a = (e) => {
            if (!e.startsWith("/")) return e;
            let { pathname: t, query: r, hash: a } = (0, o.parsePath)(e);
            return "" + (0, n.removeTrailingSlash)(t) + r + a;
          };
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      891: (e, t) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          (function (e, t) {
            for (var r in t)
              Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
          })(t, {
            cancelIdleCallback: function () {
              return n;
            },
            requestIdleCallback: function () {
              return r;
            },
          }));
        let r =
            ("undefined" != typeof self &&
              self.requestIdleCallback &&
              self.requestIdleCallback.bind(window)) ||
            function (e) {
              let t = Date.now();
              return self.setTimeout(function () {
                e({
                  didTimeout: !1,
                  timeRemaining: function () {
                    return Math.max(0, 50 - (Date.now() - t));
                  },
                });
              }, 1);
            },
          n =
            ("undefined" != typeof self &&
              self.cancelIdleCallback &&
              self.cancelIdleCallback.bind(window)) ||
            function (e) {
              return clearTimeout(e);
            };
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      4845: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "resolveHref", {
            enumerable: !0,
            get: function () {
              return f;
            },
          }));
        let n = r(1584),
          o = r(7405),
          a = r(8068),
          i = r(9623),
          u = r(9605),
          s = r(2459),
          l = r(5052),
          c = r(3628);
        function f(e, t, r) {
          let f;
          let d = "string" == typeof t ? t : (0, o.formatWithValidation)(t),
            p = d.match(/^[a-zA-Z]{1,}:\/\//),
            _ = p ? d.slice(p[0].length) : d;
          if ((_.split("?", 1)[0] || "").match(/(\/\/|\\)/)) {
            console.error(
              "Invalid href '" +
                d +
                "' passed to next/router in page: '" +
                e.pathname +
                "'. Repeated forward-slashes (//) or backslashes \\ are not valid in the href.",
            );
            let t = (0, i.normalizeRepeatedSlashes)(_);
            d = (p ? p[0] : "") + t;
          }
          if (!(0, s.isLocalURL)(d)) return r ? [d] : d;
          try {
            f = new URL(d.startsWith("#") ? e.asPath : e.pathname, "http://n");
          } catch (e) {
            f = new URL("/", "http://n");
          }
          try {
            let e = new URL(d, f);
            e.pathname = (0, u.normalizePathTrailingSlash)(e.pathname);
            let t = "";
            if ((0, l.isDynamicRoute)(e.pathname) && e.searchParams && r) {
              let r = (0, n.searchParamsToUrlQuery)(e.searchParams),
                { result: i, params: u } = (0, c.interpolateAs)(
                  e.pathname,
                  e.pathname,
                  r,
                );
              i &&
                (t = (0, o.formatWithValidation)({
                  pathname: i,
                  hash: e.hash,
                  query: (0, a.omit)(r, u),
                }));
            }
            let i =
              e.origin === f.origin ? e.href.slice(e.origin.length) : e.href;
            return r ? [i, t || i] : i;
          } catch (e) {
            return r ? [d] : d;
          }
        }
        ("function" == typeof t.default ||
          ("object" == typeof t.default && null !== t.default)) &&
          void 0 === t.default.__esModule &&
          (Object.defineProperty(t.default, "__esModule", { value: !0 }),
          Object.assign(t.default, t),
          (e.exports = t.default));
      },
      9862: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "useIntersection", {
            enumerable: !0,
            get: function () {
              return s;
            },
          }));
        let n = r(6689),
          o = r(891),
          a = "function" == typeof IntersectionObserver,
          i = new Map(),
          u = [];
        function s(e) {
          let { rootRef: t, rootMargin: r, disabled: s } = e,
            l = s || !a,
            [c, f] = (0, n.useState)(!1),
            d = (0, n.useRef)(null),
            p = (0, n.useCallback)((e) => {
              d.current = e;
            }, []);
          return (
            (0, n.useEffect)(() => {
              if (a) {
                if (l || c) return;
                let e = d.current;
                if (e && e.tagName)
                  return (function (e, t, r) {
                    let {
                      id: n,
                      observer: o,
                      elements: a,
                    } = (function (e) {
                      let t;
                      let r = {
                          root: e.root || null,
                          margin: e.rootMargin || "",
                        },
                        n = u.find(
                          (e) => e.root === r.root && e.margin === r.margin,
                        );
                      if (n && (t = i.get(n))) return t;
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
                        i.set(r, t),
                        t
                      );
                    })(r);
                    return (
                      a.set(e, t),
                      o.observe(e),
                      function () {
                        if ((a.delete(e), o.unobserve(e), 0 === a.size)) {
                          (o.disconnect(), i.delete(n));
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
            }, [l, r, t, c, d.current]),
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
      6186: (e, t) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "escapeStringRegexp", {
            enumerable: !0,
            get: function () {
              return o;
            },
          }));
        let r = /[|\\{}()[\]^$+*?.-]/,
          n = /[|\\{}()[\]^$+*?.-]/g;
        function o(e) {
          return r.test(e) ? e.replace(n, "\\$&") : e;
        }
      },
      8416: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "addPathPrefix", {
            enumerable: !0,
            get: function () {
              return o;
            },
          }));
        let n = r(7318);
        function o(e, t) {
          if (!e.startsWith("/") || !t) return e;
          let { pathname: r, query: o, hash: a } = (0, n.parsePath)(e);
          return "" + t + r + o + a;
        }
      },
      7405: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          (function (e, t) {
            for (var r in t)
              Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
          })(t, {
            formatUrl: function () {
              return a;
            },
            formatWithValidation: function () {
              return u;
            },
            urlObjectKeys: function () {
              return i;
            },
          }));
        let n = r(1810)._(r(1584)),
          o = /https?|ftp|gopher|file/;
        function a(e) {
          let { auth: t, hostname: r } = e,
            a = e.protocol || "",
            i = e.pathname || "",
            u = e.hash || "",
            s = e.query || "",
            l = !1;
          ((t = t ? encodeURIComponent(t).replace(/%3A/i, ":") + "@" : ""),
            e.host
              ? (l = t + e.host)
              : r &&
                ((l = t + (~r.indexOf(":") ? "[" + r + "]" : r)),
                e.port && (l += ":" + e.port)),
            s &&
              "object" == typeof s &&
              (s = String(n.urlQueryToSearchParams(s))));
          let c = e.search || (s && "?" + s) || "";
          return (
            a && !a.endsWith(":") && (a += ":"),
            e.slashes || ((!a || o.test(a)) && !1 !== l)
              ? ((l = "//" + (l || "")), i && "/" !== i[0] && (i = "/" + i))
              : l || (l = ""),
            u && "#" !== u[0] && (u = "#" + u),
            c && "?" !== c[0] && (c = "?" + c),
            "" +
              a +
              l +
              (i = i.replace(/[?#]/g, encodeURIComponent)) +
              (c = c.replace("#", "%23")) +
              u
          );
        }
        let i = [
          "auth",
          "hash",
          "host",
          "hostname",
          "href",
          "path",
          "pathname",
          "port",
          "protocol",
          "query",
          "search",
          "slashes",
        ];
        function u(e) {
          return a(e);
        }
      },
      3628: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "interpolateAs", {
            enumerable: !0,
            get: function () {
              return a;
            },
          }));
        let n = r(8369),
          o = r(3892);
        function a(e, t, r) {
          let a = "",
            i = (0, o.getRouteRegex)(e),
            u = i.groups,
            s = (t !== e ? (0, n.getRouteMatcher)(i)(t) : "") || r;
          a = e;
          let l = Object.keys(u);
          return (
            l.every((e) => {
              let t = s[e] || "",
                { repeat: r, optional: n } = u[e],
                o = "[" + (r ? "..." : "") + e + "]";
              return (
                n && (o = (t ? "" : "/") + "[" + o + "]"),
                r && !Array.isArray(t) && (t = [t]),
                (n || e in s) &&
                  (a =
                    a.replace(
                      o,
                      r
                        ? t.map((e) => encodeURIComponent(e)).join("/")
                        : encodeURIComponent(t),
                    ) || "/")
              );
            }) || (a = ""),
            { params: l, result: a }
          );
        }
      },
      2459: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "isLocalURL", {
            enumerable: !0,
            get: function () {
              return a;
            },
          }));
        let n = r(9623),
          o = r(9171);
        function a(e) {
          if (!(0, n.isAbsoluteUrl)(e)) return !0;
          try {
            let t = (0, n.getLocationOrigin)(),
              r = new URL(e, t);
            return r.origin === t && (0, o.hasBasePath)(r.pathname);
          } catch (e) {
            return !1;
          }
        }
      },
      8068: (e, t) => {
        "use strict";
        function r(e, t) {
          let r = {};
          return (
            Object.keys(e).forEach((n) => {
              t.includes(n) || (r[n] = e[n]);
            }),
            r
          );
        }
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "omit", {
            enumerable: !0,
            get: function () {
              return r;
            },
          }));
      },
      7318: (e, t) => {
        "use strict";
        function r(e) {
          let t = e.indexOf("#"),
            r = e.indexOf("?"),
            n = r > -1 && (t < 0 || r < t);
          return n || t > -1
            ? {
                pathname: e.substring(0, n ? r : t),
                query: n ? e.substring(r, t > -1 ? t : void 0) : "",
                hash: t > -1 ? e.slice(t) : "",
              }
            : { pathname: e, query: "", hash: "" };
        }
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "parsePath", {
            enumerable: !0,
            get: function () {
              return r;
            },
          }));
      },
      3326: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "pathHasPrefix", {
            enumerable: !0,
            get: function () {
              return o;
            },
          }));
        let n = r(7318);
        function o(e, t) {
          if ("string" != typeof e) return !1;
          let { pathname: r } = (0, n.parsePath)(e);
          return r === t || r.startsWith(t + "/");
        }
      },
      1584: (e, t) => {
        "use strict";
        function r(e) {
          let t = {};
          return (
            e.forEach((e, r) => {
              void 0 === t[r]
                ? (t[r] = e)
                : Array.isArray(t[r])
                  ? t[r].push(e)
                  : (t[r] = [t[r], e]);
            }),
            t
          );
        }
        function n(e) {
          return "string" != typeof e &&
            ("number" != typeof e || isNaN(e)) &&
            "boolean" != typeof e
            ? ""
            : String(e);
        }
        function o(e) {
          let t = new URLSearchParams();
          return (
            Object.entries(e).forEach((e) => {
              let [r, o] = e;
              Array.isArray(o)
                ? o.forEach((e) => t.append(r, n(e)))
                : t.set(r, n(o));
            }),
            t
          );
        }
        function a(e) {
          for (
            var t = arguments.length, r = Array(t > 1 ? t - 1 : 0), n = 1;
            n < t;
            n++
          )
            r[n - 1] = arguments[n];
          return (
            r.forEach((t) => {
              (Array.from(t.keys()).forEach((t) => e.delete(t)),
                t.forEach((t, r) => e.append(r, t)));
            }),
            e
          );
        }
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          (function (e, t) {
            for (var r in t)
              Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
          })(t, {
            assign: function () {
              return a;
            },
            searchParamsToUrlQuery: function () {
              return r;
            },
            urlQueryToSearchParams: function () {
              return o;
            },
          }));
      },
      5537: (e, t) => {
        "use strict";
        function r(e) {
          return e.replace(/\/$/, "") || "/";
        }
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "removeTrailingSlash", {
            enumerable: !0,
            get: function () {
              return r;
            },
          }));
      },
      8369: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          Object.defineProperty(t, "getRouteMatcher", {
            enumerable: !0,
            get: function () {
              return o;
            },
          }));
        let n = r(9623);
        function o(e) {
          let { re: t, groups: r } = e;
          return (e) => {
            let o = t.exec(e);
            if (!o) return !1;
            let a = (e) => {
                try {
                  return decodeURIComponent(e);
                } catch (e) {
                  throw new n.DecodeError("failed to decode param");
                }
              },
              i = {};
            return (
              Object.keys(r).forEach((e) => {
                let t = r[e],
                  n = o[t.pos];
                void 0 !== n &&
                  (i[e] = ~n.indexOf("/")
                    ? n.split("/").map((e) => a(e))
                    : t.repeat
                      ? [a(n)]
                      : a(n));
              }),
              i
            );
          };
        }
      },
      3892: (e, t, r) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          (function (e, t) {
            for (var r in t)
              Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
          })(t, {
            getNamedMiddlewareRegex: function () {
              return p;
            },
            getNamedRouteRegex: function () {
              return d;
            },
            getRouteRegex: function () {
              return l;
            },
            parseParameter: function () {
              return u;
            },
          }));
        let n = r(5281),
          o = r(473),
          a = r(6186),
          i = r(5537);
        function u(e) {
          let t = e.startsWith("[") && e.endsWith("]");
          t && (e = e.slice(1, -1));
          let r = e.startsWith("...");
          return (r && (e = e.slice(3)), { key: e, repeat: r, optional: t });
        }
        function s(e) {
          let t = (0, i.removeTrailingSlash)(e).slice(1).split("/"),
            r = {},
            n = 1;
          return {
            parameterizedRoute: t
              .map((e) => {
                let t = o.INTERCEPTION_ROUTE_MARKERS.find((t) =>
                    e.startsWith(t),
                  ),
                  i = e.match(/\[((?:\[.*\])|.+)\]/);
                if (t && i) {
                  let { key: e, optional: o, repeat: s } = u(i[1]);
                  return (
                    (r[e] = { pos: n++, repeat: s, optional: o }),
                    "/" + (0, a.escapeStringRegexp)(t) + "([^/]+?)"
                  );
                }
                if (!i) return "/" + (0, a.escapeStringRegexp)(e);
                {
                  let { key: e, repeat: t, optional: o } = u(i[1]);
                  return (
                    (r[e] = { pos: n++, repeat: t, optional: o }),
                    t ? (o ? "(?:/(.+?))?" : "/(.+?)") : "/([^/]+?)"
                  );
                }
              })
              .join(""),
            groups: r,
          };
        }
        function l(e) {
          let { parameterizedRoute: t, groups: r } = s(e);
          return { re: RegExp("^" + t + "(?:/)?$"), groups: r };
        }
        function c(e) {
          let {
              interceptionMarker: t,
              getSafeRouteKey: r,
              segment: n,
              routeKeys: o,
              keyPrefix: i,
            } = e,
            { key: s, optional: l, repeat: c } = u(n),
            f = s.replace(/\W/g, "");
          i && (f = "" + i + f);
          let d = !1;
          ((0 === f.length || f.length > 30) && (d = !0),
            isNaN(parseInt(f.slice(0, 1))) || (d = !0),
            d && (f = r()),
            i ? (o[f] = "" + i + s) : (o[f] = s));
          let p = t ? (0, a.escapeStringRegexp)(t) : "";
          return c
            ? l
              ? "(?:/" + p + "(?<" + f + ">.+?))?"
              : "/" + p + "(?<" + f + ">.+?)"
            : "/" + p + "(?<" + f + ">[^/]+?)";
        }
        function f(e, t) {
          let r;
          let u = (0, i.removeTrailingSlash)(e).slice(1).split("/"),
            s =
              ((r = 0),
              () => {
                let e = "",
                  t = ++r;
                for (; t > 0; )
                  ((e += String.fromCharCode(97 + ((t - 1) % 26))),
                    (t = Math.floor((t - 1) / 26)));
                return e;
              }),
            l = {};
          return {
            namedParameterizedRoute: u
              .map((e) => {
                let r = o.INTERCEPTION_ROUTE_MARKERS.some((t) =>
                    e.startsWith(t),
                  ),
                  i = e.match(/\[((?:\[.*\])|.+)\]/);
                if (r && i) {
                  let [r] = e.split(i[0]);
                  return c({
                    getSafeRouteKey: s,
                    interceptionMarker: r,
                    segment: i[1],
                    routeKeys: l,
                    keyPrefix: t ? n.NEXT_INTERCEPTION_MARKER_PREFIX : void 0,
                  });
                }
                return i
                  ? c({
                      getSafeRouteKey: s,
                      segment: i[1],
                      routeKeys: l,
                      keyPrefix: t ? n.NEXT_QUERY_PARAM_PREFIX : void 0,
                    })
                  : "/" + (0, a.escapeStringRegexp)(e);
              })
              .join(""),
            routeKeys: l,
          };
        }
        function d(e, t) {
          let r = f(e, t);
          return {
            ...l(e),
            namedRegex: "^" + r.namedParameterizedRoute + "(?:/)?$",
            routeKeys: r.routeKeys,
          };
        }
        function p(e, t) {
          let { parameterizedRoute: r } = s(e),
            { catchAll: n = !0 } = t;
          if ("/" === r) return { namedRegex: "^/" + (n ? ".*" : "") + "$" };
          let { namedParameterizedRoute: o } = f(e, !1);
          return { namedRegex: "^" + o + (n ? "(?:(/.*)?)" : "") + "$" };
        }
      },
      2017: (e, t, r) => {
        "use strict";
        (r.r(t), r.d(t, { default: () => o }));
        var n = r(997);
        function o({ Component: e, pageProps: t }) {
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
      5281: (e, t) => {
        "use strict";
        (Object.defineProperty(t, "__esModule", { value: !0 }),
          (function (e, t) {
            for (var r in t)
              Object.defineProperty(e, r, { enumerable: !0, get: t[r] });
          })(t, {
            ACTION_SUFFIX: function () {
              return s;
            },
            APP_DIR_ALIAS: function () {
              return x;
            },
            CACHE_ONE_YEAR: function () {
              return E;
            },
            DOT_NEXT_ALIAS: function () {
              return O;
            },
            ESLINT_DEFAULT_DIRS: function () {
              return B;
            },
            GSP_NO_RETURNED_VALUE: function () {
              return F;
            },
            GSSP_COMPONENT_MEMBER_ERROR: function () {
              return H;
            },
            GSSP_NO_RETURNED_VALUE: function () {
              return X;
            },
            INSTRUMENTATION_HOOK_FILENAME: function () {
              return v;
            },
            MIDDLEWARE_FILENAME: function () {
              return y;
            },
            MIDDLEWARE_LOCATION_REGEXP: function () {
              return R;
            },
            NEXT_BODY_SUFFIX: function () {
              return f;
            },
            NEXT_CACHE_IMPLICIT_TAG_ID: function () {
              return b;
            },
            NEXT_CACHE_REVALIDATED_TAGS_HEADER: function () {
              return _;
            },
            NEXT_CACHE_REVALIDATE_TAG_TOKEN_HEADER: function () {
              return g;
            },
            NEXT_CACHE_SOFT_TAGS_HEADER: function () {
              return p;
            },
            NEXT_CACHE_SOFT_TAG_MAX_LENGTH: function () {
              return P;
            },
            NEXT_CACHE_TAGS_HEADER: function () {
              return d;
            },
            NEXT_CACHE_TAG_MAX_ITEMS: function () {
              return h;
            },
            NEXT_CACHE_TAG_MAX_LENGTH: function () {
              return m;
            },
            NEXT_DATA_SUFFIX: function () {
              return l;
            },
            NEXT_INTERCEPTION_MARKER_PREFIX: function () {
              return n;
            },
            NEXT_META_SUFFIX: function () {
              return c;
            },
            NEXT_QUERY_PARAM_PREFIX: function () {
              return r;
            },
            NON_STANDARD_NODE_ENV: function () {
              return W;
            },
            PAGES_DIR_ALIAS: function () {
              return S;
            },
            PRERENDER_REVALIDATE_HEADER: function () {
              return o;
            },
            PRERENDER_REVALIDATE_ONLY_GENERATED_HEADER: function () {
              return a;
            },
            PUBLIC_DIR_MIDDLEWARE_CONFLICT: function () {
              return N;
            },
            ROOT_DIR_ALIAS: function () {
              return A;
            },
            RSC_ACTION_CLIENT_WRAPPER_ALIAS: function () {
              return M;
            },
            RSC_ACTION_ENCRYPTION_ALIAS: function () {
              return C;
            },
            RSC_ACTION_PROXY_ALIAS: function () {
              return I;
            },
            RSC_ACTION_VALIDATE_ALIAS: function () {
              return j;
            },
            RSC_MOD_REF_PROXY_ALIAS: function () {
              return T;
            },
            RSC_PREFETCH_SUFFIX: function () {
              return i;
            },
            RSC_SUFFIX: function () {
              return u;
            },
            SERVER_PROPS_EXPORT_ERROR: function () {
              return k;
            },
            SERVER_PROPS_GET_INIT_PROPS_CONFLICT: function () {
              return D;
            },
            SERVER_PROPS_SSG_CONFLICT: function () {
              return w;
            },
            SERVER_RUNTIME: function () {
              return K;
            },
            SSG_FALLBACK_EXPORT_ERROR: function () {
              return V;
            },
            SSG_GET_INITIAL_PROPS_CONFLICT: function () {
              return L;
            },
            STATIC_STATUS_PAGE_GET_INITIAL_PROPS_ERROR: function () {
              return U;
            },
            UNSTABLE_REVALIDATE_RENAME_ERROR: function () {
              return G;
            },
            WEBPACK_LAYERS: function () {
              return q;
            },
            WEBPACK_RESOURCE_QUERIES: function () {
              return z;
            },
          }));
        let r = "nxtP",
          n = "nxtI",
          o = "x-prerender-revalidate",
          a = "x-prerender-revalidate-if-generated",
          i = ".prefetch.rsc",
          u = ".rsc",
          s = ".action",
          l = ".json",
          c = ".meta",
          f = ".body",
          d = "x-next-cache-tags",
          p = "x-next-cache-soft-tags",
          _ = "x-next-revalidated-tags",
          g = "x-next-revalidate-tag-token",
          h = 128,
          m = 256,
          P = 1024,
          b = "_N_T_",
          E = 31536e3,
          y = "middleware",
          R = `(?:src/)?${y}`,
          v = "instrumentation",
          S = "private-next-pages",
          O = "private-dot-next",
          A = "private-next-root-dir",
          x = "private-next-app-dir",
          T = "private-next-rsc-mod-ref-proxy",
          j = "private-next-rsc-action-validate",
          I = "private-next-rsc-server-reference",
          C = "private-next-rsc-action-encryption",
          M = "private-next-rsc-action-client-wrapper",
          N =
            "You can not have a '_next' folder inside of your public folder. This conflicts with the internal '/_next' route. https://nextjs.org/docs/messages/public-next-folder-conflict",
          L =
            "You can not use getInitialProps with getStaticProps. To use SSG, please remove your getInitialProps",
          D =
            "You can not use getInitialProps with getServerSideProps. Please remove getInitialProps.",
          w =
            "You can not use getStaticProps or getStaticPaths with getServerSideProps. To use SSG, please remove getServerSideProps",
          U =
            "can not have getInitialProps/getServerSideProps, https://nextjs.org/docs/messages/404-get-initial-props",
          k =
            "pages with `getServerSideProps` can not be exported. See more info here: https://nextjs.org/docs/messages/gssp-export",
          F =
            "Your `getStaticProps` function did not return an object. Did you forget to add a `return`?",
          X =
            "Your `getServerSideProps` function did not return an object. Did you forget to add a `return`?",
          G =
            "The `unstable_revalidate` property is available for general use.\nPlease use `revalidate` instead.",
          H =
            "can not be attached to a page's component and must be exported from the page. See more info here: https://nextjs.org/docs/messages/gssp-component-member",
          W =
            'You are using a non-standard "NODE_ENV" value in your environment. This creates inconsistencies in the project and is strongly advised against. Read more: https://nextjs.org/docs/messages/non-standard-node-env',
          V =
            "Pages with `fallback` enabled in `getStaticPaths` can not be exported. See more info here: https://nextjs.org/docs/messages/ssg-fallback-true-export",
          B = ["app", "pages", "components", "lib", "src"],
          K = {
            edge: "edge",
            experimentalEdge: "experimental-edge",
            nodejs: "nodejs",
          },
          Y = {
            shared: "shared",
            reactServerComponents: "rsc",
            serverSideRendering: "ssr",
            actionBrowser: "action-browser",
            api: "api",
            middleware: "middleware",
            instrument: "instrument",
            edgeAsset: "edge-asset",
            appPagesBrowser: "app-pages-browser",
            appMetadataRoute: "app-metadata-route",
            appRouteHandler: "app-route-handler",
          },
          q = {
            ...Y,
            GROUP: {
              serverOnly: [
                Y.reactServerComponents,
                Y.actionBrowser,
                Y.appMetadataRoute,
                Y.appRouteHandler,
                Y.instrument,
              ],
              clientOnly: [Y.serverSideRendering, Y.appPagesBrowser],
              nonClientServerTarget: [Y.middleware, Y.api],
              app: [
                Y.reactServerComponents,
                Y.actionBrowser,
                Y.appMetadataRoute,
                Y.appRouteHandler,
                Y.serverSideRendering,
                Y.appPagesBrowser,
                Y.shared,
                Y.instrument,
              ],
            },
          },
          z = {
            edgeSSREntry: "__next_edge_ssr_entry__",
            metadata: "__next_metadata__",
            metadataRoute: "__next_metadata_route__",
            metadataImageMeta: "__next_metadata_image_meta__",
          };
      },
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
      2407: (e, t, r) => {
        "use strict";
        e.exports = r(9513).vendored.contexts.AppRouterContext;
      },
      1729: (e, t, r) => {
        "use strict";
        e.exports = r(9513).vendored.contexts.RouterContext;
      },
      3255: (e, t, r) => {
        e.exports = r(6529);
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
      1810: (e, t) => {
        "use strict";
        function r(e) {
          if ("function" != typeof WeakMap) return null;
          var t = new WeakMap(),
            n = new WeakMap();
          return (r = function (e) {
            return e ? n : t;
          })(e);
        }
        t._ = t._interop_require_wildcard = function (e, t) {
          if (!t && e && e.__esModule) return e;
          if (null === e || ("object" != typeof e && "function" != typeof e))
            return { default: e };
          var n = r(t);
          if (n && n.has(e)) return n.get(e);
          var o = { __proto__: null },
            a = Object.defineProperty && Object.getOwnPropertyDescriptor;
          for (var i in e)
            if ("default" !== i && Object.prototype.hasOwnProperty.call(e, i)) {
              var u = a ? Object.getOwnPropertyDescriptor(e, i) : null;
              u && (u.get || u.set)
                ? Object.defineProperty(o, i, u)
                : (o[i] = e[i]);
            }
          return ((o.default = e), n && n.set(e, o), o);
        };
      },
    }));
  var t = require("../webpack-runtime.js");
  t.C(e);
  var r = (e) => t((t.s = e)),
    n = t.X(0, [172], () => r(6531));
  module.exports = n;
})();
