# ADR-0007: Architecture Freeze and Change Control

**Title**: Architecture Freeze and Change Control

**Number**: ADR-0007

**Status**: Accepted

**Date**: 2026-01-09

---

## Context

The repository has experienced repeated structural churn (package moves, layering shifts, and tooling pivots) that slows delivery and increases review overhead. The current architecture is documented and stable, and the immediate priority is to stop architectural thrash while allowing incremental, product-focused work to continue.

---

## Decision

We will **freeze the architecture** and introduce explicit change control for any structural modifications.

**Frozen elements (default no-change):**

- Monorepo layout and workspace boundaries.
- Layer responsibilities documented in `docs/architecture.md`.
- API/Web/Mobile app boundaries and shared package structure.
- Deployment topology (API, web, mobile, data stores) unless a business-critical exception is approved.

**Permitted changes without an ADR:**

- Feature work that stays within existing modules.
- Refactors that do not move ownership boundaries (packages/apps remain where they are).
- Dependency upgrades that do not require moving files across layers.
- Performance or reliability fixes that preserve the existing architecture.

**Changes that require an ADR + approval:**

- Moving or renaming top-level apps/packages.
- Splitting or merging packages.
- Changing the API/web/mobile boundary (or moving shared logic between them).
- Replacing the core stack (runtime, framework, ORM, database, queueing).
- Introducing new deployment topology or breaking existing CI/CD flows.

---

## Alternatives Considered

| Option                  | Pros                     | Cons                             | Why Not Chosen                      |
| ----------------------- | ------------------------ | -------------------------------- | ----------------------------------- |
| Continue ad-hoc changes | Fast for one-off changes | Ongoing churn, unclear ownership | Too costly long-term                |
| Full rewrite            | Clean slate              | High risk, long delivery         | Not aligned with current priorities |

---

## Consequences

**Positive:**

- ✅ Predictable delivery and review cycles.
- ✅ Reduced architectural churn and clearer ownership boundaries.
- ✅ Easier onboarding with stable docs and layout.

**Negative:**

- ❌ Architectural improvements require more process.
- ❌ Some optimizations may be deferred.

**Mitigations:**

- Use lightweight ADRs for justified changes.
- Revisit the freeze quarterly or when business priorities shift.

---

## Related Decisions

- [ADR-0001: Monorepo Architecture](0001-monorepo-architecture.md)
- [ADR-0002: Shared Package Pattern](0002-shared-package-pattern.md)
- [ADR-0003: Module System Split](0003-module-system-split.md)
