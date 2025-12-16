# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for Infamous Freight Enterprises.

## What is an ADR?

An Architecture Decision Record (ADR) captures an important architectural decision made along with its context and consequences.

## Format

Each ADR follows this structure:

- **Title**: Short noun phrase
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Context**: Forces at play (technical, political, social, project)
- **Decision**: Response to these forces
- **Consequences**: Context after applying the decision

## Index

- [ADR-0001](0001-monorepo-architecture.md) - Monorepo Architecture with pnpm Workspaces
- [ADR-0002](0002-shared-package-pattern.md) - Shared Package for Common Code
- [ADR-0003](0003-module-system-split.md) - CommonJS for API, ESM for Web/Mobile
- [ADR-0004](0004-scope-based-authentication.md) - Scope-Based RBAC Authentication
- [ADR-0005](0005-prisma-orm.md) - Prisma ORM for Database Management
- [ADR-0006](0006-synthetic-ai-fallback.md) - Synthetic AI Engine Fallback

## Creating a New ADR

1. Copy the template: `cp template.md XXXX-title.md`
2. Fill in the sections
3. Update this README index
4. Submit for review
