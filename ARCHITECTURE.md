# SYSTEM ARCHITECTURE

## High-Level Flow

Client
↓
API Gateway
↓
Synthetic Intelligence Orchestrator
↓
Skill Engine
↓
Memory Engine
↓
Actions / Automation

---

## Key Design Principles

- Intelligence lives server-side
- UI is stateless
- Memory precedes response
- Avatars represent intelligence
- Actions > text
- Observability by default

---

## AI Orchestration

1. Intent classification
2. Memory retrieval
3. Skill routing
4. Execution
5. Validation
6. Learning loop

---

## Avatar Architecture

Avatar ≠ AI  
Avatar = **representation of AI state**

Components:
- Profile
- Personality matrix
- Visual state
- Evolution engine

---

## Memory Model

Types:
- Session
- User
- Driver
- Task
- Preference

Rules:
- No hallucinated state
- Promotion by frequency
- Decay by inactivity

---

## Security Layers

- JWT + refresh tokens
- RBAC scopes
- Rate limiting
- Audit logs
- Encrypted secrets

---

## Deployment Topology

- Web: Vercel
- API: Render / Fly.io
- DB: Supabase / RDS
- Workers: Redis + Node
