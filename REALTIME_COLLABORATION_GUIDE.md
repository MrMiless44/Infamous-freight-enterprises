# Real-Time Collaboration Features Guide

## Overview

Implementation guide for real-time collaboration features including presence, live editing, and conflict resolution.

## Table of Contents

1. [Architecture](#architecture)
2. [Presence System](#presence-system)
3. [Real-time Editing](#real-time-editing)
4. [Conflict Resolution](#conflict-resolution)
5. [Operational Transformation](#operational-transformation)
6. [WebSocket Optimization](#websocket-optimization)

## Architecture

### Collaboration System Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Client A      │      │   Client B      │      │   Client C      │
│  (Driver App)   │      │  (Admin Web)    │      │ (Mobile App)    │
└────────┬────────┘      └────────┬────────┘      └────────┬────────┘
         │                       │                       │
         │ WebSocket            │ WebSocket             │ WebSocket
         │                       │                       │
         └───────────┬───────────┴───────────┬──────────┘
                     │                       │
              ┌──────▼──────────────────────▼─────┐
              │  Socket.IO Server                 │
              │  - Presence Manager               │
              │  - Document Manager               │
              │  - Conflict Resolver              │
              └──────┬──────────────────────┬─────┘
                     │                      │
            ┌────────▼──────┐       ┌───────▼──────────┐
            │  PostgreSQL   │       │  Redis Pub/Sub   │
            │  (Document    │       │  (Broadcast)     │
            │   Storage)    │       │                  │
            └───────────────┘       └──────────────────┘
```

## Presence System

### Track Who's Online

```typescript
// src/apps/api/src/services/presenceService.ts
interface UserPresence {
  userId: string;
  username: string;
  status: "online" | "away" | "offline";
  lastSeen: Date;
  location?: string;
  color: string;
}

export class PresenceService {
  private presence = new Map<string, UserPresence>();

  setPresence(userId: string, presence: UserPresence) {
    this.presence.set(userId, {
      ...presence,
      lastSeen: new Date(),
    });
  }

  getPresence(userId: string): UserPresence | undefined {
    return this.presence.get(userId);
  }

  getOnlineUsers(): UserPresence[] {
    return Array.from(this.presence.values()).filter(
      (p) => p.status === "online",
    );
  }

  removePresence(userId: string) {
    this.presence.delete(userId);
  }

  updateStatus(userId: string, status: "online" | "away" | "offline") {
    const presence = this.presence.get(userId);
    if (presence) {
      presence.status = status;
      presence.lastSeen = new Date();
    }
  }
}

export const presenceService = new PresenceService();
```

### WebSocket Presence Events

```typescript
// src/apps/api/src/websocket/presence.ts
import { presenceService } from "../services/presenceService";

export function initPresenceHandlers(io: SocketIO.Server) {
  io.on("connection", (socket) => {
    // User comes online
    socket.on("user:online", (userData) => {
      const presence = {
        userId: userData.id,
        username: userData.name,
        status: "online" as const,
        color: generateUserColor(userData.id),
      };

      presenceService.setPresence(userData.id, presence);

      // Broadcast to all connected clients
      io.emit("presence:updated", {
        type: "online",
        user: presence,
      });
    });

    // User goes away (idle)
    socket.on("user:away", (userId) => {
      presenceService.updateStatus(userId, "away");
      io.emit("presence:updated", {
        type: "away",
        userId,
      });
    });

    // User comes back
    socket.on("user:back", (userId) => {
      presenceService.updateStatus(userId, "online");
      io.emit("presence:updated", {
        type: "online",
        userId,
      });
    });

    // User disconnects
    socket.on("disconnect", () => {
      // Mark as offline after 30 seconds of inactivity
      setTimeout(() => {
        presenceService.updateStatus(socket.data.userId, "offline");
        io.emit("presence:updated", {
          type: "offline",
          userId: socket.data.userId,
        });
      }, 30000);
    });
  });
}

function generateUserColor(userId: string): string {
  const colors = [
    "#FF6B6B", // Red
    "#4ECDC4", // Teal
    "#45B7D1", // Blue
    "#FFA07A", // Orange
    "#98D8C8", // Mint
    "#F7DC6F", // Yellow
  ];
  const hash = userId.charCodeAt(0) + userId.charCodeAt(1);
  return colors[hash % colors.length];
}
```

### React Presence Indicator

```typescript
// src/apps/web/components/PresenceIndicator.tsx
import { useEffect, useState } from 'react';
import { useWebSocketContext } from '@/contexts/WebSocketContext';

interface User {
  id: string;
  name: string;
  status: 'online' | 'away' | 'offline';
  color: string;
}

export function PresenceIndicator() {
  const ws = useWebSocketContext();
  const [onlineUsers, setOnlineUsers] = useState<User[]>([]);

  useEffect(() => {
    ws.subscribe('presence:updated', (event) => {
      if (event.type === 'online') {
        setOnlineUsers((prev) => [...prev, event.user]);
      } else if (event.type === 'offline') {
        setOnlineUsers((prev) =>
          prev.filter((u) => u.id !== event.userId)
        );
      }
    });

    return () => ws.unsubscribe('presence:updated');
  }, [ws]);

  return (
    <div className="flex gap-2">
      {onlineUsers.map((user) => (
        <div
          key={user.id}
          className="flex items-center gap-2 px-3 py-1 rounded-full"
          style={{ backgroundColor: user.color + '20' }}
        >
          <div
            className="w-3 h-3 rounded-full"
            style={{
              backgroundColor: user.color,
              opacity: user.status === 'online' ? 1 : 0.5,
            }}
          />
          <span className="text-sm font-medium">{user.name}</span>
        </div>
      ))}
    </div>
  );
}
```

## Real-time Editing

### Document State Management

```typescript
// src/apps/api/src/services/documentService.ts
interface Document {
  id: string;
  content: string;
  version: number;
  lastModified: Date;
  modifiedBy: string;
  locks: Map<string, string>; // userId -> lockedField
}

export class DocumentService {
  private documents = new Map<string, Document>();

  getDocument(id: string): Document | undefined {
    return this.documents.get(id);
  }

  updateDocument(id: string, content: string, userId: string): Document {
    const doc = this.documents.get(id) || {
      id,
      content: "",
      version: 0,
      lastModified: new Date(),
      modifiedBy: userId,
      locks: new Map(),
    };

    doc.content = content;
    doc.version++;
    doc.lastModified = new Date();
    doc.modifiedBy = userId;

    this.documents.set(id, doc);
    return doc;
  }

  lockField(docId: string, field: string, userId: string): boolean {
    const doc = this.documents.get(docId);
    if (!doc) return false;

    if (doc.locks.has(field) && doc.locks.get(field) !== userId) {
      return false; // Already locked by someone else
    }

    doc.locks.set(field, userId);
    return true;
  }

  unlockField(docId: string, field: string): void {
    const doc = this.documents.get(docId);
    if (doc) {
      doc.locks.delete(field);
    }
  }

  getLockedFields(docId: string): Map<string, string> {
    return this.documents.get(docId)?.locks || new Map();
  }
}

export const documentService = new DocumentService();
```

### Real-time Document Editing

```typescript
// src/apps/api/src/websocket/documents.ts
export function initDocumentHandlers(io: SocketIO.Server) {
  io.on("connection", (socket) => {
    // Subscribe to document changes
    socket.on("document:subscribe", (docId) => {
      socket.join(`document:${docId}`);

      const doc = documentService.getDocument(docId);
      if (doc) {
        socket.emit("document:loaded", doc);
      }
    });

    // Handle field lock
    socket.on("document:lock", (docId, field) => {
      const success = documentService.lockField(
        docId,
        field,
        socket.data.userId,
      );

      io.to(`document:${docId}`).emit("document:field-locked", {
        field,
        userId: socket.data.userId,
        locked: success,
      });
    });

    // Handle field unlock
    socket.on("document:unlock", (docId, field) => {
      documentService.unlockField(docId, field);

      io.to(`document:${docId}`).emit("document:field-unlocked", {
        field,
      });
    });

    // Handle content update
    socket.on("document:update", (docId, content) => {
      const doc = documentService.updateDocument(
        docId,
        content,
        socket.data.userId,
      );

      io.to(`document:${docId}`).emit("document:updated", {
        version: doc.version,
        content: doc.content,
        modifiedBy: doc.modifiedBy,
      });
    });

    // Unsubscribe
    socket.on("document:unsubscribe", (docId) => {
      socket.leave(`document:${docId}`);
    });
  });
}
```

### React Collaborative Editor

```typescript
// src/apps/web/components/CollaborativeEditor.tsx
import { useEffect, useState, useCallback } from 'react';
import { useWebSocketContext } from '@/contexts/WebSocketContext';

interface FieldLock {
  field: string;
  userId: string;
  username: string;
}

export function CollaborativeEditor({ docId }: { docId: string }) {
  const ws = useWebSocketContext();
  const [content, setContent] = useState('');
  const [locks, setLocks] = useState<FieldLock[]>([]);
  const [editingField, setEditingField] = useState<string | null>(null);

  useEffect(() => {
    // Subscribe to document
    ws.emit('document:subscribe', docId);

    ws.subscribe('document:loaded', (doc) => {
      setContent(doc.content);
    });

    ws.subscribe('document:updated', (event) => {
      setContent(event.content);
    });

    ws.subscribe('document:field-locked', (event) => {
      if (event.locked) {
        setLocks((prev) => [
          ...prev,
          { field: event.field, userId: event.userId },
        ]);
      }
    });

    ws.subscribe('document:field-unlocked', (event) => {
      setLocks((prev) =>
        prev.filter((lock) => lock.field !== event.field)
      );
    });

    return () => {
      ws.emit('document:unsubscribe', docId);
    };
  }, [docId, ws]);

  const handleFieldChange = useCallback(
    (field: string, value: string) => {
      if (!locks.some((lock) => lock.field === field)) {
        ws.emit('document:lock', docId, field);
        setEditingField(field);
      }

      setContent(value);
      ws.emit('document:update', docId, value);
    },
    [docId, locks, ws]
  );

  const handleFieldBlur = () => {
    if (editingField) {
      ws.emit('document:unlock', docId, editingField);
      setEditingField(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2 flex-wrap">
        {locks.map((lock) => (
          <span
            key={lock.field}
            className="inline-block px-2 py-1 bg-yellow-100 rounded text-sm"
          >
            🔒 {lock.field}
          </span>
        ))}
      </div>

      <textarea
        value={content}
        onChange={(e) => handleFieldChange('content', e.target.value)}
        onBlur={handleFieldBlur}
        className="w-full h-96 p-4 border rounded"
        placeholder="Start collaborating..."
      />
    </div>
  );
}
```

## Conflict Resolution

### Operational Transformation

```typescript
// src/apps/api/src/services/operationalTransform.ts
interface Operation {
  type: "insert" | "delete";
  position: number;
  content?: string;
  length?: number;
  userId: string;
  timestamp: number;
  version: number;
}

export class OperationalTransform {
  // Transform operation against another operation
  static transform(op1: Operation, op2: Operation): Operation {
    const result = { ...op1 };

    if (op1.type === "insert" && op2.type === "insert") {
      // Both inserting
      if (op1.position < op2.position) {
        // op1 comes first, op2 position shifts
        return result;
      } else if (op1.position > op2.position) {
        // op2 comes first, op1 position shifts
        result.position += op2.content!.length;
      } else {
        // Same position, use userId to break tie
        if (op1.userId < op2.userId) {
          return result;
        } else {
          result.position += op2.content!.length;
        }
      }
    } else if (op1.type === "delete" && op2.type === "insert") {
      // Deleting against insert
      if (op1.position > op2.position) {
        result.position += op2.content!.length;
      }
    } else if (op1.type === "insert" && op2.type === "delete") {
      // Inserting against delete
      if (op1.position > op2.position) {
        result.position = Math.max(op2.position, op1.position - op2.length!);
      }
    } else if (op1.type === "delete" && op2.type === "delete") {
      // Both deleting
      if (op1.position > op2.position) {
        result.position -= op2.length!;
      }
    }

    return result;
  }

  // Merge concurrent operations
  static mergeOperations(ops: Operation[]): Operation[] {
    // Sort by timestamp
    const sorted = [...ops].sort((a, b) => a.timestamp - b.timestamp);

    // Transform each operation against all previous ones
    const result: Operation[] = [];
    for (let i = 0; i < sorted.length; i++) {
      let op = sorted[i];
      for (let j = 0; j < i; j++) {
        op = this.transform(op, sorted[j]);
      }
      result.push(op);
    }

    return result;
  }
}
```

### Conflict Resolution Strategy

```typescript
// Strategies for resolving conflicts
type ResolutionStrategy = "last-write-wins" | "first-write-wins" | "merge";

function resolveConflict(
  local: any,
  remote: any,
  strategy: ResolutionStrategy = "last-write-wins",
): any {
  switch (strategy) {
    case "last-write-wins":
      return remote.timestamp > local.timestamp ? remote : local;

    case "first-write-wins":
      return local.timestamp < remote.timestamp ? local : remote;

    case "merge":
      // Smart merge strategy
      return {
        ...local,
        ...remote,
        merged: true,
        sources: [local, remote],
      };

    default:
      return local;
  }
}
```

## WebSocket Optimization

### Message Batching

```typescript
// src/apps/api/src/services/messageBatcher.ts
export class MessageBatcher {
  private queue: any[] = [];
  private batchSize = 10;
  private batchTimeoutMs = 100;
  private timeout: NodeJS.Timeout | null = null;

  constructor(private onBatch: (messages: any[]) => void) {}

  add(message: any) {
    this.queue.push(message);

    if (this.queue.length >= this.batchSize) {
      this.flush();
    } else if (!this.timeout) {
      this.timeout = setTimeout(() => this.flush(), this.batchTimeoutMs);
    }
  }

  flush() {
    if (this.queue.length > 0) {
      this.onBatch(this.queue);
      this.queue = [];
    }

    if (this.timeout) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
  }
}
```

### Compression

```typescript
// src/apps/api/src/middleware/compression.ts
import compress from "compression";

export function setupCompression(app: Express) {
  // Compress all responses larger than 1kb
  app.use(
    compress({
      filter: (req, res) => {
        if (req.headers["x-no-compression"]) {
          return false;
        }
        return compress.filter(req, res);
      },
      level: 6, // Balance between compression ratio and CPU usage
    }),
  );
}
```

---

See Also: [OPERATIONAL_RUNBOOKS.md](OPERATIONAL_RUNBOOKS.md) and [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md)
