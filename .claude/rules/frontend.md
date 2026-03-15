---
paths:
  - "frontend/**"
---
# Frontend Rules

## Page Pattern

Every page follows this structure:
```tsx
"use client";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { MyType } from "@/lib/types";

export default function MyPage() {
  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        <h1 className="text-xl font-semibold">Title</h1>
        <p className="text-sentinel-muted text-sm mb-4">Description</p>
      </div>
    </AppLayout>
  );
}
```

Adding a new page: create dir in `src/app/`, add to `Sidebar.tsx` NAV_GROUPS, add types to `types.ts`, add API method to `api.ts`.

## Design Tokens (Dark Theme Only)

```
sentinel-bg: #0B0E14     sentinel-surface: #111720   sentinel-card: #161D2A
sentinel-border: #1E2A3A  sentinel-hover: #1A2435     sentinel-text: #E2E8F0
sentinel-muted: #94A3B8   sentinel-accent: #06B6D4    sentinel-green: #22C55E
sentinel-red: #EF4444     sentinel-orange: #F59E0B     sentinel-purple: #A78BFA
```

Font: `font-mono` (JetBrains Mono). Severity: critical=red, high=orange, medium=blue, low=green, info=gray.

## API Client

- All API calls go through `api.ts` typed methods. No raw `fetch()`.
- Types must match backend Pydantic schemas exactly.
- WebSocket via `useWebSocket` hook in `hooks/useWebSocket.ts`.
