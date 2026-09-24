# Controller Architecture

```mermaid
flowchart LR
 D[Dashboard/API caller] --> C[AgentController]
 C --> S[AgentSession state]
 C --> Q[AgentTask queues]
 C --> T[Transport adapter]
 T --> R[Result callback]
 R --> I[Integrity layer]
```

The state model includes pending, connected, tasked, collecting, idle, lost,
and terminated states. The controller stores results in memory with a bounded
retention count. It does not provide durable recovery or access control.