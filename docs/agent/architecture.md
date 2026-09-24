# Agent Architecture

```mermaid
flowchart TD
 T[Task contract\nPROPOSED] --> P[Policy and argument checks\nPLANNED]
 P --> A[Collection adapter\nPARTIAL]
 A --> M[Metadata/result envelope\nPROPOSED]
 M --> C[Controller transport\nPROTOTYPE]
 M --> H[Integrity record\nPARTIAL]
```

Native collectors under `execution_engine/forensics/` and the Python modules
under `forensic_primitives/` do not currently form one complete adapter API.
The transport router's command dispatch is explicitly a hook.