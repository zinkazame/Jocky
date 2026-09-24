# Backend API

The following routes exist in the FastAPI source and should be treated as a
prototype API, not a security-reviewed public contract:

| Route | Purpose |
|---|---|
| `GET /`, `GET /health` | Metadata and controller health |
| `GET /agents`, `POST /agents`, `GET /agents/{id}`, `DELETE /agents/{id}` | Agent management |
| `POST /agents/{id}/tasks`, `GET /agents/{id}/tasks/{task}` | Task dispatch/status |
| `POST /broadcast` | Broadcast task request |
| `GET /agents/{id}/results`, `GET /results` | Result retrieval |
| `GET /integrity/{id}`, `GET /integrity/{id}/verify` | Chain access/verification |
| `GET /stream` | Server-Sent Events |
| `POST /demo/seed` | Synthetic demo data |

Authentication, authorization, rate limiting, and input policy are not present.
The chain retrieval route uses `json.load()` although `HashChain` writes one
JSON object per line; this must be resolved before relying on the endpoint.