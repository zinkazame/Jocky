# Backend Overview

The current backend surface is the FastAPI application in
`management_interface/dashboard/api.py`. It creates an `AgentController`,
connects result callbacks to integrity chains and an SSE queue, and serves
management routes.

Status: PARTIALLY IMPLEMENTED. No separate service layer, database, production
configuration, or authentication module was found.