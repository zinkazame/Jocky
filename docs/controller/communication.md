# Controller Communication

The API calls controller methods for registration, tasking, broadcast, status,
results, and shutdown. The controller is intended to use the transport adapter
for agent communication. Current code contains a protocol mismatch risk: task
dispatch and transport result methods need a reviewed contract, and the
transport `_dispatch_command()` hook is not connected to a collection backend.

Status: PROTOTYPE integration. Proposed future work includes versioned message
schemas, mutual authentication, replay protection, timeouts, authorization,
and contract tests with a mock agent.