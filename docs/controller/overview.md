# Controller Overview

`management_interface/agent_controller.py` manages in-memory agent sessions,
task descriptors, result queues, state transitions, polling, and callbacks. It
runs an asyncio loop in a background thread and exposes synchronous methods for
the API layer.

Status: PARTIALLY IMPLEMENTED. Durable state, authentication, and a verified
agent protocol are absent.