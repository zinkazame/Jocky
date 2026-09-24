# Agent Runtime

The documented lifecycle is: initialize configuration, establish an authorized
session, receive a bounded task, execute a supported adapter, create a result,
record errors, and close the session. `transport/cdn_router.py` implements a
background check-in loop, retry/backoff, and circuit-breaker state. It does not
complete task dispatch into the execution engine.

Status: PROTOTYPE/PARTIAL. This page intentionally omits deployment, evasion,
persistence, or unauthorized-access instructions.