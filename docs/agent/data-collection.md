# Data Collection

The IR ABI and native forensics directory reference process, memory, network,
registry, filesystem, and related operations. The native bridge implements some
of these and leaves others as no-ops. The Python forensic primitive files are
placeholders. Therefore the project supports a collection *shape* and several
experiments, not a complete cross-component capability matrix.

Every future adapter should define inputs, output schema, required privilege,
failure behavior, data minimization, and an integrity event.