"""Shared run-state constants used by database mixins and callers."""

RUN_RUNNING = "running"
RUN_DONE = "done"
RUN_FAILED = "failed"
RUN_CANCELLED = "cancelled"
RUN_IMPORTED = "imported"
RUN_SUPERSEDED = "superseded"
RUN_KIND_AUDIT = "audit"
RUN_KIND_MAINTENANCE = "maintenance"
RUN_KINDS = frozenset({RUN_KIND_AUDIT, RUN_KIND_MAINTENANCE})
RUN_STATUSES = frozenset(
    {
        RUN_RUNNING,
        RUN_DONE,
        RUN_FAILED,
        RUN_CANCELLED,
        RUN_IMPORTED,
        RUN_SUPERSEDED,
    }
)
