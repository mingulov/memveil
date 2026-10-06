# Valid-empty capture fixture

Real privileged host recording (10 s window, kernel
7.0.0-34-generic, validated profile bindings hold) over an idle
machine: four counter snapshots, zero bounce attempts, lossless
detail. Only the `boot_id` was replaced (host value removed);
all other bytes are the writer's original output.

Expected replay: exit 4 (terminal partial by design), detail
`complete_for_scope` loss 0, every attempt metric `0` — visibly
distinct from unavailable (`null`) metrics.
