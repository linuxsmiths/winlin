# Development ground rules

These rules apply to all development in this repository.

## Readability and simplicity

- Do not write terse or compressed code. Use descriptive names, explicit control
  flow, and readable statements instead of clever shortcuts or dense one-liners.
- Prefer the simplest correct implementation. Introduce complexity for
  performance only where performance is critical, and explain the tradeoff.
  Being a benchmark project does not make every code path performance-critical.
- Leave a blank line between logical code blocks where it helps distinguish
  initialization, validation, processing, error handling, and cleanup.
- Keep changes focused. Avoid unrelated refactoring and unnecessary abstractions.

## Comments and explanations

- Explain code with good comments unless its purpose and behavior are very
  obvious. Explain intent and rationale, not just what individual statements say.
- Write comments in clear, explanatory sentences rather than terse summaries or
  compressed jargon. Give readers enough context to understand how the code
  works and why it is structured that way without needing a separate explanation.
- Start every class or struct with a documentation comment explaining why it
  exists, what it does, who uses it, and any precautions or callouts. Include
  ownership, lifetime, thread-safety, and platform constraints where relevant.
- Add a short comment immediately before every function explaining what it
  does. Mention important preconditions, side effects, or return semantics when
  they are not obvious.
- Inside a function, comment every non-trivial logical block. Explain what it
  does and why it is needed, especially for state transitions, synchronization,
  native API contracts, performance optimizations, and resource cleanup.
- Keep comments accurate when changing behavior. Do not leave stale explanations.

## Errors and diagnostics

- Never silently dismiss an error. Check failure return values and do not swallow
  exceptions. Propagate errors to a handler that logs them with useful context.
- Log recoverable errors and explain any recovery or degraded behavior. Do not
  make a failed or incomplete benchmark look successful.
- If execution cannot proceed, emit a prominent fatal warning explaining what
  failed and exit with a nonzero status. Worker failures must reach the
  controlling thread rather than leaving a run hanging or falsely successful.
- Send diagnostics to stderr when stdout carries structured output. Never log
  run IDs or private keys.
- Preserve completed results where possible and clearly mark incomplete or
  failed runs.

## Cross-platform behavior and measurement integrity

- Keep Linux and Windows server behavior in sync. Put shared routing,
  run leases, capabilities, and telemetry schemas in the shared agent;
  keep native transport details in their platform-specific implementations.
- Never silently substitute a backend, TLS configuration, or workload. Reject
  unsupported configurations explicitly.
- Report unavailable metrics as unavailable, not zero. Document measurement
  scope and platform differences so comparisons remain honest.
- Keep unnecessary work out of measured hot paths. Document unavoidable
  instrumentation overhead rather than concealing it.

## Validation

- Use the repository's .clang-format configuration when formatting C++.
- Add focused regression tests for fixed bugs and tests for new behavior.
- Use the existing build scripts and CTest workflow; see README.md and
  docs/windows.md for platform-specific setup and commands.
- Run the relevant checks before declaring a change complete. State what was
  actually tested and any remaining limitations.
- Cross-compilation is not native runtime validation. Do not claim Windows
  behavior is verified solely because it builds on Linux.
