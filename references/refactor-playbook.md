# Refactor Playbook

Use this when the user asks `grill-me-code` to improve, debug, harden, or refactor code.

## Fix Loop

1. Start from findings, not vibes.
2. Group fixes by behavioral risk.
3. Keep each edit narrow and reversible.
4. Preserve public contracts unless the user approves a breaking change.
5. Add or adjust tests for the behavior at risk.
6. Run the smallest meaningful check first, then the broader suite.
7. Re-grill the changed surface after tests pass.

## Red Flags

Stop and ask before:

- changing public API shape
- changing database schema or migration order
- altering auth, billing, permissions, or destructive actions
- deleting large code paths without proof they are unused
- replacing a proven library with handwritten logic

## Refactor Types

`clarify`:
- improve names, function boundaries, and data flow
- preserve behavior exactly

`harden`:
- add validation, error handling, timeouts, retries, and safe defaults
- prove bad inputs fail safely

`simplify`:
- remove duplication or reduce branching
- keep tests around old behavior green

`extract`:
- create helpers only when duplication or complexity justifies it
- keep helper APIs local and boring

`replace`:
- swap implementation behind an existing contract
- add parity tests or golden cases first

## Verification Ladder

Use the highest practical rung:

1. Syntax or type check for touched files.
2. Focused unit tests for changed behavior.
3. Integration tests for wiring.
4. End-to-end or manual browser checks for real user flows.
5. Release/rollback checklist for production-sensitive changes.

If a check cannot run, say exactly why and what risk remains.

## Re-Grill Pass

After fixes, ask:

- Did the fix address the root cause or only the symptom?
- Did it create a new branch without test coverage?
- Did it preserve existing behavior?
- Is the failure mode now safer?
- Did any verification pass for the wrong reason?
- What would a second reviewer still object to?
