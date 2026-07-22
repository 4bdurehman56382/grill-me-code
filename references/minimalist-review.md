# Minimalist Review

Use this when `grill-me-code` needs to hunt over-engineering, unnecessary code, speculative abstractions, dependency bloat, or a shorter safe implementation path.

This reference adapts the Ponytail idea of lazy senior engineering: do less, but only after understanding the real flow. It is not a license to skip safety, tests, validation, accessibility, or user-requested behavior.

## Ladder

Stop at the first rung that honestly works:

1. Delete the feature or code if the need is speculative.
2. Reuse an existing helper, type, route, component, or pattern.
3. Use the standard library.
4. Use a native platform feature.
5. Use an already-installed dependency.
6. Collapse the change to the shortest readable diff.
7. Only then add new code, files, config, abstractions, or dependencies.

## Runner Signals

The runner marks Minimalist findings with `MIN-*` codes:

- `MIN-001`: dependency may be replaceable by native or standard-library behavior.
- `MIN-002`: tiny wrapper only delegates to another callable.
- `MIN-003`: interface, protocol, factory, or builder may be speculative.

`lite` mode only checks low-noise dependency signals. `full` and `ultra` also inspect wrappers and abstractions.

## Questions

- Does this need to exist?
- Is there already a local helper or platform feature?
- Is this abstraction backed by multiple real implementations?
- Did this dependency replace three lines of native code?
- Can this fix land in one shared root-cause location instead of many callers?
- What safety or test proof must remain even if the diff gets shorter?

## Boundaries

Never simplify away:

- trust-boundary validation
- security checks
- data-loss prevention
- accessibility basics
- durable error handling
- behavior the user explicitly requested

Minimal code is a shipping advantage only when it is also correct.
