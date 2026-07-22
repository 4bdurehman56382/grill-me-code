# Jury Mode

Use this when the user asks for a deeper grill, cross-functional review, or market-grade differentiation.

When `scripts/grill_runner.py` is available, use its `jury_scores` output as the factual floor for Jury Mode. The LLM layer may add reasoning and edge-case questions, but it must not claim a lens has been tool-verified unless the runner, project checks, or another real tool produced evidence.

## Lenses

### Breaker

Goal: find the input, state, timing, or dependency failure that breaks behavior.

Ask:

- What happens at zero, one, many, null, empty, expired, duplicated, or reordered?
- What race or retry makes this wrong?
- What dependency response shape makes the code lie?

### Security

Goal: find abuse paths and data exposure.

Ask:

- Can user input reach shell, SQL, path, HTML, or eval?
- Are secrets, tokens, IDs, or logs exposed?
- Is authorization checked where the data is used, not just where the UI links?

### Tester

Goal: demand proof.

Ask:

- Which test would fail before the fix?
- Does the assertion prove behavior or just implementation details?
- What branch is untested?

### Refactorer

Goal: protect contracts during cleanup.

Ask:

- What public behavior must stay identical?
- Which callers depend on this shape?
- Is the new abstraction real or decorative?

### Release Captain

Goal: protect production.

Ask:

- What is the rollback?
- What config, migration, queue, job, cron, or cache must be coordinated?
- What log/metric proves the release is healthy?

### Maintainer

Goal: make future work easier.

Ask:

- Is the intent readable without tribal context?
- Is complexity now lower, or merely moved?
- What will the next engineer misunderstand?

### Minimalist

Goal: make the correct solution shorter.

Ask:

- Can this be deleted, reused, or handled by the standard library?
- Is this dependency, wrapper, factory, interface, or config buying flexibility that is not used?
- What proof must stay even if the diff gets smaller?

## Verdict

End Jury Mode with:

```markdown
## VERDICT

Decision: SHIP | SHIP WITH RISKS | DO NOT SHIP | BLOCKED
Why:
- ...
Proof:
- ...
Remaining risks:
- ...
```
