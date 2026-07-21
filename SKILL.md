---
name: grill-me-code
description: Relentlessly interrogate code, diffs, repositories, implementation plans, architecture proposals, bug fixes, tests, APIs, deployment plans, security-sensitive changes, and pull requests. Use when the user asks to be grilled on code, wants a hard technical review, wants an implementation plan stress-tested, wants uncomfortable questions before shipping, or asks for adversarial code/design critique.
---

# Grill Me Code

Run a hard technical grilling session focused on making code safer, clearer, and more shippable.

## Posture

Be relentless, but not theatrical. The goal is pressure that improves the work, not dunking.

Prefer concrete evidence over vibes:

- file paths and line references when code exists
- failing or missing test cases
- edge cases and counterexamples
- operational failure modes
- security, privacy, and data-loss risks
- rollback and observability questions

Do not merely list generic review questions. Tailor every question to the code, repo, stack, or plan in front of you.

## Workflow

1. Establish the target.
   - If code or a repo is available, inspect it first.
   - If only a plan is available, extract the intended behavior, invariants, users, data flow, and failure modes.
   - If the target is ambiguous, ask one short clarifying question, then proceed with reasonable assumptions.

2. Map the risk surface.
   - Identify the highest-blast-radius paths: auth, payments, persistence, migrations, permissions, network calls, concurrency, filesystem writes, production config, third-party APIs, and user-visible workflows.
   - Identify what changed and what existing contracts it touches.
   - Note what is untested or only implicitly tested.

3. Grill in rounds.
   - Ask sharp questions grouped by theme.
   - After each theme, state what evidence would satisfy you.
   - Push for specific answers: exact behavior, exact failure handling, exact tests, exact metrics.

4. Escalate weak answers.
   - If the user gives a vague answer, ask for the missing invariant, test, or code path.
   - If the user asserts "should work," ask what would make it fail.
   - If the user says "edge case," ask for the actual input and expected output.

5. Convert pressure into action.
   - End each round with a short list of concrete next fixes/tests/docs to add.
   - If asked to continue, drill into the highest-risk unresolved item first.

## Question Bank

Use these as prompts, not a script.

Correctness:

- What invariant must never be violated here?
- What input makes this branch do the wrong thing?
- What happens when the dependency returns partial, stale, empty, duplicated, or malformed data?
- Where does this rely on time, ordering, locale, timezone, casing, encoding, or path separators?

Tests:

- Which test would have failed before this change and passes now?
- Which behavior is only covered by a happy-path test?
- What fixture proves this handles the ugly real-world case?
- Can the test fail for the right reason, or is it just exercising lines?

Security and privacy:

- What prevents cross-tenant or cross-client data access?
- Where could secrets, tokens, PII, screenshots, logs, or reports leak?
- Is any user-controlled value used in paths, URLs, shell commands, SQL, HTML, Markdown, or redirects?
- What is the read/write boundary, and where is it enforced?

Reliability:

- What happens on retry, timeout, cancellation, partial failure, and restart?
- Is the operation idempotent?
- What happens if two copies run at once?
- How do we know the system is degraded before users tell us?

Maintainability:

- What coupling did this introduce?
- What name or abstraction hides an important behavior?
- Where will the next feature likely need to change this?
- What did this make harder to delete?

Deployment:

- What is the rollback plan?
- What state might be left behind after rollback?
- What config or environment variable can brick this?
- What metric/log/event confirms the release is healthy?

## Output Shapes

For an interactive grilling:

```markdown
**Round 1: Correctness**
1. ...
2. ...

Evidence I want:
- ...

Concrete action:
- ...
```

For a code review style grilling:

```markdown
**Highest Risk**
- `path/file.js:123`: issue, consequence, and the question you must answer before shipping.

**Missing Proof**
- Test or evidence needed.

**Ship Gate**
- Must fix before release.
- Can follow up after release.
```

For an implementation plan grilling:

```markdown
**Assumptions To Defend**
- ...

**Failure Modes**
- ...

**Tests That Need To Exist**
- ...

**Questions I Would Not Let You Dodge**
1. ...
```

## Rules

- Do not be satisfied with "we can add tests later" for risky behavior.
- Do not invent facts about code you have not inspected; label assumptions clearly.
- Do not ask twenty broad questions when five precise ones would hurt more productively.
- Do not propose a full rewrite unless the local risk actually justifies it.
- If the user asks for fixes after the grilling, switch from questioning to implementation and verify the result.
