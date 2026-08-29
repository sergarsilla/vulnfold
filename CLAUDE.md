# CLAUDE.md — Engineering standards for vulnfold

Read `CONTEXT.md` first. It holds the strategy and the architecture decisions
(D1-D4) that constrain everything below.

---

## Language

**Everything in this repository is written in English.** Code, identifiers,
comments, docstrings, documentation, commit messages, test names, log messages,
error strings, CLI help text and issue titles. No exceptions, including when the
maintainer writes to you in Spanish.

---

## Before you write code

1. State what you understood from the specification, in your own words.
2. List every design decision the spec does not cover.
3. **Ask instead of assuming.** A wrong assumption implemented cleanly is more
   expensive than a question.
4. Do not start until ambiguities are resolved.

Never expand scope beyond the specification. If something looks like it "should
obviously also do X", say so and wait — do not build it.

---

## Code standards

**Typing.** Full type hints on every function signature, including return types.
The codebase must pass `mypy --strict`. No `Any` without a comment explaining
why it is unavoidable.

**Structure.** Domain logic is pure: functions that take data and return data,
no I/O. All I/O lives at the boundary (`client.py`, `render.py`, `cli.py`).
This is what makes the core testable without mocks.

**Dependencies flow inward.** `collapse.py` must not import `client.py`.
Pass data in, do not reach out for it.

**Naming.** Names state intent, not implementation. `collapse_findings_to_actions`
not `process_data`. No abbreviations except universally understood ones
(`cve`, `url`, `id`).

**Errors.** Custom exception types deriving from a single `VulnfoldError` base.
Never a bare `except:`. Never `except Exception:` without re-raising or logging
with full context. Error messages state what failed, what was expected, and what
the user can do about it.

**Functions.** One reason to exist. If a docstring needs the word "and" to
describe what it does, split it.

**Configuration.** No magic numbers or hardcoded strings in logic. Constants at
module top or in `config.py`. Field names live only in `mappings/` (see D1).

**Comments.** Explain *why*, never *what*. Code that needs a comment to explain
what it does should be rewritten. No commented-out code — that is what git is
for. No `TODO` without a linked issue number.

**Public API.** Docstrings on every public function and class: one-line summary,
`Args`, `Returns`, `Raises`. Google style.

---

## Testing

- `pytest`. Test names describe behaviour: `test_collapse_groups_same_package_across_agents`,
  not `test_collapse_1`.
- Arrange / Act / Assert, visually separated.
- Mock only at the boundary you own the contract for. Use `respx` for HTTP;
  never mock your own domain functions.
- Every edge case listed in the spec gets its own named test.
- A bug fix starts with a failing test that reproduces it.
- No test depends on another test's state or on execution order.

---

## Security posture

This is a security tool operating against a customer's SIEM. Hold a higher bar
than usual:

- **Never write to the cluster.** Any code path that could issue a non-read
  request is a defect, not a feature request.
- Credentials come from environment variables or a config file, never from CLI
  arguments (shell history, `ps`) and never from source.
- Never log credentials, tokens, or full request bodies that may contain them.
- TLS verification is on by default; disabling it requires an explicit flag and
  prints a warning.
- Pin dependency versions. Every new dependency must be justified — each one is
  supply-chain surface in a tool that reads security data.

---

## Commits

Conventional Commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`.
Subject in imperative mood, under 72 characters. The body explains *why* when
the change is not self-evident. One logical change per commit.

---

## What to do when the spec is wrong

If, while implementing, you find that the specification leads to a bad design,
**stop and say so** with the reasoning. Do not silently implement something
better and do not silently implement something you know is wrong. The
specification is a decision, and decisions can be revised — but explicitly.