# SPEC-03 — Complete the scanner-condition grammar

**Precondition:** SPEC-02 is implemented and merged.

**Goal:** stop the plan printing a target version that is not a version.

---

## 0. The defect

A live run prints this row, ranked 8th of 20:

```
| n8n | 1.101.2 | or equal to 1.114.4 | 1 | 190 | 51 crit |
```

`or equal to 1.114.4` is not a version. `vulnerability.scanner.condition` has
four grammatical forms, and the mapping only models two:

| Form | Findings | Share | Handled today |
|---|---|---|---|
| `Package default status` | 19,039 | 58.19% | yes — register |
| `Package less than <v>` | 13,659 | 41.75% | yes — plan |
| `Package equal to <v>` | 15 | 0.05% | no — `unrecognized_fixability` |
| `Package less than or equal to <v>` | 5 | 0.02% | **no — silently mis-parsed** |

`Package less than or equal to 1.114.4` begins with the string
`Package less than `, so the prefix strip leaves `or equal to 1.114.4` and the
finding is classified fixable with that as its target version.

**The blast radius is far larger than five findings.** `max_target_version`
compares run-by-run with non-digit runs ordered by ASCII, where `o` sorts above
every digit. So the malformed string wins the maximum for its whole group:

```python
max_target_version(["1.114.4", "or equal to 1.114.4"]) == "or equal to 1.114.4"
```

One bad finding therefore replaces the target version of every action that
merges with it — in the observed case, an action covering 190 findings and 51
criticals. Any `(package, version)` group containing one of these five findings
displays a wrong target.

---

## 1. Semantics — decide before coding

Neither new form names a fixed version.

- **`Package equal to <v>`** — exactly that version is affected. Nothing states
  what to move to.
- **`Package less than or equal to <v>`** — everything up to *and including*
  `<v>` is affected. Naming `<v>` as the target would be actively wrong: `<v>`
  is itself vulnerable. The safe version is *some* release above it, and the
  vendor has not said which.

Both therefore mean **affected, with no concrete fixed version available**, which
is the register's definition. Route both to `NO_FIX`.

Rejected alternative: render the target as `> 1.114.4` and keep them in the
plan. It reads well but breaks the contract that `target_version` is a version
string, and it puts an unverifiable instruction into the artefact an auditor
reads. The register says something true; the plan would be guessing.

---

## 2. Mapping — `mappings/wazuh-4.x.yaml`

`fixability` gains a prefix list beside the exact-match list:

```yaml
fixability:
  no_fix_values: ["Package default status"]
  # Conditions that identify an affected range but name no fixed version.
  no_fix_prefixes:
    - "Package equal to "
    - "Package less than or equal to "
  fixed_version_prefix: "Package less than "
```

`FixabilityRules` gains `no_fix_prefixes: list[str]`.

**Matching order is load-bearing and must be asserted by a test:** exact values,
then `no_fix_prefixes`, then `fixed_version_prefix`. Evaluating
`fixed_version_prefix` first reintroduces exactly this bug, because
`Package less than ` is a prefix of `Package less than or equal to `.

---

## 3. Guard — `versions.py`

`max_target_version` must never be handed a non-version string again, and must
not silently order one if it is. Add a cheap validity predicate — a candidate
must begin with a digit or an epoch (`<digits>:`) — and raise a `ValueError`
naming the offending string when a candidate fails it.

This is a defence-in-depth assertion, not the fix. The fix is §2. The guard
exists so that the next unmodelled condition form fails loudly at the point of
damage instead of printing prose into a version column.

---

## 4. Acceptance criteria

1. `mypy --strict` clean; the suite stays green.
2. Against the recorded fixture, the split becomes **13,659 fixable / 19,059
   no-fix**, criticals unchanged at 1,322 / 1,170 unless the twenty reclassified
   findings carry criticals, in which case state the new numbers and explain the
   move. `unrecognized_fixability` no longer fires: all 418 distinct condition
   strings are now modelled.
3. No `target_version` anywhere in a rendered plan begins with a non-digit.
   Assert over the whole plan, not a sample.
4. A test named for this defect asserts that
   `Package less than or equal to 1.114.4` classifies as `NO_FIX` and never
   reaches `max_target_version`.
5. A test asserts the matching order directly: a rules object whose
   `fixed_version_prefix` would also match a `no_fix_prefixes` entry still
   classifies as `NO_FIX`.
6. `max_target_version` raises `ValueError` on a non-version candidate, with the
   offending value in the message.
7. The n8n action's target is sourced from its remaining `Package less than`
   findings.

> **Criterion 7 corrected 2026-08-31.** This originally demanded the target
> become `1.114.4`. That was wrong, and it was wrong because it was read off the
> corrupted row rather than from the data. `n8n 1.101.2` carries 52 distinct
> conditions: 51 name a fixed version and one is the inclusive bound. The
> highest of the 51 is **`2.31.5`**, which is what the implementation correctly
> produces. Verified independently against the indexer. A criterion asserting a
> specific value must be derived from the source data, never from the output
> being fixed.

---

## 5. What not to do

- **Do not special-case the strings in Python.** Every condition string belongs
  in `mappings/`. That is D1, and it is the reason this fix is a YAML change plus
  an ordering rule rather than a parser rewrite.
- **Do not widen `fixed_version_prefix` with a regular expression.** The failure
  here was an over-eager prefix match; a regex makes the next one harder to see.
- **Do not drop the unrecognised-condition warning.** It did its job for
  `Package equal to`, and it is the only thing that will catch form five.
