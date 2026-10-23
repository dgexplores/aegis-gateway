# AEGIS portfolio brief

Recorded 2026-10-22. Scope: existing gateway implementation and redesigned
landing page. Owner: Deepak Gangwar; AI-assisted development.

## Technical review entry point

Use the [engineering case study](RECRUITER-CASE-STUDY.md) and run
`make recruiter-evidence` to reproduce payload, poisoned-context, tenant-state,
provider-failure and audit-tampering observations. The generated report uses
recording/failing providers and makes no model API calls. It is a fixture-based
engineering demonstration, not a security certification.

The local suite after showcase changes recorded 533 passed, 5 skipped. The
verification ledger below records the earlier landing-page run in its original
scope.

## The project in one minute

AEGIS puts tenant controls, request screening, recognized-PII pseudonymization,
provider routing and linked audit records in front of AI calls. The Python API
and browser console make those decisions visible. Its default echo provider is
an offline demonstration path, not a trained model or a quality benchmark.

## What changed in the presentation

- Replaced the illustrated marketing layout with a request-path diagram, clear
  demo labeling, a functional console entry point and a technical reviewer path.
- Removed hardcoded latency, recall and perfect-protection statements from the
  landing page. Retained only the explicitly recorded local test result.
- Made the input/alias diagram explicitly illustrative; it does not impersonate
  a live request trace or promise an exact pseudonym format.
- Kept the existing working dashboard and operator controls intact.
- Rewrote the README around reproducible setup, architecture, boundaries,
  verification and common interviewer questions.

## Verification ledger

| Evidence | Result | What it does not establish |
|---|---|---|
| Local `python -m pytest tests -q` | 527 passed, 5 skipped | Hosted CI, production security or provider quality |
| Live-provider tests | Skipped without a configured endpoint/model/key | Successful calls to a real model |
| Reference screenshots | Existing local screenshots; labeled historical | Current hosted response or deployment configuration |
| Public deployment | Root workflow must verify the newly published commit | A landing-page build alone is not an API walkthrough |

A test count can change when tests change. Re-run the suite and update this
record together rather than silently reusing the number for a different commit.

## Suggested interview explanation

“I worked on a Python gateway that applies tenant and request controls before
AI calls and records the decision for inspection. The offline provider lets me
reproduce failure and security cases without a paid API. I distinguish those
checks from real-provider testing, and I document the limits of pattern-based
masking, audit retention and single-process deployment.”

Only describe contributions you understand and can demonstrate. Do not claim
all leakage is prevented, all prompt injections are blocked, or that test fixture
results imply production reliability. Real provider performance and usage cost
need a separately recorded workload and configuration.
