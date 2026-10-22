# AEGIS: engineering an inspectable boundary around AI requests

**Role relevance:** backend engineering, application security, and AI platform integration.

**The interview question:** Can this engineer define a trust boundary, reproduce its failures, and explain what the evidence actually establishes?

AEGIS is a Python/FastAPI gateway between an application and an AI provider.
A fictional company policy assistant makes the workflow tangible. The engineering
case rests on request orchestration, tenant boundaries, failure handling and
audit verification. The model itself is an external dependency.

## Start with an experiment a reviewer can reproduce

```bash
pip install -e '.[dev]'
python scripts/recruiter_demo.py --output-dir work/recruiter-evidence
```

Open `work/recruiter-evidence/index.html`. The adjacent JSON includes the
observations and SHA-256 fingerprints of the source files used. The command
returns nonzero if a fixture check fails. It uses production pipeline components
with a recording provider and a deliberately failing provider, makes no model
API calls, and writes only temporary audit files and the requested report.

An example report is committed as [HTML](recruiter-evidence.html) and
[JSON](recruiter-evidence.json). Download both to view the HTML locally. Generate
a fresh report when reviewing another source version; the example is a recorded
run, not a live assertion about every future commit.

| Experiment | What is directly observed | Engineering signal |
|---|---|---|
| Direct request compared with guarded request | Recording provider receives the raw fictional email on the direct call and an alias through AEGIS; the caller receives the restored value | Tests the downstream boundary, beyond a UI badge |
| Personal data in a system-role turn | The actual provider payload contains the alias | Applies privacy handling across message roles |
| Supported injection in a user message | Refusal plus zero additional recording-provider calls | Tests absence of downstream side effects |
| Injection in retrieved document text | Source is retrieved; request is refused; downstream call count stays unchanged | Treats retrieval context as untrusted input |
| Another tenant uses the same question and alias | No source from the first tenant is retrieved; its alias cannot be restored through the second tenant's map | Separates tenant state at the service layer |
| Primary provider deliberately fails | One failed attempt, then one recording-fallback call | Exercises provider failure control flow |
| Retained audit entry is edited in an isolated copy | Original verifies, altered copy fails verification | Tests evidence integrity with a negative control |

The recording provider returns its input to exercise the restoration path.
It is a test double, not a language model. The tenant experiment is below the
HTTP layer; API authentication and scopes are covered by separate tests.

## Three engineering decisions worth discussing

### 1. One pipeline for every message role

A request can carry sensitive data or instructions in user, assistant, or system
turns. Retrieved documents also arrive as system-role context. The gateway scans
and redacts every turn before routing, so a role label is not a bypass.

**Trade-off:** a pattern scanner can refuse legitimate text and miss unfamiliar
attacks. The evidence establishes the listed fixtures; a real application needs
its own benign and adversarial workload evaluation.

**Code:** [orchestration](../src/aegis/gateway.py) ·
[trust-boundary regressions](../tests/test_trust_boundary.py).

### 2. Record decisions and test altered evidence

The audit log links records with hashes and signs record material with HMAC.
The evidence experiment edits a retained record in a copy and checks that the
verifier rejects it. Existing recovery tests go further into interrupted writes
and restore behaviour.

**Trade-off:** an HMAC verifier shares secret-key trust; this is not public-key
non-repudiation. A valid retained chain alone cannot establish that its tail was
not lost. Backups, external head anchors, key handling and multi-replica history
remain operational concerns. Audit metadata is not a complete transcript of
what every model said.

**Code:** [audit implementation](../src/aegis/security/audit.py) ·
[crash-safety tests](../tests/test_audit_crash_safety.py).

### 3. Provider failure must have an explicit meaning

The registry attempts the configured provider chain and records successful
routing. The experiment injects a failure and observes which downstream provider
is called next. The console identifies echo responses explicitly.

**Trade-off:** a deterministic echo fallback preserves a test path, but does not
supply an intelligent answer. A company pilot needs an explicit unavailable or
fallback policy and real-provider verification. Failure-flow tests and model
quality are separate questions.

**Code:** [provider registry](../src/aegis/providers/registry.py) ·
[provider contract](../src/aegis/providers/base.py).

## How to present it in five minutes

- **Problem, 30 seconds:** “I wanted internal AI calls to have a defined control boundary and inspectable decisions.” Explain the employee → application → gateway → provider path.
- **Evidence, 90 seconds:** show the direct and guarded payload comparison. Then show the refused attack with a downstream call count of zero.
- **Harder case, 60 seconds:** show that a poisoned retrieved document is treated as untrusted input. Explain why scanning only the user message would miss it.
- **Failure and integrity, 60 seconds:** show the injected provider failure and the audit-copy edit that fails verification.
- **Judgment, 60 seconds:** discuss pattern limits, echo fallback, and why a retained chain does not prove complete history. Describe the next experiment you would run with a real model and representative workload.

Use the policy assistant as the application context. Give most of the technical
time to a few claims you can prove and explain.

## Ownership and interview preparation

This project was developed with AI assistance. Describe your actual contribution
accurately. Before putting a claim on your resume, be able to locate its code,
run its experiment, explain its failure case, and make a small change to it.

Prepare answers to these questions:

1. At what point can raw personal data leave the application, and what can the detector miss?
2. Why is retrieved text not automatically trusted because it comes from a company document?
3. What does a valid HMAC-linked log prove, and what does it leave unknown?
4. What happens when the primary provider fails and echo answers instead?
5. Which state is per process, and what must change before adding replicas?
6. Which parts did you design, verify, or change yourself, and where did AI assist?

A defensible resume description, after you can explain the implementation:

> Developed an AI-assisted Python/FastAPI gateway with tenant-scoped retrieval,
> recognized-PII masking, request screening, provider failover and HMAC-linked
> audit records. Built a reproducible evidence runner that captures downstream
> payloads and exercises poisoned context, provider failure and audit tampering.

Do not add customer adoption, independent authorship, production throughput,
model-quality results, or universal protection claims without supporting work.
