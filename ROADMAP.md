# Roadmap

AEGIS targets developers and IT teams integrating controls around internal AI
assistants. The company policy assistant is the first demonstrable use case.
[Current status](STATUS.md) distinguishes implemented functionality from verified
company operation.

## 1. Verify a real-provider integration

Configure one external provider in a controlled environment. Pass the live
provider tests without skips, review policy answers against approved documents,
and record provider identity, latency, failure behaviour and usage cost.
A citation alone does not establish answer correctness.

## 2. Complete one company pilot

Choose one application and operator. Map authenticated company users to scoped
tenant requests in the application's backend; use private credentials and an
approved corpus. Define behaviour for refusals, rate limits and provider outages.
Test document isolation and corpus updates with the actual integration.

## 3. Prove persistence and recovery

Run the chosen Redis/Postgres/object-storage configuration. Exercise restart,
backup/restore, retention and key rotation. Define the retained audit history
and its completeness guarantees before scaling to multiple replicas.

## 4. Evaluate representative traffic

Extend benign, sensitive-data, retrieval and adversarial fixtures from the pilot's
real traffic shapes. Publish bounded results with the corpus and configuration,
including false positives and failure cases. Avoid combining unrelated historical
fixture results into one performance claim.

## 5. Operational acceptance

Assign ownership for monitoring, incident response and secrets. Exercise provider
and storage outages, measure workload limits, and independently review security
before broader production onboarding. See the detailed
[production-readiness plan](docs/PRODUCTION-READINESS.md).

## Product scope

The project remains a gateway that teams run and integrate. It does not train a
model, establish compliance by itself or provide a general-purpose employee app.
The console and video demonstrate the controls and explain how to use the APIs.
