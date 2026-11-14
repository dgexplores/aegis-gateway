# Reproducible evaluation runs

The existing evaluator now saves the inputs and evidence behind its score.
No new service or dependency is required. Run from the repository root after
installing `.[dev]` in a virtual environment.

```sh
make eval-report

# Compare against a prior JSON report; use a new output directory for every run.
python scripts/eval_gate.py \
  --compare work/evaluations/BASELINE/report.json \
  --report-dir work/evaluations/candidate

# Additional fictional policy cases, including known echo limitations.
python scripts/eval_gate.py --dataset src/aegis/evals/experiments.yaml \
  --report-dir work/evaluations/policy
```

Open the generated `report.html` in a browser. Its JSON companion contains the
complete selected cases, corpus, responses, retrieved context, verdict checks,
per-category results, end-to-end latency, actual provider/model, reported token
counts, configuration, package versions, source fingerprint, commit and working
tree status. It does not serialize environment variables or API keys. Reports
contain dataset and answer text: use fictional data and keep private evaluations
in appropriately protected storage. Generated runs live under ignored `work/`.
Existing report directories cannot be overwritten. CI runs the golden gate;
HTML and JSON reports are generated locally when `--report-dir` is supplied.

## What the score means

This is a deterministic regression checker. It checks specified substrings,
forbidden terms, refusals and source identifiers. Benign blocked requests and
empty answers fail. Citation-required answers need an actual `[source#chunkN]`
marker that matches retrieved metadata; merely retrieving a document earns no
citation credit. Expected source checks require retrieval of the named source
and, when citations are required, citation of it in the answer. Invented markers
fail even when a valid marker also appears.

These checks do **not** establish whether a citation supports every claim, whether
a model understands a policy, or whether its answer is generally correct. A
response can still game substring checks. Human review and independently
calibrated semantic grading remain necessary for those claims.

The default provider is explicitly `echo`, regardless of ambient provider
configuration. Its token counts are estimates and its answers reproduce context;
its score and latency are pipeline evidence, not language-model performance.
Costs remain `null` because no verified price schedule is applied.

The initial new development dataset run passed 11/14 with echo. The failures
were `backup-retention` (the expected source was not retrieved), and
`unknown-pension` / `unknown-meals` (echo did not state that the answer was
not provided). The default 85% gate correctly returned failure. These examples
are failure discovery, not an acceptance benchmark. The older golden suite
passed 64/64 under the stricter judge.

## Dataset authoring and split discipline

`experiments.yaml` contains six fictional policy documents, 14 development
cases, and four public holdout candidates. It was authored with AI assistance.
Each case has a stable id, question, category, split and explicit scoring rules.
For numeric or wording-dependent checks, inspect the rule before interpreting a
failure: valid paraphrases can fail a substring test. The abstention fixtures
currently require the phrase `not provided`; they are a narrow regression rule,
not a complete semantic abstention classifier.

The loader rejects unknown fields, duplicate ids, exact normalized duplicate
questions, empty rules, invalid splits and missing expected sources. Exact
deduplication does not detect paraphrase leakage. Legacy `golden.yaml` cases are
all development cases; none is retroactively claimed as unseen.

Normal runs select only `development`. `--split holdout` or `--split all`
requires `--allow-holdout`, and the report records that the holdout was consumed.
Public AI-assisted cases are not an independent benchmark. Before a final model
comparison, arrange independently authored private cases and avoid using their
results to choose prompts, models or parameters. Replace any consumed final set.

## Real-provider runs

Configure the selected provider's existing credentials privately, then opt in:

```sh
python scripts/eval_gate.py --provider gemini \
  --dataset src/aegis/evals/experiments.yaml \
  --report-dir work/evaluations/gemini-policy
```

No live provider is called by default. An unavailable selected provider is a
configuration error. If a configured provider fails and the gateway falls back
to echo, that answer fails the requested-provider check and retains the actual
provider identity. Upstream blocks do not call a provider. The evaluator uses an
isolated in-memory index, disabled response cache, and temporary local audit;
it does not clear the API index or use the application's durable stores.

The manifest records model settings and actual response models. Provider-side
model changes and stochastic generation can still change results. A source
fingerprint identifies local code but is not a substitute for preserving that
source checkout and its environment.

## Paired comparison

`--compare` requires matching cases, corpus, split and judge fingerprint. Every
selected case needs exactly one outcome. It reports improvements and regressions
by case id, so an unchanged average cannot conceal a newly broken case. Any
pass-to-fail regression fails the gate, even when another case improves.
The comparison is descriptive and makes no statistical significance claim.

The legacy scalar `--baseline` and `--max-drop` remain available, but they cannot
establish that two evaluations used matching cases. Prefer JSON report comparison.
Read and write scalar baselines in separate runs to avoid replacing the baseline
before comparing against it.

## Remaining acceptance work

This milestone adds local dataset validation, experiment records, paired
comparison and CI evidence. It does not complete a company pilot, validate live
storage recovery, establish load limits or independent security review, or
resolve human authorship and licensing eligibility for any external program.
See `ROADMAP.md` and `docs/PRODUCTION-READINESS.md` for those acceptance gates.
