# AEGIS walkthrough video: what it does and how to use it

**Format:** approximately two minutes, 16:9, 1920 x 1080, screen-based product
walkthrough with generic synthetic draft narration and captions. Audience:
recruiters and developers evaluating the integration use case.

**Dedicated skill used:** `agency-short-video-editing-coach` (story-first edit,
clear screen close-ups, restrained cuts, intelligible narration, caption safe
margins and H.264/AAC delivery). The video is a draft assembled from captured
product screens and explanatory cards; it is not an uninterrupted screen recording.

## Narrative and exact screen actions

| Scene | Approx. time | Screen / action | What the viewer should understand |
|---|---|---|---|
| 1. Purpose | 0:00-0:12 | Deployed overview; focus on the application/gateway/provider relationship | Developer gateway with a concrete policy-assistant example |
| 2. Who integrates it | 0:12-0:26 | Clearly labelled explanatory architecture card | Website or workflow calls through a backend; keep keys server-side |
| 3. First request | 0:26-0:44 | Open dashboard; select Vacation days; inspect response/provider | Policy retrieval works; echo output is a test response |
| 4. Privacy check | 0:44-1:02 | Select Try privacy check; expand the newest Show details; focus on provider input | Recognized email becomes an alias before a provider call |
| 5. Refusal | 1:02-1:18 | Select Try attack attempt; inspect newest refusal/details | A supported suspicious request is refused |
| 6. Engineering evidence | 1:18-1:36 | Open /showcase; focus on recorded poison/failover/tamper observations | Recorded experiments establish specific behaviour with test providers |
| 7. Integration | 1:36-1:51 | Clearly labelled backend request example / API documentation | Existing service APIs connect to a controlled integration pilot |
| 8. Close | 1:51-2:05 | Source, showcase URL and scope card | Reproduce evidence; real-model and company operation need separate acceptance |

Timings are editorial targets. The exported draft derives its exact duration
from the narration; captions follow the exported timeline.

## Narration

### 1 — Purpose

AEGIS puts an inspectable control boundary around AI requests. This example is
a company policy assistant, built to show how developers can handle access,
privacy, suspicious input, and request evidence in one gateway.

### 2 — Integration boundary

A website or workflow sends requests through its own backend to AEGIS. The
gateway checks the tenant, screens supported attack patterns, masks recognized
personal data, and calls a configured provider. Keep credentials on the server.

### 3 — First request

Open the console and choose Vacation days. The request retrieves fictional
company policies. Inspect the source and provider label beside the response.
This public demo uses echo, which returns deterministic test output. It does
not generate an intelligent policy answer.

### 4 — Privacy

Choose Try privacy check, then expand Show details for the newest response.
The original message contains a fictional email. In the outbound provider
payload, that value becomes an alias. AEGIS restores recognized values for the
caller. Detection is pattern based and has limits.

### 5 — Refusal

Choose Try attack attempt. The gateway refuses this supported suspicious
request. Inspect the decision and absent outbound payload. The recorded
engineering experiment separately checks that the recording provider received
zero additional calls. This is a specific test, not universal attack protection.

### 6 — Evidence

The engineering showcase labels its results as a recorded run. It demonstrates
poisoned retrieved context, tenant-state separation, an injected provider
failure, and an altered audit-copy record that fails verification. Reproduce
these experiments with the evidence command in the repository.

### 7 — Application integration

Your backend can call the chat API with a scoped tenant key. A document
assistant uses the ingestion and retrieval endpoints instead of plain chat.
Handle refusals, usage limits, unavailable providers, and echo fallback
explicitly. Native company connectors are not included.

### 8 — Close

Start with the public showcase, explore the source, and reproduce the checks.
AEGIS is a working gateway prototype for a controlled integration pilot.
Real-model quality, approved company data, persistence, and operational
acceptance still require deployment-specific verification.

## Capture and edit instructions

- Use the deployed pages listed below and fictional inputs only. Never record
  credential editors, personal browser content or private company documents.
- Keep an “Echo controls demo” label visible over live-console scenes and a
  “Recorded experiment” label over evidence scenes.
- Use readable close-ups of the outbound alias and refusal. Preserve surrounding
  UI context; never replace a real response with a fabricated answer.
- Cut loading waits and navigation dead time. Do not imply the public service
  has guaranteed availability; free hosting can wake slowly.
- Use hard cuts and short restrained dissolves only where they clarify a change
  of screen. No stock hacking imagery, dramatic metrics or simulated customers.
- Generic synthetic narration is a production draft, not an impersonation of the
  owner. Replace it with the owner's recording for a personal interview version.
- Keep voice clear and consistent, use no background music in this draft, and
  provide captions with a high-contrast backing inside the safe margins.
- Export MP4 with H.264 video, AAC audio, 30 fps and fast-start metadata. Keep
  the exact narration text and an SRT caption file alongside it.

## Source screens

- https://aegis-gateway-free.onrender.com/
- https://aegis-gateway-free.onrender.com/dashboard
- https://aegis-gateway-free.onrender.com/showcase
- https://aegis-gateway-free.onrender.com/docs

The working draft video, captions, narration and captured frames are delivered
as local output artifacts. No video-hosting upload or social publication is implied.
