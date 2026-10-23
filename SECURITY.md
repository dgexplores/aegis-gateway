# Security

AEGIS is an engineering prototype with documented verification boundaries.
The public evaluation service contains public demo credentials and fictional
sample policies. Do not submit real personal data or company documents there.

## Report a suspected vulnerability

Use GitHub's private vulnerability-reporting option if it is enabled for this
repository. Otherwise, open an issue requesting a private reporting channel
without including an exploit, credentials or sensitive data. No response-time
SLA or independent security certification is claimed.

Include the affected commit, a minimal fictional-input reproduction, expected
and observed behaviour, and relevant sanitized logs through the private channel.
Do not test against another person's tenant or disrupt the public service.

## Deployment boundaries

- Keep provider secrets and scoped AEGIS keys on the server side.
- Replace development credentials and signing keys before real use.
- Public demo configuration is not production configuration.
- Pattern-based screening and masking are incomplete controls.
- Audit key security, retention, recovery and completeness need operational review.

See [current status](STATUS.md) and [production readiness](docs/PRODUCTION-READINESS.md).
