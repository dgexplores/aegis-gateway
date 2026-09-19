"""Golden eval dataset loading and case model."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class GoldenCase:
    id: str
    question: str
    must_contain: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)
    requires_citation: bool = False
    attack_like: bool = False  # cases that should be REFUSED/blocked by gateway
    expect_source: str = ""  # retrieval ground truth: source doc that answers this


def load_dataset(path: str | Path) -> list[GoldenCase]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [GoldenCase(**case) for case in raw["cases"]]


# Canonical eval knowledge base (single source of truth for eval_gate.py and
# rag_eval.py). Keep in sync with golden.yaml expect_source values.
# 52 documents: 4 original + 48 added for M1 (retrieval drift gate depth).
# Each doc carries a unique answer fact so recall@k is meaningful; confusable
# pairs (vacation/sick/parental leave, vpn/wifi/mfa) test discrimination.
KNOWLEDGE_BASE: list[tuple[str, str]] = [
    ("vacation-policy.md",
     ("Full-time employees receive twenty paid vacation days (20 days) per calendar year. "
      "Unused vacation days roll over once. Requests are approved in the HR portal.")),
    ("password-reset.md",
     ("To reset your password, open the self-service portal and choose 'Forgot Password'. "
      "A reset link is emailed to your registered address within five minutes.")),
    ("expense-policy.md",
     ("The maximum expense reimbursement without manager approval is $75 per transaction. "
      "Itemized receipts are mandatory for expenses above ten dollars.")),
    ("security-contact.md",
     ("Report any security incident immediately to security@aegis.example. "
      "Critical incidents must also be phoned in to the on-call duty officer.")),
    ("sick-leave.md",
     ("Employees receive twelve paid sick days (12 days) per year with no rollover. "
      "A doctor's note is required for absences longer than three consecutive days.")),
    ("parental-leave.md",
     ("New parents receive sixteen weeks of fully paid parental leave. "
      "Leave must start within twelve months of birth or adoption and needs HR pre-approval.")),
    ("public-holidays.md",
     ("The company observes eleven public holidays per year including Republic Day and Diwali. "
      "Holiday calendars are published each December on the intranet homepage.")),
    ("remote-work.md",
     ("Employees may work remotely up to three days per week with manager approval. "
      "Full-time remote arrangements require a written agreement renewed annually.")),
    ("onboarding-checklist.md",
     ("New hires complete laptop setup, HR orientation, and security training within week one. "
      "Buddy assignments are made on day one by the hiring manager.")),
    ("performance-review.md",
     ("Performance reviews run twice yearly in April and October on a five-point scale. "
      "Promotions require two consecutive ratings of four or above.")),
    ("vpn-setup.md",
     ("Connect to the corporate VPN using the WireGuard client and your SSO credentials. "
      "VPN sessions expire after twelve hours and must be re-authenticated.")),
    ("wifi-access.md",
     ("Office Wi-Fi uses SSID Aegis-Corp with WPA2-Enterprise and your employee ID. "
      "Guest Wi-Fi credentials rotate every Monday at the front desk.")),
    ("mfa-enrollment.md",
     ("Enroll two MFA factors: an authenticator app plus a hardware security key. "
      "SMS codes are deprecated and disabled for admin roles.")),
    ("laptop-request.md",
     ("Request laptops through the IT service desk with a fifteen business day lead time. "
      "Standard issue is a 14-inch laptop with 32GB RAM and full-disk encryption.")),
    ("software-install.md",
     ("Install approved software from the company portal without a ticket. "
      "Unlisted tools need security review with a five business day turnaround.")),
    ("it-incident-response.md",
     ("Report IT outages to the #it-help channel with severity SEV1 through SEV4. "
      "SEV1 pages the on-call engineer with a fifteen minute response target.")),
    ("travel-policy.md",
     ("Domestic travel needs manager approval; international travel needs VP approval. "
      "Book flights at least fourteen days ahead via the corporate travel portal.")),
    ("invoice-submission.md",
     ("Submit vendor invoices by the 25th of each month for payment on the 5th. "
      "Invoices must reference a valid purchase order starting with PO-.")),
    ("budget-codes.md",
     ("Use cost center codes starting with CC- followed by four digits for all spend. "
      "Travel maps to CC-4100 and software licenses map to CC-4200.")),
    ("payroll-schedule.md",
     ("Payroll runs monthly on the last working day with payslips on the employee portal. "
      "Tax declarations for the new fiscal year close on March 15th.")),
    ("phishing-report.md",
     ("Forward suspected phishing to phishing@aegis.example without clicking links. "
      "Confirmed phishing campaigns trigger a company-wide alert within one hour.")),
    ("badge-access.md",
     ("Office badges grant access from 7am to 9pm on weekdays. "
      "After-hours access needs manager approval logged in the access system.")),
    ("data-classification.md",
     ("Data is classified Public, Internal, Confidential, or Restricted with handling rules. "
      "Customer PII is always Confidential or above and never leaves the VPN.")),
    ("retention-schedule.md",
     ("Financial records are retained seven years; interview notes are deleted after one year. "
      "Audit logs are immutable and retained for three years minimum.")),
    ("office-hours.md",
     ("Headquarters operates 9am to 6pm IST Monday through Friday. "
      "Reception closes at 5pm and visitors need pre-registration.")),
    ("parking-policy.md",
     ("Parking allotments use zone B for staff with EV chargers on level P2. "
      "Visitor parking is limited to two hours with a dashboard pass.")),
    ("cafeteria-menu.md",
     ("The cafeteria serves lunch 12pm to 2pm with vegetarian and Jain options daily. "
      "Meal subsidies cap at 150 rupees per employee per day.")),
    ("meeting-rooms.md",
     ("Book meeting rooms via the calendar app with a maximum four hour block. "
      "Rooms above ten seats need facilities approval one day ahead.")),
    ("nda-policy.md",
     ("All contractors sign a two-year mutual NDA before accessing internal systems. "
      "NDA templates live in the legal drive under Agreements/2026.")),
    ("contract-approval.md",
     ("Contracts above 500000 rupees need legal plus finance sign-off. "
      "Standard MSAs clear within ten business days of submission.")),
    ("compliance-training.md",
     ("Complete POSH and anti-bribery training annually by September 30th. "
      "Completion is tracked and reported to department heads monthly.")),
    ("deploy-process.md",
     ("Production deploys run Tuesday and Thursday via the green-blue pipeline. "
      "Freeze windows apply the last week of each quarter with CTO exception only.")),
    ("oncall-rotation.md",
     ("On-call rotations are weekly from Monday 10am with a fifteen minute ack SLA. "
      "Handoffs require a written summary in the ops channel every Friday.")),
    ("code-review-sla.md",
     ("Code reviews target first response within four business hours. "
      "Two approvals are required for production services; one for internal tools.")),
    ("environments-guide.md",
     ("Three environments exist: dev, staging, and prod with staging mirroring prod data shapes. "
      "Production access needs break-glass approval with full audit logging.")),
    ("sla-commitments.md",
     ("Customer SLAs promise 99.9% monthly uptime with credits after 43 minutes downtime. "
      "Status updates post every thirty minutes during an active incident.")),
    ("escalation-matrix.md",
     ("Escalate L1 to L2 after thirty minutes without progress. "
      "L3 escalation pages the engineering manager and opens a war room bridge.")),
    ("status-page.md",
     ("The public status page is status.aegis.example with RSS and webhook subscriptions. "
      "Postmortems publish within five business days of resolution.")),
    ("api-rate-limits.md",
     ("Public API limits are 1000 requests per hour per key with burst allowance of fifty. "
      "Exceeding limits returns 429 with a Retry-After header in seconds.")),
    ("backup-policy.md",
     ("Production databases back up nightly at 2am UTC with thirty day retention. "
      "Restore drills run quarterly and results are filed with compliance.")),
    ("password-policy.md",
     ("Passwords need minimum fourteen characters with MFA enforced for all staff. "
      "Password managers are provisioned free and rotation is event-driven, not periodic.")),
    ("recruitment-referral.md",
     ("Referral bonuses pay 50000 rupees after the referred hire completes ninety days. "
      "Hiring managers cannot refer into their own reporting chain.")),
    ("exit-process.md",
     ("Resignations need thirty days notice with knowledge transfer documented in week three. "
      "Access is revoked on the last working day at 6pm sharp.")),
    ("procurement-threshold.md",
     ("Purchases above 100000 rupees need three competitive quotes. "
      "Preferred vendors are listed in the procurement portal with annual rate cards.")),
    ("conference-budget.md",
     ("Each engineer gets 75000 rupees yearly for conferences plus five training days. "
      "Talks accepted at major conferences unlock an extra travel grant.")),
    ("health-insurance.md",
     ("Group health insurance covers 500000 rupees per family per year. "
      "Top-ups can be bought during the April enrollment window only.")),
    ("grievance-redressal.md",
     ("File grievances via the HR portal with acknowledgement within two working days. "
      "Resolution target is fifteen working days with appeal to the ethics committee.")),
    ("open-source-policy.md",
     ("Contributing to open source needs manager approval for work-time projects. "
      "Releasing company code requires legal review and an Apache-2.0 license default.")),
    ("customer-data-request.md",
     ("Customer data exports complete within thirty days of verified requests. "
      "Deletion requests propagate to backups within ninety days per policy.")),
    ("feature-flag-guide.md",
     ("Roll out features behind flags with 1%, 10%, 50%, 100% stages. "
      "Kill switches must be tested monthly and owned by the feature team.")),
    ("load-testing.md",
     ("Load test staging at twice expected peak before launch week. "
      "SLOs require p99 latency under 800 milliseconds at the planned throughput.")),
    ("seo-guidelines.md",
     ("Marketing pages need unique titles under sixty characters with one H1 each. "
      "Core Web Vitals targets are LCP under 2.5 seconds measured on mobile.")),
]
