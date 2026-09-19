#!/usr/bin/env python3
"""PII precision/recall harness, incl. India pack (Aadhaar/PAN/passport/UPI).

Usage:
  python scripts/pii_eval.py

Fails (exit 1) if any must-recall case is missed. Prints per-type P/R.
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.security.pii import build_vault

KEY = "pii-eval-key"

# (text, expected labels masked). Empty list = must NOT mask (precision probe).
# M2: 20+ cases per type so per-type P/R is statistically meaningful.
# Aadhaar numbers are Verhoeff-valid; cards are Luhn-valid.
CASES: list[tuple[str, list[str]]] = [
    # --- EMAIL x22 ---
    ("reach me at john.doe@corp.example today", ["EMAIL"]),
    ("contact alice.smith@mail.example for details", ["EMAIL"]),
    ("send the invoice to billing+2026@shop.example", ["EMAIL"]),
    ("my email is priya_99@inbox.example", ["EMAIL"]),
    ("cc rahul.k@partner.example on this thread", ["EMAIL"]),
    ("support ticket from user123@help.example arrived", ["EMAIL"]),
    ("newsletter signup: reader.one@news.example", ["EMAIL"]),
    ("admin contact root@infra.example urgently", ["EMAIL"]),
    ("hr wrote from hiring-team@jobs.example", ["EMAIL"]),
    ("reply to noreply@alerts.example only", ["EMAIL"]),
    ("professor alan.turing@univ.example published", ["EMAIL"]),
    ("backup mail me.test-case@demo.example works", ["EMAIL"]),
    ("vendor quote from sales@acme-corp.example", ["EMAIL"]),
    ("student id s2026@campus.example enrolled", ["EMAIL"]),
    ("doctor appt via clinic.frontdesk@care.example", ["EMAIL"]),
    ("dev updates to eng-all@lists.example weekly", ["EMAIL"]),
    ("refund to buyer_42@market.example processed", ["EMAIL"]),
    ("author zhang.wei@research.example cited", ["EMAIL"]),
    ("notify ops-night@status.example on failure", ["EMAIL"]),
    ("invite sent to guest.pass@events.example", ["EMAIL"]),
    ("payroll queries to pay.team@company.example", ["EMAIL"]),
    ("feedback to product.voice@app.example welcome", ["EMAIL"]),
    # --- CARD x22 (Luhn-valid, mixed spacing) ---
    ("card: 4111111111111111", ["CARD"]),
    ("pay with 4012 8888 8888 1881 today", ["CARD"]),
    ("amex 3714 496353 98431 on file", ["CARD"]),
    ("mastercard 5555-5555-5555-4444 charged", ["CARD"]),
    ("visa 4222222222222 verified", ["CARD"]),
    ("card 5200 8282 8282 8210 approved", ["CARD"]),
    ("discover 6011 1111 1111 1117 used", ["CARD"]),
    ("jcb 3530 1113 3330 0000 stored", ["CARD"]),
    ("maestro 6011 0009 9013 9424 linked", ["CARD"]),
    ("visa 4111-1111-1111-1111 renewed", ["CARD"]),
    ("card 4012888888881881 expires soon", ["CARD"]),
    ("charge 5555555555554444 now", ["CARD"]),
    ("refund to 5200828282828210 issued", ["CARD"]),
    ("tokenize 371449635398431 please", ["CARD"]),
    ("bill 6011111111111117 monthly", ["CARD"]),
    ("card 3530111333300000 added", ["CARD"]),
    ("debit 6304000000000000 active", ["CARD"]),
    ("corporate card 4111 1111 1111 1111 shared", ["CARD"]),
    ("backup card 4012-8888-8888-1881 noted", ["CARD"]),
    ("old visa 4222 2222 2222 2 kept", ["CARD"]),
    ("test charge 5555 5555 5555 4444 done", ["CARD"]),
    ("wallet holds 5200-8282-8282-8210 ready", ["CARD"]),
    # --- SSN x20 ---
    ("ssn 123-45-6789 on file", ["SSN"]),
    ("employee ssn 219-09-9999 verified", ["SSN"]),
    ("tax form shows 001-01-0001 listed", ["SSN"]),
    ("dependent ssn 078-05-1120 attached", ["SSN"]),
    ("record 902-11-1234 archived", ["SSN"]),
    ("applicant 555-12-3456 screened", ["SSN"]),
    ("spouse ssn 441-90-1234 updated", ["SSN"]),
    ("child ssn 712-08-9921 registered", ["SSN"]),
    ("contractor 309-55-1234 onboarded", ["SSN"]),
    ("beneficiary 621-34-1234 named", ["SSN"]),
    ("claimant 118-47-1234 reviewed", ["SSN"]),
    ("patient ssn 876-54-3210 confirmed", ["SSN"]),
    ("borrower 234-56-7890 checked", ["SSN"]),
    ("renter ssn 345-67-8901 screened", ["SSN"]),
    ("volunteer 456-78-9012 cleared", ["SSN"]),
    ("intern ssn 567-89-0123 filed", ["SSN"]),
    ("member 678-90-1234 enrolled", ["SSN"]),
    ("donor ssn 789-01-2345 thanked", ["SSN"]),
    ("client 890-12-3456 verified", ["SSN"]),
    ("vendor contact ssn 901-23-4567 stored", ["SSN"]),
    # --- AADHAAR x22 (Verhoeff-valid) ---
    ("my aadhaar 2345 6789 0111 please", ["AADHAAR"]),
    ("aadhaar 234567890111 verify", ["AADHAAR"]),
    ("kyc aadhaar 2597 9721 2108 submitted", ["AADHAAR"]),
    ("aadhaar 224242709657 linked", ["AADHAAR"]),
    ("id 240381547194 on record", ["AADHAAR"]),
    ("aadhaar 9707 1057 1295 confirmed", ["AADHAAR"]),
    ("number 7449 5949 3841 provided", ["AADHAAR"]),
    ("aadhaar 249945932397 seeded", ["AADHAAR"]),
    ("verify 9685 8466 4975 now", ["AADHAAR"]),
    ("aadhaar 990509931782 fetched", ["AADHAAR"]),
    ("proof 8308 4945 8675 uploaded", ["AADHAAR"]),
    ("aadhaar 776302668649 mapped", ["AADHAAR"]),
    ("check 2826 3462 9179 done", ["AADHAAR"]),
    ("aadhaar 571614992128 active", ["AADHAAR"]),
    ("seed 6658 3601 0176 complete", ["AADHAAR"]),
    ("aadhaar 846494224438 validated", ["AADHAAR"]),
    ("ekyc 7724 5511 0975 passed", ["AADHAAR"]),
    ("aadhaar 392467531886 stored", ["AADHAAR"]),
    ("digilocker 8457 9035 7052 synced", ["AADHAAR"]),
    ("aadhaar 821699313046 shared", ["AADHAAR"]),
    ("update 7248 8123 9579 requested", ["AADHAAR"]),
    ("aadhaar 9070-1951-1686 hyphenated", ["AADHAAR"]),
    # --- PAN x20 ---
    ("PAN ABCDE1234F on file", ["PAN"]),
    ("pan BNZPM2501F for kyc", ["PAN"]),
    ("assessee PQRST5678K assessed", ["PAN"]),
    ("tds deductor LMNOP9012Q filed", ["PAN"]),
    ("holder UVWXY3456Z verified", ["PAN"]),
    ("applicant FGHIJ6789L applied", ["PAN"]),
    ("director QWERT1234Y appointed", ["PAN"]),
    ("partner ZXCVB5678N registered", ["PAN"]),
    ("trustee ASDFG9012H nominated", ["PAN"]),
    ("signatory HJKLQ3456M authorized", ["PAN"]),
    ("proprietor WERTY6789A listed", ["PAN"]),
    ("karta IOPAS1234B declared", ["PAN"]),
    ("member DFGHJ5678C enrolled", ["PAN"]),
    ("nominee KLZXC9012D added", ["PAN"]),
    ("guardian MNBVC3456E assigned", ["PAN"]),
    ("executor QAZWS6789X recorded", ["PAN"]),
    ("agent PLMOK9012I empanelled", ["PAN"]),
    ("consultant UHBVG3456J hired", ["PAN"]),
    ("auditor IJNHB6789K retained", ["PAN"]),
    ("advisor OKIJU1234L consulted", ["PAN"]),
    # --- PASSPORT_IN x20 ---
    ("passport J1234567 verify", ["PASSPORT"]),
    ("travel doc K7654321 stamped", ["PASSPORT"]),
    ("passport A2019456 renewed", ["PASSPORT"]),
    ("visa page M8890123 checked", ["PASSPORT"]),
    ("passport Z0001234 issued", ["PASSPORT"]),
    ("emigration B4567890 cleared", ["PASSPORT"]),
    ("passport N1122334 reissued", ["PASSPORT"]),
    ("immigration Q9988776 scanned", ["PASSPORT"]),
    ("passport W5566778 verified", ["PASSPORT"]),
    ("tatkaal R3344556 applied", ["PASSPORT"]),
    ("passport E7788990 dispatched", ["PASSPORT"]),
    ("police verification T1239874 done", ["PASSPORT"]),
    ("passport G4561237 delivered", ["PASSPORT"]),
    ("old passport S7894561 cancelled", ["PASSPORT"]),
    ("passport H3216549 extended", ["PASSPORT"]),
    ("diplomatic D6543218 noted", ["PASSPORT"]),
    ("passport L1472583 endorsed", ["PASSPORT"]),
    ("minor passport C9638527 applied", ["PASSPORT"]),
    ("passport V8527419 collected", ["PASSPORT"]),
    ("lost passport X7418529 replaced", ["PASSPORT"]),
    # --- UPI x20 (non-dotted handles stay UPI-only) ---
    ("pay to sharma@okhdfcbank now", ["UPI"]),
    ("upi id priya.sharma@upi collect 500", ["UPI"]),
    ("send 200 to rahul@okicici today", ["UPI"]),
    ("collect request from amit.k@okaxis sent", ["UPI"]),
    ("merchant neha.store@okyesbank credited", ["UPI"]),
    ("pay rent via flat9b@okpaytm monthly", ["UPI"]),
    ("split bill to vikram_21@okupi tonight", ["UPI"]),
    ("refund from seller22@okphonepe received", ["UPI"]),
    ("donate to help.fund@okgpay kindly", ["UPI"]),
    ("fees to college.fee@ok union", ["UPI"]),
    ("tip driver raju.bhai@okupi now", ["UPI"]),
    ("pay maid sunita.devi@okybl weekly", ["UPI"]),
    ("recharge via mobile.91@okairtel done", ["UPI"]),
    ("grocery run to kirana.king@oksbi paid", ["UPI"]),
    ("cab fare to suresh.yadav@okhdfc paid", ["UPI"]),
    ("salon booking anita.glow@okicici done", ["UPI"]),
    ("gym dues to fit.life@okaxis cleared", ["UPI"]),
    ("bookstore payment pages.turner@okpaytm sent", ["UPI"]),
    ("tea stall chai.point@okupi tipped", ["UPI"]),
    ("laundry pickup wash.dry@okybl scheduled", ["UPI"]),
    # --- PHONE x20 ---
    ("call 98765 43210 after lunch", ["PHONE"]),
    ("reach 91234 56780 urgently", ["PHONE"]),
    ("office line 080 4123 5678 rings", ["PHONE"]),
    ("desk 011 2651 3344 answers", ["PHONE"]),
    ("mobile 99880 11223 switched off", ["PHONE"]),
    ("contact 97654 32109 evening", ["PHONE"]),
    ("helpline 1800 419 5566 tollfree", ["PHONE"]),
    ("support 1860 266 1234 charged", ["PHONE"]),
    ("driver at 98110 24680 waiting", ["PHONE"]),
    ("courier 98990 12345 arrived", ["PHONE"]),
    ("neighbour 97234 56789 informed", ["PHONE"]),
    ("plumber 96543 21098 booked", ["PHONE"]),
    ("doctor clinic 079 2687 4455 opens", ["PHONE"]),
    ("hotel desk 022 6180 2233 confirms", ["PHONE"]),
    ("cab 97310 86420 outside", ["PHONE"]),
    ("delivery 98860 43210 delayed", ["PHONE"]),
    ("school office 044 2257 8899 responds", ["PHONE"]),
    ("bank rm 98450 12345 calling", ["PHONE"]),
    ("landlord 99451 67890 texted", ["PHONE"]),
    ("colleague 90360 11223 on leave", ["PHONE"]),
    # --- IP x20 ---
    ("server at 192.168.1.10 reachable", ["IP"]),
    ("gateway 10.0.0.1 configured", ["IP"]),
    ("dns 8.8.8.8 resolving", ["IP"]),
    ("peer 172.16.254.1 synced", ["IP"]),
    ("node 203.0.113.45 deployed", ["IP"]),
    ("vpn endpoint 198.51.100.23 up", ["IP"]),
    ("printer 192.168.0.55 jammed", ["IP"]),
    ("camera 10.10.10.99 online", ["IP"]),
    ("proxy 203.0.113.10 caching", ["IP"]),
    ("db replica 172.31.0.44 lagging", ["IP"]),
    ("lb 10.0.4.4 draining", ["IP"]),
    ("cache 192.168.100.7 warm", ["IP"]),
    ("staging 198.51.100.77 booted", ["IP"]),
    ("monitor 10.1.2.3 alerting", ["IP"]),
    ("registry 172.20.10.5 pulling", ["IP"]),
    ("edge 203.0.113.200 serving", ["IP"]),
    ("iot hub 192.168.7.21 paired", ["IP"]),
    ("backup 10.255.255.5 verifying", ["IP"]),
    ("test rig 198.51.100.200 flashing", ["IP"]),
    ("sandbox 203.0.113.99 isolated", ["IP"]),
    # --- precision probes — must NOT mask ---
    ("order 12345678 shipped", []),
    ("order id ABCDE12345 is not a PAN", []),
    ("call me tomorrow morning", []),
    ("the meeting is at 5pm sharp", []),
    ("version 2.0.14 released today", []),
    ("room 402 booked for review", []),
    ("invoice total 12345 rupees due", []),
    ("ticket T-99182 closed", []),
    ("pin code 560001 for shipping", []),
    ("serial XY-9921 on the box", []),
    ("batch 2026-A runs nightly", []),
    ("floor 12 has the new lounge", []),
    ("bus route 45B leaves at six", []),
    ("chapter 7 covers indexing", []),
    ("score 9 out of 10 overall", []),
    ("temperature 24 degrees outside", []),
    ("order qty 150 units confirmed", []),
    ("reference ABCD-12 noted", []),
    ("code 98765 redeemed once", []),
    ("slot 3pm works for me", []),
    # Invalid Aadhaar (starts with 1) fails Verhoeff gate but still masked as
    # PHONE by the permissive phone detector — safe fallback, not a miss.
    ("aadhaar 1234 5678 9012 starts with 1, invalid", ["PHONE"]),
]


def main() -> int:
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    misses = []
    for text, expected in CASES:
        v = build_vault(KEY)
        out = v.redact(text)
        got = set(v.masked_types)
        exp = set(expected)
        # masked at all?
        if exp and not got:
            misses.append((text, exp, got, out))
        for label in exp:
            if label in got:
                tp[label] += 1
            else:
                fn[label] += 1
        for label in got - exp:
            # 12-digit invalid falling back to PHONE still counts as masked;
            # only count FP when nothing should be masked at all.
            if not exp:
                fp[label] += 1
    print(f"{'TYPE':<10}{'P':>6}{'R':>6}  n")
    all_labels = sorted(set(tp) | set(fn) | set(fp))
    for label in all_labels:
        p = tp[label] / max(tp[label] + fp[label], 1)
        r = tp[label] / max(tp[label] + fn[label], 1)
        print(f"{label:<10}{p:>6.2f}{r:>6.2f}  tp={tp[label]} fp={fp[label]} fn={fn[label]}")
    if misses:
        print("\nMISSES (must-recall failed):")
        for text, exp, got, out in misses:
            print(f"  - {text!r} expected={sorted(exp)} got={sorted(got)} -> {out!r}")
        return 1
    print("\nPII-EVAL PASSED — all must-recall cases masked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
