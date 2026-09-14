from aegis.security.pii import build_vault

KEY = "test-india-key"


def test_aadhaar_valid_masked():
    v = build_vault(KEY)
    out = v.redact("my aadhaar 2345 6789 0111 here")
    assert "2345 6789 0111" not in out
    assert "AADHAAR" in v.masked_types


def test_aadhaar_invalid_first_digit_not_aadhaar():
    v = build_vault(KEY)
    v.redact("aadhaar 1234 5678 9012 invalid")
    assert "AADHAAR" not in v.masked_types


def test_pan_masked():
    v = build_vault(KEY)
    out = v.redact("PAN ABCDE1234F on file")
    assert "ABCDE1234F" not in out
    assert "PAN" in v.masked_types


def test_passport_masked():
    v = build_vault(KEY)
    out = v.redact("passport J1234567 verify")
    assert "J1234567" not in out
    assert "PASSPORT" in v.masked_types


def test_upi_masked_not_email():
    v = build_vault(KEY)
    out = v.redact("pay to sharma@okhdfcbank now")
    assert "sharma@okhdfcbank" not in out
    assert "UPI" in v.masked_types


def test_email_still_email_not_upi():
    v = build_vault(KEY)
    v.redact("mail john.doe@corp.example today")
    assert "EMAIL" in v.masked_types
    assert "UPI" not in v.masked_types


def test_india_restore_roundtrip():
    v = build_vault(KEY)
    text = "aadhaar 234567890111 and PAN ABCDE1234F and sharma@okhdfcbank"
    masked = v.redact(text)
    assert masked != text
    assert v.restore(masked) == text
