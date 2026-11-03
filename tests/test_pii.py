from aegis.security.pii import build_vault

KEY = "test-vault-key"


def test_email_redacted_and_restored():
    v = build_vault(KEY)
    masked = v.redact("reach me at john.doe@corp.example today")
    assert "john.doe@corp.example" not in masked
    assert "@" not in masked
    restored = v.restore(masked)
    assert "john.doe@corp.example" in restored


def test_stable_pseudonyms_for_same_value():
    v1 = build_vault(KEY)
    v2 = build_vault(KEY)
    m1 = v1.redact("email a@b.com please")
    v2.redact("another email a@b.com here")
    token1 = next(iter(v1._real_to_token.values()))
    token2 = next(iter(v2._real_to_token.values()))
    assert m1 != "email a@b.com please"
    assert token1 == token2


def test_luhn_rejects_non_card_numbers():
    v = build_vault(KEY)
    # 1234 5678 is too short / fails luhn -> untouched
    out = v.redact("order 12345678 shipped")
    assert "12345678" in out


def test_valid_card_masked():
    v = build_vault(KEY)
    out = v.redact("card: 4111111111111111")
    assert "4111111111111111" not in out
    assert "CARD" in v.masked_types


def test_ssn_masked():
    v = build_vault(KEY)
    out = v.redact("ssn 123-45-6789 on file")
    assert "123-45-6789" not in out
    assert "SSN" in v.masked_types


def test_different_key_different_pseudonym():
    v1 = build_vault(KEY)
    v2 = build_vault("another-key-entirely")
    assert v1._pseudonym("a@b.com") != v2._pseudonym("a@b.com")


def test_restore_provider_response_without_guillemets():
    v = build_vault(KEY)
    token = v.redact("alex@example.test")[1:-1]
    assert v.restore(f"Your email address is {token}.") == "Your email address is alex@example.test."


def test_restore_bare_token_does_not_replace_identifier_substrings():
    v = build_vault(KEY)
    token = v.redact("alex@example.test")[1:-1]
    for value in (f"x{token}", f"{token}x", f"_{token}_"):
        assert v.restore(value) == value


def test_restore_bare_token_is_scoped_to_its_vault():
    owner = build_vault(KEY)
    token = owner.redact("alex@example.test")[1:-1]
    other = build_vault("other-tenant-key")
    other.redact("alex@example.test")
    assert other.restore(token) == token


def test_restore_multiple_bare_tokens():
    v = build_vault(KEY)
    first = v.redact("alex@example.test")[1:-1]
    second = v.redact("sam@example.test")[1:-1]
    assert v.restore(f"{first}, {second}") == "alex@example.test, sam@example.test"
