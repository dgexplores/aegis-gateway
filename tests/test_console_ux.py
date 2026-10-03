"""Console regressions found by using the thing, not by reading it.

Each of these was visible on screen and invisible in the source review:

  - "Reset my password" was one of three suggested questions on a page whose
    own heading promises "leave, pay, expenses or any policy". An IT action in
    a list of HR questions, from a demo fixture nobody meant to ship.
  - The static markup said "Demo key ready" and nothing ever corrected it,
    because `initKey` only touched the pill in the *empty* case. So a deployment
    with a real key still called itself a demo, and the word "Demo" sat on a
    product surface.
  - The empty state hardcoded "the three starter questions", so changing the
    starter row would have made the sentence a lie.
  - The status pills failed WCAG AA contrast at 4.04:1. Those pills carry the
    words "intact", "blocked" and "draining" -- they are status text, not
    decoration, and they are the thing an operator reads during an incident.

The contrast check is done numerically here rather than by trusting the CSS: a
colour pair that passes on white can fail on this design's cream paper, which
is exactly what happened.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "src" / "aegis" / "templates" / "dashboard.html"
ADMIN = ROOT / "src" / "aegis" / "templates" / "admin.html"
JS = ROOT / "src" / "aegis" / "static" / "dashboard.js"
CSS = ROOT / "src" / "aegis" / "static" / "dashboard.css"

# The light-theme block, and the paper these badges are tinted from. Checking
# against white would have passed everything that actually failed: the design's
# paper is a warm cream, and a colour can clear 4.5:1 on #fff and miss on it.
LIGHT_BLOCK = ":root {"
PAPER = "#fdfbf7"


def _light_theme() -> str:
    css = CSS.read_text(encoding="utf-8")
    return css[css.index(LIGHT_BLOCK) : css.index('[data-theme="dark"]')]


def _token(block: str, name: str) -> str:
    m = re.search(rf"--{name}:\s*(#[0-9a-fA-F]{{6}})", block)
    assert m, f"--{name} is not defined in the light theme"
    return m.group(1)


def _mix(fg: str, bg: str, pct: float) -> str:
    """`color-mix(in srgb, fg pct%, bg)`, computed.

    Pill backgrounds are a low-percentage tint of a status colour over the
    paper, so the real background is not any single value in the stylesheet and
    cannot be eyeballed -- it has to be mixed.
    """
    f, b = fg.lstrip("#"), bg.lstrip("#")
    out = []
    for i in (0, 2, 4):
        a, c = int(f[i : i + 2], 16), int(b[i : i + 2], 16)
        out.append(round(a * pct + c * (1 - pct)))
    return "#" + "".join(f"{v:02x}" for v in out)


def _srgb_to_linear(channel: float) -> float:
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def contrast(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return round((hi + 0.05) / (lo + 0.05), 2)


# -------------------------------------------------------------- contrast --

# (pill token, palette hue it is tinted from, mix percentage from the CSS)
PILLS = [
    ("pill-ok", "green", 0.12),
    ("pill-warn", "amber", 0.14),
    ("pill-bad", "red", 0.12),
    ("pill-info", "blue", 0.12),
]


@pytest.mark.parametrize("token,hue,pct", PILLS)
def test_status_pill_text_clears_wcag_aa_on_its_real_background(token, hue, pct):
    """WCAG 1.4.3: 4.5:1 for text below 18.66px bold / 24px regular.

    The design's --green/--red are chosen to read as a 9px dot and a 2px
    border, which is a much easier contrast job than 14px text. Used as the
    pill's own text they came out at 4.04:1 -- and these pills carry the words
    "intact", "blocked" and "draining", which is what an operator reads while
    deciding whether the audit chain is healthy.
    """
    block = _light_theme()
    fg = _token(block, token)
    bg = _mix(_token(block, hue), PAPER, pct)
    ratio = contrast(fg, bg)
    assert ratio >= 4.5, f".pill.{token.split('-')[1]} is {fg} on {bg} = {ratio}:1, needs 4.5:1"


@pytest.mark.parametrize("token,hue,pct", PILLS)
def test_status_pill_text_also_clears_aa_on_bare_paper(token, hue, pct):
    """A pill is sometimes rendered without its tint. Both backgrounds matter."""
    block = _light_theme()
    ratio = contrast(_token(block, token), PAPER)
    assert ratio >= 4.5, f"--{token} is {ratio}:1 on the bare paper"


def test_the_badge_uses_the_passing_tokens_not_the_palette():
    """.tag and .pill both render status text, so both must use the colours that
    were darkened for text rather than the dot-and-border palette."""
    css = CSS.read_text(encoding="utf-8")
    for selector in (".tag.ok", ".tag.warn", ".tag.bad", ".pill.ok", ".pill.warn", ".pill.bad", ".pill.info"):
        line = next(css_line for css_line in css.splitlines() if css_line.strip().startswith(selector))
        assert "--pill-" in line, f"{selector} still uses a dot-and-border colour: {line}"


def test_the_light_theme_red_is_usable_as_text():
    """--red also carries `a:hover` and `.btn.danger` text, so it has to pass as
    text and not only as a border."""
    red = _token(_light_theme(), "red")
    ratio = contrast(red, PAPER)
    assert ratio >= 4.5, f"light --red {red} is {ratio}:1 on the paper"


# ------------------------------------------------- product-surface wording --


def test_the_starter_questions_are_all_questions_someone_would_actually_ask():
    html = DASH.read_text(encoding="utf-8")
    starters = re.findall(r'data-ask="([^"]+)"', html)
    assert len(starters) >= 3
    for q in starters:
        assert q.strip().endswith("?"), f"not a question: {q!r}"
    # An IT account action belongs in a support ticket, not offered as a
    # suggested policy question on a page about leave and expenses.
    for banned in ("password", "reset", "login", "sign in"):
        assert not any(banned in q.lower() for q in starters), f"{banned!r} is not a policy question: {starters}"


def test_the_page_never_calls_itself_a_demo():
    """In development the key field is pre-filled; in production it is not. The
    label has to be true either way, and "Demo" is development language on a
    product surface."""
    for f in (DASH, ADMIN):
        text = f.read_text(encoding="utf-8")
        assert "Demo key ready" not in text, f"{f.name} ships a demo label"


def test_the_key_pill_reports_reality_in_both_directions():
    """The bug: `initKey` only updated the pill when the field was empty, so a
    pre-filled key left the static markup's claim on screen."""
    js = JS.read_text(encoding="utf-8")
    body = js[js.index("function initKey()") : js.index("function initKey()") + 900]
    assert "Key active for this visit" in body, "a loaded key is still not reported"
    assert "No key loaded" in body, "an empty key is still not reported"


def test_the_empty_state_does_not_hardcode_the_starter_count():
    js = JS.read_text(encoding="utf-8")
    assert "three starter" not in js, (
        "the empty state counts the starter questions, so it goes stale the moment anyone adds or removes one"
    )


# --------------------------------------------------- accessible names ------


@pytest.mark.parametrize("f", [DASH, ADMIN])
def test_no_visible_label_is_contradicted_by_an_aria_label(f):
    """WCAG 2.5.3 Label in Name.

    A name that only *contains* the visible text is still flagged by tooling, and
    the fix that satisfies it is the simpler one: let the element's own text be
    its name, and move any extra explanation into `title`.
    """
    html = f.read_text(encoding="utf-8")
    for match in re.finditer(r'<button[^>]*aria-label="([^"]+)"[^>]*>([^<]+)</button>', html):
        label, visible = match.group(1).strip(), match.group(2).strip()
        if visible.isalpha() and len(visible) > 1:
            assert label == visible, (
                f"button shows {visible!r} but is named {label!r} -- let the text "
                "be the name and use title for the explanation"
            )
