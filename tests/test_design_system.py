"""The console's visual contract gets pinned by tests too.

The AWWWARDS redesign that preceded the hand-drawn system shipped green while
breaking the page in two ways nothing could see: it deleted the console's entire
utility layer (`.row`, `.grid-2`, `.muted`, …) although the template still uses
every one of them, and it replaced the local artwork with remote Picsum images
that the console's own `img-src 'self' data:` policy blocks outright.

Both slipped through because nothing asserted that the template's classes exist
in the stylesheet, or that the stylesheet stays free of remote URLs — the
existing console checks only grep for a handful of CDN hostnames, and the
production guard only inspects the markup.

So these tests pin the two properties that would have caught them, plus the
parts the hand-drawn system is actually made of: locally bundled fonts, hard
offset shadows, balanced markup, and a motion shim that resolves.
"""

import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img",
    "input", "link", "meta", "param", "source", "track", "wbr",
}

BUNDLED_FONTS = (
    "kalam-700-latin.woff2",
    "patrick-hand-400-latin.woff2",
)


def _static() -> Path:
    return Path(__file__).resolve().parents[1] / "src" / "aegis" / "static"


def _templates() -> Path:
    return Path(__file__).resolve().parents[1] / "src" / "aegis" / "templates"


def _template(name: str = "dashboard.html") -> str:
    return (_templates() / name).read_text(encoding="utf-8")


# Every operator-facing surface. dashboard.html answers "what happened to my
# request?"; admin.html answers "is the fleet healthy?". Both ship local assets
# only, so these rules are checked across the whole set rather than per page.
CONSOLE_SHELLS = ("dashboard.html", "admin.html")


def _stylesheet() -> str:
    return (_static() / "dashboard.css").read_text(encoding="utf-8")


def test_stylesheet_makes_no_remote_requests():
    """A remote background-image is silently dropped by `img-src 'self' data:`
    and is dead on an air-gapped deploy. The pre-existing checks only look for
    a few CDN hostnames, so a stock-photo host sailed straight through."""
    css = _stylesheet()
    remote = [
        src for src in
        (url.strip().strip("'\"") for url in re.findall(r"url\(([^)]*)\)", css))
        if re.match(r"(https?:)?//", src)
    ]
    assert not remote, f"the stylesheet fetches over the network: {remote}"


def test_every_class_used_by_the_template_is_defined_in_the_stylesheet():
    """The template is the contract; a class it renders with no rule behind it
    is a silently unstyled element."""
    html, css = _template(), _stylesheet()
    used: set[str] = set()
    for value in re.findall(r'class="([^"]*)"', html):
        used.update(value.split())
    undefined = sorted(
        name for name in used
        if not re.search(rf"\.{re.escape(name)}(?![A-Za-z0-9_-])", css)
    )
    assert not undefined, f"template classes with no CSS rule: {undefined}"


def test_handwriting_fonts_are_bundled_locally():
    """`font-src 'self'` plus an air-gapped deployment mean the handwriting has
    to ship in the image. A remote `@font-face` fails both at once."""
    faces = re.findall(r"@font-face\s*\{(.*?)\}", _stylesheet(), re.S)
    assert faces, "no @font-face rule: the hand-drawn system has no handwriting"
    for body in faces:
        found = re.search(r"url\(([^)]*)\)", body)
        assert found, "@font-face without a src"
        src = found.group(1).strip("'\" ")
        assert not re.match(r"(https?:)?//", src), f"remote font source: {src}"
        assert (_static() / src).is_file(), f"font file is not shipped: {src}"


def test_bundled_font_files_are_valid_woff2():
    for name in BUNDLED_FONTS:
        path = _static() / "fonts" / name
        assert path.is_file(), f"missing bundled font: {name}"
        assert path.read_bytes()[:4] == b"wOF2", f"{name} is not a woff2"


def test_hidden_actually_hides():
    """`hidden` has to beat the layout classes, and it did not.

    The browser's `[hidden] { display: none }` is a UA-stylesheet rule, so any
    author rule setting `display` on the same element wins — `.row
    { display: flex }` among them. Only `.view[hidden]` was ever handled, so the
    admin key editor sat permanently on screen while `el.hidden` reported
    `true`: the DOM and the screen disagreed, and no test could see it.

    `!important` is the standard remedy and is load-bearing here, not laziness.
    """
    css = _stylesheet()
    # Anchored, or the match lands on the explanation in the comment above it.
    rule = re.search(r"^\[hidden\]\s*\{([^}]*)\}", css, re.MULTILINE)
    assert rule, "no [hidden] rule — the UA default loses to every display class"
    assert "display: none" in rule.group(1)
    assert "important" in rule.group(1), (
        "the [hidden] rule needs !important or any .row/.grid-*/.flex-1 element "
        "renders while claiming to be hidden"
    )


def test_shadows_are_hard_offset_not_blurred():
    """The whole look depends on the shadow having no blur: a blur reads as a
    modern drop shadow and destroys the drawn-on-paper illusion."""
    values = re.findall(r"--shadow[\w-]*:\s*([^;]+);", _stylesheet())
    assert values, "no shadow tokens"
    for value in values:
        assert "blur(" not in value, f"blurred shadow token: --{value.strip()}"


def test_design_tokens_use_the_hand_drawn_palette():
    css = _stylesheet()
    for token in ("--paper", "--ink", "--red", "--blue"):
        assert re.search(rf"{token}:", css), f"missing hand-drawn token {token}"


class _Balance(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, tuple[int, int]]] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID_ELEMENTS:
            self.stack.append((tag, self.getpos()))

    def handle_endtag(self, tag):
        if tag in VOID_ELEMENTS:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}> at {self.getpos()}")
            return
        opened, position = self.stack.pop()
        if opened != tag:
            self.errors.append(f"</{tag}> at {self.getpos()} closes <{opened}> opened at {position}")


def test_template_markup_is_balanced():
    """One unclosed `<p>` in the capability grid shipped through review and
    silently reparented the card content."""
    parser = _Balance()
    parser.feed(_template())
    assert not parser.errors, parser.errors
    assert not parser.stack, f"never closed: {[tag for tag, _ in parser.stack]}"


def test_shipped_javascript_parses():
    """A duplicate `const` is a *parse* error, so the whole file silently stops
    executing: every binding is lost, `init()` never runs, and the console
    renders as a dead page with no visible error beyond one line in devtools.

    That happened twice here — once when the motion shim read an undefined
    global, and once when a new `SCENARIOS` collided with the capability
    tour's. Nothing in the Python suite noticed, because the tests read the
    file as text. A parser does.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not available to parse the console's JavaScript")
    for script in sorted(_static().glob("*.js")):
        result = subprocess.run(  # noqa: S603 — argv list, no shell; target is a repo-globbed path, not input
            [node, "--check", str(script)], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, (
            f"{script.name} does not parse, so the console would not run at all:\n"
            f"{result.stderr.strip()[:400]}"
        )


def test_every_class_the_console_generates_is_defined_in_the_stylesheet():
    """Covers the classes the script builds at runtime, not just the markup's.

    The template-only version of this check could not see a class the console
    injects, so it passed while the panel rendered unstyled. Found so far:
    `.raw`, the `<details>` wrapper around "Raw response" — every evidence
    body in the app ends in a disclosure with no rule behind it, so the
    triangle, spacing and hover state were all missing.
    """
    js = (_static() / "dashboard.js").read_text(encoding="utf-8")
    css = _stylesheet()

    generated: set[str] = set()
    for value in re.findall(r'class="([^"$<]*)"', js):  # template literals only
        generated.update(value.split())
    for value in re.findall(r"className = '([a-z][a-z0-9_ -]*)'", js):
        generated.update(value.split())

    undefined = sorted(
        name for name in generated
        if name and not re.search(rf"\.{re.escape(name)}(?![A-Za-z0-9_-])", css)
    )
    assert not undefined, f"classes the script generates with no CSS rule: {undefined}"


def test_every_element_the_console_looks_up_exists_in_a_template():
    """Every `$('#id')` must resolve, and every `id="..."` in a template must
    be reachable from script.

    The redesign that preceded this one rewrote the markup and left the script
    pointing at elements it had removed. `$('#metricsRefresh')` returned null,
    `addEventListener` threw, and the whole bootstrap below it — including
    `refreshAll()` — never ran, so the page rendered but issued zero API calls
    and every pill sat on its placeholder. Nothing caught it, because the tests
    only asserted that the endpoints *exist*, not that the console could reach
    them. Ids the script injects itself are exempt.

    There are two shells — dashboard.html (a user) and admin.html (the fleet) —
    so the union of their ids is what the script is allowed to reach. Each
    binding is still guarded on the element existing, so a shared id missing
    from one page degrades that page's surface rather than breaking the other.
    """
    html = "\n".join(_template(name) for name in CONSOLE_SHELLS)
    js = (_static() / "dashboard.js").read_text(encoding="utf-8")

    template_ids = set(re.findall(r'id="([^"]+)"', html))
    script_generated = set(re.findall(r'id="([A-Za-z0-9_-]+)"', js))
    looked_up = (
        set(re.findall(r"\$\$?\('#([A-Za-z0-9_-]+)'", js))
        # `on('id', ...)` is the guarded-binding form the shells use, so its
        # literal ids count as lookups too.
        | set(re.findall(r"\bon\(\s*'([A-Za-z0-9_-]+)'", js))
    )

    missing = sorted(looked_up - template_ids - script_generated)
    assert not missing, (
        f"the console looks up ids no markup defines: {missing} — "
        "each one throws and aborts the rest of the initialisation"
    )


def test_user_surface_offers_no_document_input():
    """The user page is a question box, not a document manager.

    It shipped with an "Add a document" card — a name field, a paste area and
    three seed buttons — because the demo had no other way to give itself a
    corpus. That is corpus *administration*: an employee asking about vacation
    days should not be the person who uploads the HR policy. It also made the
    page require input before it could do anything, which is the opposite of the
    chat surface it claims to be, and the two demo seed buttons duplicated
    scenarios the admin Capability Tour already drives against the real API.

    The corpus is still listed, read-only, because knowing what the assistant
    can see is the trust story. What is banned is the user *writing* to it: no
    upload form, and no per-row delete either, since retiring a company policy
    is the operator's call, not the reader's.

    The guard is on the markup, not on the script: `dashboard.js` is shared, and
    it legitimately keeps `ingest()` for the admin Capability Tour, which is
    `admin`-scoped. What must not exist is a control on the *user* shell that
    reaches one of those calls — and `test_interactive_controls_in_the_template_
    are_wired` plus the missing-id test already fail if such a control is
    invented without a handler or the script is left pointing at a deleted node.
    """
    html = _template("dashboard.html")

    for banned in ('id="ragSource"', 'id="ragText"', 'id="ingestBtn"',
                   "data-seed", "data-delete", "Add a document"):
        assert banned not in html, (
            f"the user surface offers document input again ({banned!r}); corpus "
            "management belongs to the operator, not to the person asking questions"
        )


def test_interactive_controls_in_the_template_are_wired():
    """A button that looks actionable but has no handler is a defect the a11y
    tree cannot reveal — the three primary CTAs shipped unbound. Only <button>
    is checked: an <a> navigates on its own and needs no script.

    The handler may live in dashboard.js (the console) or theme.js (shared with
    the landing page), so a button counts as wired if either script names it.
    """
    js = "\n".join(
        (_static() / name).read_text(encoding="utf-8")
        for name in ("dashboard.js", "theme.js")
    )

    def is_wired(element_id: str) -> bool:
        """An id counts as handled if it appears in any binding form the
        scripts actually use: the `$` helper, a querySelector,
        getElementById, or the guarded `on('id', ...)` wrapper both shells
        bind through. Matching only one spelling reports false failures —
        and a missed binding is worse than a noisy test, because a control
        that looks actionable but does nothing is a defect the a11y tree
        cannot reveal."""
        ident = re.escape(element_id)
        return bool(
            re.search(rf"\$\$?\(\s*['\"]#{ident}['\"]", js)
            or re.search(rf"querySelector\w*\(\s*['\"]#{ident}['\"]", js)
            or re.search(rf"getElementById\(\s*['\"]{ident}['\"]", js)
            or re.search(rf"\bon\(\s*['\"]{ident}['\"]", js)
        )

    for template in (*CONSOLE_SHELLS, "landing.html"):
        html = _templates() / template
        text = html.read_text(encoding="utf-8")
        buttons = set(re.findall(r'<button\b[^>]*\bid="([A-Za-z0-9_-]+)"', text))
        if template in CONSOLE_SHELLS:
            assert buttons, "no buttons found in the template — the selector is wrong"
        unwired = sorted(b for b in buttons if not is_wired(b))
        assert not unwired, f"{template}: buttons with no handler: {unwired}"


def test_console_javascript_never_hides_content_with_inline_opacity():
    """Nothing shipped may set an element's opacity to 0 from script.

    Content that starts hidden can only be restored by whatever hides it, so a
    single mistake makes the hero CTAs, every chat turn or every evidence body
    disappear with no way back. The scroll-driven shim this replaced did exactly
    that: it set opacity 0 on the hero words, the CTAs, each new turn and each
    evidence body, then animated a plain JS property instead of `style.opacity`,
    so none of it ever came back. All motion is now declarative CSS.
    """
    for name in ("dashboard.js",):
        text = (_static() / name).read_text(encoding="utf-8")
        for pattern in ("style.opacity = '0'", 'style.opacity = "0"', "style.opacity=0"):
            assert pattern not in text, (
                f"{name} hides content with {pattern!r}; animate in CSS instead"
            )
