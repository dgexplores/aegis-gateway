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
from html.parser import HTMLParser
from pathlib import Path

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


def _template() -> str:
    return (Path(__file__).resolve().parents[1] / "src" / "aegis" / "templates" / "dashboard.html").read_text(
        encoding="utf-8"
    )


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


def test_every_element_the_console_looks_up_exists_in_the_template():
    """Every `$('#id')` must resolve, and every `id="..."` in the template must
    be reachable from script.

    The redesign that preceded this one rewrote the markup and left the script
    pointing at elements it had removed. `$('#metricsRefresh')` returned null,
    `addEventListener` threw, and the whole bootstrap below it — including
    `refreshAll()` — never ran, so the page rendered but issued zero API calls
    and every pill sat on its placeholder. Nothing caught it, because the tests
    only asserted that the endpoints *exist*, not that the console could reach
    them. Ids the script injects itself are exempt.
    """
    html, js = _template(), (_static() / "dashboard.js").read_text(encoding="utf-8")

    template_ids = set(re.findall(r'id="([^"]+)"', html))
    script_generated = set(re.findall(r'id="([A-Za-z0-9_-]+)"', js))
    looked_up = set(re.findall(r"\$\$?\('#([A-Za-z0-9_-]+)'", js))

    missing = sorted(looked_up - template_ids - script_generated)
    assert not missing, (
        f"the console looks up ids the markup does not define: {missing} — "
        "each one throws and aborts the rest of the initialisation"
    )


def test_interactive_controls_in_the_template_are_wired():
    """A button that looks actionable but has no handler is a defect the a11y
    tree cannot reveal — the three primary CTAs shipped unbound. Only <button>
    is checked: an <a> navigates on its own and needs no script."""
    html, js = _template(), (_static() / "dashboard.js").read_text(encoding="utf-8")
    buttons = set(re.findall(r'<button\b[^>]*\bid="([A-Za-z0-9_-]+)"', html))
    assert buttons, "no buttons found in the template — the selector is wrong"
    unwired = sorted(b for b in buttons if f"'#{b}'" not in js and f'"#{b}"' not in js)
    assert not unwired, f"buttons with no handler in dashboard.js: {unwired}"


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
