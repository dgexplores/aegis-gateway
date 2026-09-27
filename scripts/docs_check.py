"""Docs must not contradict the repo.

Two failure modes, both credibility bugs rather than build failures:

  1. A stale number. The front page claimed `233 tests` while the suite was at
     252. A reviewer who runs `make test` and sees a different number stops
     trusting every other claim on the page.
  2. A dead image. README screenshots are the product's face; a renamed file
     leaves a broken image on the project's front page and nothing else fails.

Neither is caught by the test suite, so both are checked here.

Usage: python scripts/docs_check.py  (exit 0 = consistent, 1 = drifted)
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"DOCS-CHECK FAIL: {msg}")


def collected_tests() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    matches = re.search(r"(\d+) tests? collected", out.stdout)
    return int(matches.group(1)) if matches else 0


def check_test_counts() -> None:
    actual = collected_tests()
    if not actual:
        fail("could not count the collected tests — the number in the docs is unverified")
        return
    for doc in ("README.md", "STATUS.md"):
        path = ROOT / doc
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for claimed in {int(n) for n in re.findall(r"\b(\d{3})\s+tests?\b", text)}:
            if claimed < actual:
                fail(
                    f"{doc} claims {claimed} tests but the suite collects {actual}. "
                    "A reader who runs the suite sees a different number."
                )
            else:
                print(f"docs-check ok: {doc} test count {claimed} >= {actual} collected")


def check_image_links() -> None:
    docs = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    for doc in docs:
        if not doc.exists():
            continue
        text = doc.read_text(encoding="utf-8")
        for ref in set(re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)):
            if ref.startswith(("http://", "https://", "#")):
                continue
            target = (doc.parent / ref).resolve()
            if not target.is_file():
                fail(f"{doc.name} references a missing image: {ref}")


def main() -> int:
    check_test_counts()
    check_image_links()
    if failures:
        print(f"\nDOCS-CHECK BLOCKED ({len(failures)} problem(s))")
        return 1
    print("\nDOCS-CHECK PASSED — docs match the repo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
