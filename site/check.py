"""Checks the built website before it is published.

    python3 -I site/check.py DIR

DIR is the folder `site/build.sh` wrote, or `site` itself. The check fails if

- a page of the site lacks the content security policy, or carries an inline
  script, an inline style, a style attribute or an event-handler attribute,
  any of which the policy would block or that would weaken it;
- anything a page or the stylesheet loads comes from another server: the
  site makes no third-party request at all;
- a link inside the site points to a file or an anchor that does not exist;
- the sample report is missing, or is not the inert page the scanner writes.

It uses the standard library only.
"""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; frame-src 'self'; base-uri 'none'; form-action 'none'"
)
# The scanner's own report keeps its own, stricter policy.
REPORT = Path("sample/report.html")
LOADS = {
    "script": ("src",),
    "link": ("href",),
    "img": ("src", "srcset"),
    "iframe": ("src",),
    "frame": ("src",),
    "source": ("src", "srcset"),
    "video": ("src", "poster"),
    "audio": ("src",),
    "track": ("src",),
    "embed": ("src",),
    "object": ("data",),
    "input": ("src",),
}


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.loads: list[tuple[str, str]] = []
        self.links: list[str] = []
        self.policy: str | None = None
        self.inline_scripts = 0
        self.styles = 0
        self.style_attrs = 0
        self.handlers: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        for name in ("id", "name"):
            if values.get(name):
                self.ids.add(values[name])
        if "style" in values:
            self.style_attrs += 1
        self.handlers.extend(name for name in values if name.startswith("on"))
        if tag == "meta" and values.get("http-equiv", "").lower() == "content-security-policy":
            self.policy = values.get("content", "")
        if tag == "script" and not values.get("src"):
            self.inline_scripts += 1
        if tag == "style":
            self.styles += 1
        if tag == "link" and values.get("rel", "").lower() in {"canonical", "alternate"}:
            self.links.append(values.get("href", ""))
        else:
            for name in LOADS.get(tag, ()):
                if values.get(name):
                    self.loads.append((tag, values[name]))
        if tag == "a" and "href" in values:
            self.links.append(values["href"])


def external(url: str) -> bool:
    parts = urlsplit(url)
    return bool(parts.scheme or parts.netloc) and parts.scheme != "data"


def target(page: Path, url: str, root: Path) -> tuple[Path, str]:
    parts = urlsplit(url)
    path = unquote(parts.path)
    if path == "":
        resolved = page
    else:
        resolved = (page.parent / path).resolve()
        if path.endswith("/") or resolved.is_dir():
            resolved = resolved / "index.html"
    return resolved, unquote(parts.fragment)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python3 -I site/check.py DIR", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    problems: list[str] = []
    pages = sorted(root.rglob("*.html"))
    parsed: dict[Path, Page] = {}
    for path in pages:
        page = Page()
        page.feed(path.read_text(encoding="utf-8"))
        parsed[path.resolve()] = page

    report = root / REPORT
    if not report.is_file():
        problems.append(f"{REPORT}: missing; run site/build.sh")

    for path in pages:
        page = parsed[path.resolve()]
        name = path.relative_to(root)
        if name == REPORT:
            if not page.policy or "default-src 'none'" not in page.policy:
                problems.append(f"{name}: the report's own policy is missing")
            if page.inline_scripts or page.loads:
                problems.append(f"{name}: the report must load nothing and run no script")
        else:
            if page.policy != POLICY:
                problems.append(f"{name}: the content security policy is missing or differs")
            if page.inline_scripts:
                problems.append(f"{name}: {page.inline_scripts} inline script(s)")
            if page.styles:
                problems.append(f"{name}: {page.styles} inline stylesheet(s)")
            if page.style_attrs:
                problems.append(f"{name}: {page.style_attrs} style attribute(s)")
        if page.handlers:
            problems.append(f"{name}: event-handler attributes {sorted(set(page.handlers))}")
        for tag, url in page.loads:
            if external(url):
                problems.append(f"{name}: <{tag}> loads {url} from another server")
                continue
            file, _ = target(path, url, root)
            if not file.exists():
                problems.append(f"{name}: <{tag}> loads {url}, which does not exist")
        for url in page.links:
            parts = urlsplit(url)
            if parts.scheme in {"http"}:
                problems.append(f"{name}: plain-http link {url}")
            if external(url) or parts.scheme in {"mailto"}:
                continue
            file, fragment = target(path, url, root)
            if not file.exists():
                problems.append(f"{name}: link {url} points to a missing file")
            elif fragment and file.suffix == ".html":
                if fragment not in parsed[file.resolve()].ids:
                    problems.append(f"{name}: link {url} points to a missing anchor")

    for sheet in sorted(root.rglob("*.css")):
        text = sheet.read_text(encoding="utf-8")
        for url in re.findall(r"url\(\s*['\"]?([^'\")]+)", text):
            if url.startswith("data:"):
                continue
            if external(url):
                problems.append(f"{sheet.relative_to(root)}: loads {url} from another server")
            elif not (sheet.parent / url).exists():
                problems.append(f"{sheet.relative_to(root)}: {url} does not exist")
        if "@import" in text:
            problems.append(f"{sheet.relative_to(root)}: @import is not allowed")

    for script in sorted(root.rglob("*.js")):
        text = script.read_text(encoding="utf-8")
        if re.search(r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b", text):
            problems.append(f"{script.relative_to(root)}: makes or could make a request")

    if problems:
        print("site check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"site check passed: {len(pages)} pages, no third-party requests, every internal link resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
