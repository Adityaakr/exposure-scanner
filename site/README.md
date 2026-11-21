# The exposure website

A static site: three pages of hand-written HTML, one stylesheet, two small
scripts and self-hosted fonts. There is no build framework, no tracker, no
analytics, and nothing is loaded from another server. A content security
policy on every page holds it to that.

| Path | What it is |
|---|---|
| `index.html` | The landing page |
| `sample/index.html` | The sample report page, which frames the report below |
| `sample/report.html`, `sample/report.json` | The report `exposure` writes for the synthetic fixtures in `tests/fixtures`. Generated, never edited by hand |
| `docs/index.html` | Install and docs |
| `assets/site.css` | The one stylesheet. Its colours follow the HTML report (`crates/xs-render/src/html/report.css`) |
| `assets/theme.js`, `assets/site.js` | The only scripts: the light and dark switch, copy buttons on commands. They make no request |
| `assets/fonts/` | Geist and Geist Mono, under the SIL Open Font License (`OFL.txt`) |
| `assets/og.png` | The image shown when a link to the site is shared |
| `build.sh` | Builds the site into a folder, writing the sample report afresh |
| `check.py` | Checks a built site before it is published |

## Preview

Any static file server works:

```console
$ python3 -m http.server 8000 --directory site
```

Then open <http://localhost:8000/>.

## The sample report

The report on the site is what the scanner on the same commit writes, so it
is generated, not written by hand:

```console
$ site/build.sh --sample        # rewrite site/sample/report.html and report.json
```

The script builds `exposure` from this checkout and scans the fixtures. A
scan of the same fixtures with the same rule pack gives the same bytes, so a
committed sample that differs from a fresh one is out of date. Regenerate it
after a change to the report's wording or stylesheet, to the rule pack, or
to the fixtures. The pages quote a few lines of that report and of the
terminal output; update them in the same change if they move.

## Checks

```console
$ site/build.sh /tmp/exposure-site       # the folder that is published
$ python3 -I site/check.py /tmp/exposure-site
```

`check.py` fails when a page lacks the content security policy or carries
an inline script or style, when anything would load from another server,
when a link inside the site points to a missing file or anchor, or when the
sample report is missing or not the inert page the scanner writes.

## Publishing

`.github/workflows/pages.yml` runs `build.sh` and `check.py` on every pull
request that touches `site/`, and fails it if the committed sample report is
out of date. On `main` it also publishes the built folder with GitHub Pages.
That needs Pages enabled for the repository with **GitHub Actions** as the
source (Settings > Pages). The site uses relative links only, so it works at
`https://<owner>.github.io/exposure-scanner/` and on a custom domain alike;
only the absolute address of the share image in each page's `og:image`
names the Pages address.

## Rules for the copy

Every sentence must be true of the code on `main`. Anything not built is
marked **Planned**. Findings are about the synthetic fixtures or are
company-level counts; the site names no third-party app as a finding.
Wording states graded facts, as the report does: "ships", "may access",
never "spies".
