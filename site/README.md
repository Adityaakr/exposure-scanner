# The exposure website

A static site: three pages of hand-written HTML, one stylesheet, three small
scripts and self-hosted fonts. There is no build framework, no tracker, no
analytics, and nothing is loaded from another server. A content security
policy on every page holds it to that.

The look is a terminal's: black and green, the content in one centred
column, headings in a pixel typeface, and a wireframe terrain drawn behind
the column. Headings and terminal output type themselves out as they come
into view. A visitor who asks for reduced motion gets none of that motion:
every word is there from the start, and the terrain is one still frame.

| Path | What it is |
|---|---|
| `index.html` | The landing page. Its "How to use it" steps show the commands for the system picked above them: macOS, Linux, Windows (not supported, and it says so) or Android packages |
| `sample/index.html` | The sample report page, which frames the report below |
| `sample/report.html`, `sample/report.json` | The report `exposure` writes for the synthetic fixtures in `tests/fixtures`. Generated, never edited by hand |
| `docs/index.html` | Install and docs |
| `assets/site.css` | The one stylesheet. Black and green only: a grade is told apart by fill and outline, `contains` filled and `declares` outlined |
| `assets/boot.js` | Runs before the page paints, to mark that script runs and whether motion is welcome |
| `assets/site.js` | Copy buttons on commands, a guess at the visitor's system for the steps, the typing, and figures that settle in as they scroll into view |
| `assets/terrain.js` | Draws the wireframe terrain on a canvas behind the column |
| `assets/fonts/` | Geist and Geist Mono (`Geist-OFL.txt`) and Departure Mono (`DepartureMono-OFL.txt`), all under the SIL Open Font License |
| `assets/og.png` | The image shown when a link to the site is shared |
| `build.sh` | Builds the site into a folder, writing the sample report afresh |
| `check.py` | Checks a built site before it is published |

The scripts make no request and store nothing, and every page is complete
without them. The system picker is plain CSS: without script it opens on
macOS, and a browser without `:has()` shows the commands for every system,
each labelled.

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

## Deploying

`site/` is the whole website, ready to serve as it is: static files, relative
links only, fonts included, the sample report committed. There is no build
step. Point any static host at the `site` folder.

| Host | How |
|---|---|
| **Vercel** | Add New > Project > import this repository. Root Directory: `site`. Framework Preset: **Other**. Leave the Build Command and Output Directory empty. Deploy. From a terminal: `npx vercel deploy site --prod`. |
| **Netlify** | Add new site > Import an existing project > this repository. Base directory: empty. Build command: empty. Publish directory: `site`. Deploy. Without Git, drop the `site` folder on <https://app.netlify.com/drop>. From a terminal: `npx netlify-cli deploy --dir site --prod`. |
| **Cloudflare Pages** | Workers & Pages > Create > Pages > Connect to Git > this repository. Framework preset: **None**. Build command: empty (or `exit 0` if the form asks for one). Build output directory: `site`. Save and Deploy. From a terminal: `npx wrangler pages deploy site --project-name exposure`. |
| **GitHub Pages** | Settings > Pages > Source: **GitHub Actions**. `.github/workflows/pages.yml` then publishes the site on every push to `main` that touches it or the scanner. |

Three things to know:

- **The sample report.** A host that serves the folder as it is serves the
  committed `sample/report.html`. The GitHub Pages workflow instead builds
  `exposure` from the same commit and writes the sample afresh before it
  publishes, and its pull-request check fails when the committed copy is out
  of date. After a change to the scanner, run `site/build.sh --sample` and
  commit the result so every host shows the current report.
- **The share image.** Each page's `og:image` names
  `https://adityaakr.github.io/exposure-scanner/assets/og.png`, because link
  previews need an absolute address. On another host, replace that address
  in `index.html`, `sample/index.html` and `docs/index.html` with your own.
- **The tooling.** `build.sh`, `check.py` and this file are served too when
  the folder is published as it is. They hold nothing private. The GitHub
  Pages workflow leaves them out.

## Rules for the copy

Every sentence must be true of exposure 0.2.0, the current release, unless
it is marked **Next release** (merged on `main` and listed as unreleased in
the changelog) or **Planned** (not built). A command that does not work in
the current release is faded and has no copy button. Terminal output on the
pages is real: what 0.2.0 prints for the fixtures, or, for a command marked
**Next release**, what `main` prints, and said so; where a scan of your own
Mac is shown, only its shape is, with placeholders. Findings are about the
synthetic fixtures or are company-level counts; the site names no
third-party app as a finding. Wording states graded facts, as the report
does: "ships", "may access", never "spies".
