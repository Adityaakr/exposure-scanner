# Test fixtures

`macos/Skeleton.app` is a synthetic macOS application bundle. It is the
fixture of the walking skeleton (build plan, task 4): scanning it must yield
exactly one claim, Sentry, from the folder name
`Contents/Frameworks/Sentry.framework`.

Nothing in it is a real program. The two "binaries" are a Mach-O magic number
followed by a line of text, which is all the collector needs to classify and
hash them. The framework uses the symbolic links Xcode creates, so the
fixture also exercises the rule that links are never followed.

Real artifacts are never stored in this repository. They are pinned by hash
and URL and fetched in CI (build plan, task 13).
