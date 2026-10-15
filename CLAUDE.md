# Working on Sift

## Push every change

This repo must always match the working tree. After finishing any change:

```
go build ./... && go test ./...
git add -A
git commit -m "..."
git push origin main
```

Use `git add -A` from the repo root, not `git add <file>`. It stages **new files, moves and
deletions**, not just edits — new files being left behind is the thing to avoid. Do this without
being asked, as soon as a change builds and its tests pass. One commit per coherent change, never
a knowingly broken tree.

Before committing, check nothing is being silently skipped:

```
git status --porcelain            # should be empty after the commit
git status --porcelain --ignored  # only .claude/ and dist/ should be listed
```

If a new file shows up as ignored and shouldn't be, fix `.gitignore` rather than force-adding it.

## Never commit

- API keys, tokens, proxy credentials, certificates, private keys
- captured traffic (`.har`), APK/IPA files, `config.json`, `sender.json`
- the built `dist/sift.exe` (it goes on a release instead)

All Sift runtime data lives in `%USERPROFILE%\.sift` — settings, the CA key, and `sender.json`,
which holds saved proxy passwords. None of it belongs in the repo. `.gitignore` is a backstop,
not the plan.

## Commits

Author is `oli <258931592+dna0102@users.noreply.github.com>`, set in this repo's local git
config. That is GitHub's noreply address for the dna0102 account, so commits attribute correctly
while keeping personal email addresses out of a public repo.

Do not add `Co-Authored-By` trailers or any other attribution. The history was rewritten once to
remove them so the repo shows a single contributor; don't reintroduce them.

Note that `D:` doesn't record file ownership, so git needs
`git config --global --add safe.directory D:/Sift`. It is already set.

## Code style

**No comments.** Not in Go, JS, CSS or HTML. The only exceptions are compiler directives
(`//go:build`, `//go:embed`), which are not comments and must stay. Let naming carry the meaning
and put explanation in `docs/README.md`.

Keep the README plain-spoken: no feature tables, no bolded marketing, no exhaustive bullets.

Browser JS stays in `internal/ui/web/`, one file per view (`app.js` traffic, `sender.js` Sender,
`jar.js` Jar, `apps.js` Apps). Shared helpers live at the top level of `app.js`, which loads
first. Everything else is Go.

## Layout

```
cmd/sift/main.go        flags, startup, shutdown
internal/app/           the App bundle every subsystem is handed
internal/core/          Flow, Store, Hub, Config, rules, breakpoints, body decoding
internal/proxy/         the proxy, upstream, pinning, clienthello, websockets
internal/ca/            certificate authority
internal/sysproxy/      Windows proxy settings and platform bits
internal/apk/           APK/IPA parsing, scanner, jadx
internal/emulator/      emulator control and Frida
internal/sender/        the Sender, TLS fingerprinting, the Jar
internal/ui/            dashboard, templates, embedded web assets
```

Subsystems take the dependencies they need, not a `*App`. `internal/app` holds the shared bundle
so `ui` can import it without a cycle. The proxy reaches the emulator through a callback field,
so neither imports the other. A Go package is a directory — adding a folder means adding a
package.

## Build and release

```
scripts\build.cmd                 builds dist\sift.exe
dist\sift.exe -no-open            run it
go test ./...                     all tests
```

Releases carry the exe:

```
gh release create vX.Y.Z "dist/sift.exe#sift.exe (Windows x64)" --title "Sift X.Y.Z" --notes "..."
```

Bump `Version` in `internal/app/app.go` to match.
