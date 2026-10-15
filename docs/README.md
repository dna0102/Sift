# Sift

Local HTTP/HTTPS traffic capture and inspection, like Proxyman. Sift sits between the apps on your
PC and the internet, decrypts HTTPS, and shows every request live at **http://127.0.0.1:9091**.

One Go program, one ~11 MB `sift.exe`, no runtime to install.

## Start

Double-click **`Sift.cmd`** (it builds `dist\sift.exe` the first time if needed), or:

```
scripts\build.cmd
dist\sift.exe
```

1. Click **Certificate → Install** once. Windows asks you to confirm. Without it, HTTPS can't be read.
2. Tick **System proxy**. Every app that uses the Windows proxy setting now goes through Sift.
3. Ctrl+C (or closing the window) quits and puts your proxy settings back, even after a crash.

| Flag | |
|---|---|
| `-port 9090` | proxy port |
| `-ui-port 9091` | dashboard port |
| `-lan` | let phones/VMs on your network use the proxy |
| `-system-proxy` / `-no-system-proxy` | turn the system proxy on/off at launch |
| `-no-open` | don't open the browser |
| `-reset-proxy` | restore the Windows proxy settings and exit |

Flags only apply to that run. Settings, rules and the certificate live in `%USERPROFILE%\.sift`.

## What it does

- Captures HTTP, HTTPS (HTTP/1.1 and HTTP/2), WebSockets (every message) and streaming responses, at full network speed: responses are streamed to the app while a copy is kept.
- Shows which app made each request, grouped by app and domain.
- Filter box: plain text, or `method:POST status:4xx host:api path:/v1 type:json app:chrome body:token`, `-word` to exclude.
- Inspector: headers, query, cookies, body (JSON tree, pretty, form, multipart, GraphQL, image/video/HTML preview, text, hex), raw message, timing breakdown, WebSocket messages.
- Tools: breakpoints (pause, edit, continue or abort requests and responses), Map Local, Map Remote, Block List, Allow List, Rewrite (headers, body text, status), HTTPS include/exclude lists, network throttling, no-cache mode.
- Replay, edit and resend, compose new requests. Copy as cURL, PowerShell, Python, Go or fetch.
- Export HAR (streamed to disk, so large captures don't run out of memory), Postman collections; import HAR.
- Keys: `↑ ↓` move · `/` filter · `Ctrl+K` clear · `Ctrl+E` pause recording · `R` replay · `E` edit · `Del` delete · `Esc` close.

## Keeping apps working

- **Certificate pinning**: when an app rejects Sift's certificate, Sift passes that host through untouched from then on, so the app keeps working (its first connection fails; apps retry). Hosts learned this way are listed under Tools → HTTPS decryption, where you can undo them. Services known to pin (Apple, iCloud, WhatsApp, Signal, Dropbox, password managers, Windows Update, Battle.net) are skipped from the start.
- **Per-app decryption**: right-click an app in the sidebar → *Don't decrypt*, or list apps under Tools → HTTPS decryption.
- **Microsoft Store apps** (Mail, Store, Xbox, new Teams…) can't reach a proxy on 127.0.0.1 by default and go offline while the system proxy is on. Settings → *Allow all Store apps* fixes that (Windows asks for administrator rights; *Undo* removes only what Sift added).
- **Non-HTTP traffic** on proxied connections (MQTT, game or chat protocols over TLS, raw TCP) is passed or relayed as-is instead of breaking.
- **Old apps and devices**: TLS 1.0/1.1, old ciphers and RSA-only clients are accepted, and old servers are reachable.
- **Unencrypted HTTP/2 (h2c)**, e.g. gRPC without TLS, works through Sift.
- **Crash safety**: a tiny watchdog process restores your proxy settings if Sift is killed or crashes.
- Every connection that isn't decrypted shows why in the list (pinning, excluded app, not HTTP…).

## Phones and other devices

Click **Devices**. Turn on *Allow other devices on my network* in Settings, allow Sift through Windows Firewall (one click, needs administrator), then on the phone set the Wi-Fi proxy to *Automatic* with `http://<this PC>:9090/proxy.pac`. If Sift isn't running, the phone connects directly. Install the certificate from `http://<this PC>:9090/`. Most Android apps ignore user-installed certificates; Sift detects that and lets them through so they keep working.

## App analysis (APK / IPA)

The **Apps** tab (next to Traffic) statically analyses a mobile app so you can see how it works before and alongside its traffic. Drop an **.apk** or **.ipa** (also .xapk, .aab) onto the page, or click *Open APK / IPA…*.

- **Android (.apk)**: decompiled with [jadx](https://github.com/skylot/jadx), downloaded automatically on first use (~40 MB, needs a Java runtime). Reads the manifest for package, version, SDK levels, permissions, exported components, deep links, cleartext and network-security config, and the signing scheme.
- **iOS (.ipa)**: read directly (no jadx). Parses `Info.plist` (binary or XML) for bundle id, version, URL schemes, App Transport Security, and usage-description permissions, and scans strings in the Mach-O binary.
- **Findings**, each with file and line and a built-in code viewer:
  - **Endpoints** — URLs and WebSockets the app talks to. Hosts also seen in captured traffic get a **● traffic** badge that jumps to those requests.
  - **Secrets** — API keys, tokens, private keys, hardcoded passwords (masked in the UI).
  - **SSL pinning** — OkHttp CertificatePinner, custom TrustManagers, network-security-config pins, TrustKit, Alamofire/SecTrustEvaluate, Flutter/React-Native pinning. These are the places that would stop Sift reading HTTPS.
  - **Auth & Captcha** — login, register, OTP/2FA, OAuth, biometric, payment and captcha (reCAPTCHA, hCaptcha, Turnstile, Arkose) touchpoints, mapped only.
  - **Deep links, trackers/SDKs, cleartext config.**
- A legend of what each finding means is shown by default (Hide to collapse it).

Static analysis is read-only: Sift reads the app, it never logs in, submits forms or solves captchas.

### Run it in an emulator

On an APK report, **▶ Open in emulator** boots an Android emulator, routes its traffic through Sift, installs the app and opens it — so you can drive the app by hand while all its traffic flows into the **Traffic** tab, tagged with the app name. It needs the Android SDK (Android Studio: an AVD plus platform-tools); Sift finds it via `ANDROID_HOME`/`ANDROID_SDK_ROOT` or the default install path.

How it works: `adb reverse` tunnels the emulator's loopback to Sift's port, Android's global proxy is pointed at it, and Sift's certificate is installed as a **system** CA (on a writable-system or rooted AVD) so apps trust it.

**Bypass SSL pinning (Frida).** Tick this in the launch dialog to decrypt apps that pin their certificate. Sift starts `frida-server` on the device and injects a universal unpinning script, so the app's HTTPS becomes readable in the Traffic tab instead of showing as encrypted tunnels. It needs the `frida` Python module on this PC (`pip install frida-tools`) and a rooted AVD with `/data/local/tmp/frida-server` (the version must match your host's `frida`). Without it, pinned apps still run and are captured, just as tunnels.

What it covers: the script hooks the common **Java-layer** pinning — OkHttp `CertificatePinner`, custom `X509TrustManager`, Conscrypt, the network-security-config pin checker, TrustKit, WebView. This reliably decrypts the large majority of apps. It launches the app under Frida (spawn); if the app detects that and self-exits, Sift re-launches it normally and attaches instead.

What it does **not** reliably do: apps with heavy anti-instrumentation (notably **TikTok / ByteDance**) detect Frida through native code and kill themselves regardless — there is no dependable one-click bypass for these, and defeating them is an app-specific, constantly-changing effort outside Sift's scope. Pinning done purely in native BoringSSL is also not bypassed by default, because the native hooks that would do it destabilise some apps. When unpinning can't take hold, the app still runs and all its non-pinned traffic is captured.

Best AVD choice: a **non-Play-Store, rooted** image (e.g. a Frida AVD with frida-server). Play Store images have a locked system partition, so only browser HTTPS decrypts there. **Stop** shuts the emulator down and restores its settings.

## Notes

- Command-line tools (Python requests, Node, curl) ignore the Windows proxy. The Certificate dialog lists the environment variables to set. Windows' `curl.exe` also needs `--ssl-no-revoke`.
- Captured traffic is kept in memory only (limits in Settings: requests, body size, total memory).
- `SIFT_DEBUG=1` prints connection decisions to the console; `SIFT_PPROF=1` serves a CPU profile on 127.0.0.1:6060.

## Code

All Go source and the embedded dashboard live in `cmd/sift/` (one `package main`, so the
`//go:embed web` of the dashboard works). Paths below are relative to `cmd/sift/`.

| File | |
|---|---|
| `main.go` | startup, ports, shutdown, replay/compose |
| `proxy.go` | the proxy: CONNECT, deciding what to decrypt, rules, streaming, pass-through |
| `clienthello.go` | reads the server name and protocols from an app's TLS hello |
| `pins.go` | certificate-pinning detection and the known-pinned list |
| `upstream.go` | connections to the real servers (HTTP/1.1, HTTP/2, h2c, legacy TLS) |
| `websocket.go` | WebSocket relay and message capture |
| `ca.go` | the Sift certificate authority and installing it |
| `store.go` | captured requests and the live-update hub |
| `rules.go`, `breakpoints.go` | rule matching, paused requests |
| `render.go` | the detail pane HTML (bodies, highlighting, timing) |
| `web.go` | dashboard server and API |
| `har.go`, `codegen.go` | HAR/Postman export and import, copy as code |
| `decode.go` | gzip/deflate/brotli/zstd decoding, content types |
| `sysproxy.go`, `platform_*.go` | Windows system proxy, app detection, Store-app and firewall fixes, watchdog |
| `mobile.go`, `mobilestore.go` | APK/IPA analysis engine and the in-memory report store |
| `dexscan.go`, `axml.go` | direct dex-string + binary-manifest scan for apps too big to decompile |
| `emulator.go`, `web_emulator.go` | boot an emulator, route it through Sift, install & run the app |
| `frida.go`, `web/unpin.js` | SSL-pinning bypass: start frida-server and spawn the app under Frida |
| `tools.go` | downloads and caches jadx on first use |
| `scan.go` | the endpoint/secret/pinning/auth pattern scanner |
| `plist.go` | Apple property-list reader (binary + XML) for IPAs |
| `highlight.go` | source highlighter for the decompiled-code viewer |
| `web_mobile.go` | dashboard API for the Apps view |
| `web/` | `index.html`, `app.css`, `app.js` (traffic view + live updates), `apps.js` (Apps view), `modals.html` (dialogs) |
