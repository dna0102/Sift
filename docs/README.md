# Sift

Local HTTP/HTTPS traffic capture and inspection, like Proxyman. Sift sits between the apps on your
PC and the internet, decrypts HTTPS, and shows every request live at **http://127.0.0.1:9091**.

One Go program, one ~18 MB `sift.exe`, no runtime to install.

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
- Replay, edit and resend, compose new requests, or open any request in the **Sender** (below). Copy as cURL, PowerShell, Python, Go or fetch.
- Export HAR (streamed to disk, so large captures don't run out of memory), Postman collections; import HAR.
- Keys: `↑ ↓` move · `/` filter · `Ctrl+K` clear · `Ctrl+E` pause recording · `R` replay · `E` edit · `S` send to Sender · `Del` delete · `Esc` close.
- Right-click any request for replay, Sender, copy-as-code, breakpoint, map-local, block and don't-decrypt in one menu.

## Sender

The **Sender** tab is a request workbench: take anything you captured, change any part of it,
and send it again — as many times as you like, down whichever path you choose.

Open it with the **Sender ▸** button in the detail pane, right-click → *Send to Sender*, or the
`S` key. Each request gets its own tab; tabs are named (double-click to rename), kept across
restarts, and each keeps its own send history.

- **Edit the request as raw HTTP text** — the request line, every header, the body. Nothing is
  normalised behind your back, so deliberately malformed requests still go out as typed. The
  `Host` header is sent exactly as written even when it doesn't match the target, which is the
  point for host-routing tests.
- **Target** is separate from the request text, so you can point the same request at staging,
  production or localhost without retyping it. A full `http(s)://…` in the request line wins.
- **Update Content-Length** (on by default) recomputes it from the body. Turn it off to send a
  value you typed — it is clamped to the body length, and the Sender tells you when it clamped.
- `Transfer-Encoding: chunked` is honoured if you type it.
- **Route** decides how the request leaves this machine:

  | Route | |
  |---|---|
  | **Direct** | straight out over this PC's network |
  | **Through Sift** | back in through Sift's own proxy, so breakpoints, rewrites, Map Local/Remote, blocking and throttling all apply to the resend. The send then shows up twice: once as your Sender row, once as the proxy saw it |
  | **HTTP / HTTPS proxy** | an upstream proxy, with optional username and password |
  | **SOCKS5 proxy** | likewise, with RFC 1929 username/password auth. Host names are resolved by the proxy, not locally |

  Each saved route can also pin **Send from** — a local interface address, so you choose Wi-Fi
  vs Ethernet vs a VPN adapter — plus certificate verification (follow Settings, always verify,
  or accept anything), redirect following, and a timeout. Routes are saved as named profiles in
  `%USERPROFILE%\.sift\sender.json` (mode 0600, since they can hold proxy passwords) and never
  in the project folder.
- **Response** views: Raw, Pretty (JSON reformatted), Headers, Render (sandboxed preview) and
  **Diff**, which compares the response line-by-line with the previous send in that tab — so you
  can see exactly what your edit changed.
- **History** along the bottom: every send with its status, time and size. Click one to bring
  its request and response back.
- **Inspect ▸** jumps to the same send in the Traffic list, where the full inspector — JSON
  tree, timing breakdown, cookies, hex — works on it like any other request.
- `Ctrl+Enter` sends.

## Keeping apps working

- **Certificate pinning**: when an app rejects Sift's certificate, Sift passes that host through untouched from then on, so the app keeps working (its first connection fails; apps retry). Hosts learned this way are listed under Tools → HTTPS decryption, where you can undo them. A client that rejects three or more different hosts, and hasn't completed a handshake with Sift in the last three minutes, doesn't trust the certificate at all. That isn't pinning, so Sift says so and doesn't learn those hosts. It also un-learns any it already saved from that client. Once that client completes a handshake again, the hosts are decrypted again. Services known to pin (Apple, iCloud, WhatsApp, Signal, Dropbox, password managers, Windows Update, Battle.net) are skipped from the start.
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

The default choice is the **Sift device**, an AVD Sift creates for itself on first use. It is built from an installed Google APIs system image (Android 14 preferred), because those can be rooted and Play Store images can't. It gets 4 GB of RAM, four cores and the host GPU. The first launch does a full boot, which takes about a minute. Stopping it from Sift saves a quickboot snapshot, and later launches resume in well under half a minute with the certificate still trusted. Other AVDs, and devices that are already running (including phones on USB), are listed below it. Other AVDs also boot with the GPU on and at least 3 GB of RAM. Without those, Android draws on the CPU, which is what makes System UI stop responding.

How it works: Android's global proxy is pointed at Sift on `10.0.2.2`, and Sift's certificate is trusted as a **system** CA. With `adb root`, Sift copies the system store into a tmpfs over `/system/etc/security/cacerts` and adds its own certificate. The file must be named after OpenSSL's `subject_hash_old` of the certificate's subject (MD5 of its DER encoding). Android looks up an issuer by that name, and under any other name the certificate is ignored. When the certificate is newly installed, the pins learned while the device didn't trust Sift are cleared. On Android 14 and later it also bind-mounts that store over the Conscrypt APEX inside zygote's mount namespace and each running app's, so every app sees it. Animations, package verification and ANR dialogs are switched off so installs and launches don't stall.

**Bypass SSL pinning (Frida).** Tick this in the launch dialog to decrypt apps that pin their certificate. Sift starts `frida-server` on the device and injects a universal unpinning script, so the app's HTTPS becomes readable in the Traffic tab instead of showing as encrypted tunnels. It needs the `frida` Python module on this PC (`pip install frida-tools`) and a rooted AVD with `/data/local/tmp/frida-server` (the version must match your host's `frida`). Without it, pinned apps still run and are captured, just as tunnels.

What it covers: the script hooks the common **Java-layer** pinning — OkHttp `CertificatePinner`, custom `X509TrustManager`, Conscrypt, the network-security-config pin checker, TrustKit, WebView. This reliably decrypts the large majority of apps. It launches the app under Frida (spawn); if the app detects that and self-exits, Sift re-launches it normally and attaches instead.

What it does **not** reliably do: apps with heavy anti-instrumentation (notably **TikTok / ByteDance**) detect Frida through native code and kill themselves regardless — there is no dependable one-click bypass for these, and defeating them is an app-specific, constantly-changing effort outside Sift's scope. Pinning done purely in native BoringSSL is also not bypassed by default, because the native hooks that would do it destabilise some apps. When unpinning can't take hold, the app still runs and all its non-pinned traffic is captured.

If the device already has a different build of the app, Sift allows the downgrade. If that isn't enough, for example because the signature differs, it uninstalls the old copy and installs again. Apps often update themselves on the device, so this comes up a lot. When an install does fail, Sift shows Android's failure code. Traffic is tagged with the app's real name, which Sift reads from its decompiled resources when the manifest only references a string resource.

Play Store images can't be rooted, so on them only browser HTTPS decrypts. Apps on the normal Android network stack (HttpsURLConnection, OkHttp, Cronet) trust the system CA. Chrome itself and Flutter apps bring their own root stores and ignore it, so for those you need the Frida option. **Stop** clears the proxy and shuts down an emulator Sift started. It leaves alone a device that was already running.

The code viewer opens the file a finding came from. Large APKs are scanned from the strings in their dex files. Those dumps stay viewable after jadx finishes decompiling in the background, and for big dumps the viewer shows only the lines around the finding.

## Notes

- Command-line tools (Python requests, Node, curl) ignore the Windows proxy. The Certificate dialog lists the environment variables to set. Windows' `curl.exe` also needs `--ssl-no-revoke`.
- Captured traffic is kept in memory only (limits in Settings: requests, body size, total memory).
- `SIFT_DEBUG=1` prints connection decisions to the console; `SIFT_PPROF=1` serves a CPU profile on 127.0.0.1:6060.

## TLS fingerprints

Every request the Sender and the Jar send can impersonate a real client's TLS and HTTP/2
fingerprint, using [tls-client](https://github.com/bogdanfinn/tls-client). Pick one from the
**TLS** dropdown: 83 profiles covering Chrome, Firefox, Safari (desktop and iOS), Edge, Opera,
Brave, OkHttp and a few app-specific ones.

This changes what the server sees:

| | Go default | chrome_131 |
|---|---|---|
| JA3 | `d6627faa72aa91c9e2ae51d456173c69` | `a19ab9f02aacf42deddc1f2acb3d3f63` |
| JA4 | `t13d2512h2_b78ed14e2fd0_ab7e3b40a677` | `t13d1516h2_8daaf6152771_02713d6af862` |

Headers go out in the order you typed them, which matters as much as the TLS hello — a Chrome
JA3 with Go's alphabetical header order still reads as a bot. The Sender preserves your order
and passes it through as the HTTP/2 header order too.

A route can carry a default fingerprint, and the dropdown overrides it per tab. "Go default"
turns impersonation off and uses the standard library, which is faster and fine when nothing is
checking. Routes can also force HTTP/1.1.

Fingerprinting works through every route, including an upstream HTTP or SOCKS5 proxy and
Sift's own proxy.

## Jar

The **Jar** tab fetches a page and shows you everything about the cookies it hands out.

Give it a URL, pick a route and a fingerprint, and it walks the redirect chain (up to 12 hops)
keeping a cookie jar as a browser would. For each hop you get the cookies that were sent, the
`Set-Cookie` headers that came back with their domain, path, expiry and flags, and the full
request and response headers. Every hop is also a normal row in the Traffic list, so *inspect*
opens it in the usual inspector.

The **Find** box searches the jar, the `Set-Cookie` headers and both sets of headers at once,
as plain text or as a regular expression. Results say where each hit came from and on which
hop. Searching re-runs in the browser as you type, so it is instant once the fetch is done.

## Scan

The **Scan** tab finds web vulnerabilities and reports them as findings, each with a severity,
a confidence level, the evidence behind it, and how to reproduce and fix it.

It works in two ways. **Passive** analysis runs on its own over every request Sift records —
nothing extra is sent. It looks at headers, cookies, CORS, redirects, error pages and served
JavaScript, and flags things like missing HSTS or CSP, session cookies without Secure or
HttpOnly, a reflected `Access-Control-Allow-Origin` with credentials, stack traces and SQL
errors, leaked internal addresses and file paths, software-version banners, secrets echoed back
in a response, and API paths mined out of scripts. **Analyse captured traffic** replays passive
analysis over everything already in the list.

**Active scan** sends crafted requests. It will only touch hosts you list as in scope, so it
never fires at anything you have not named. For each request it finds the insertion points —
query and body parameters (form and JSON), cookies, and a few headers — takes a baseline of the
normal response, and then tries each enabled check, comparing what comes back against that
baseline so a real signal stands out from normal variation. The checks cover reflected XSS,
SQL injection (error, boolean and time-based), template injection, OS command injection, path
traversal and local file inclusion, open redirect, SSRF, CRLF/header injection, XXE and NoSQL
injection. Time-based checks confirm with a second, different delay before reporting, to keep
false positives down. With **discover** on it also looks for hidden files, directories and
parameters that are not linked from the traffic it has seen.

Intensity (light → insane) scales how many payloads and how much budget a scan uses; you can
also set the route, a TLS fingerprint, a request-per-second cap and concurrency. Every request a
scan sends is a normal row in the Traffic list, tagged `scan`, so each finding links straight to
the exact request behind it.

Findings collapse by type, host and insertion point, so the same issue on the same parameter is
one entry with a count rather than a flood. The left list sorts by severity and confidence and
filters as you type; selecting one shows the detail, the matched evidence, the payload, the
reproduction steps and the remediation, with a link back to the exact request in the Traffic
inspector. Severity runs critical / high / medium / low / info and confidence runs certain /
firm / tentative, the way a tester would rank them.

## AI

Sift can hand its findings and traffic to a language model to triage, correlate and suggest
next steps. It talks to several kinds of provider over plain HTTP: anything OpenAI-compatible
(OpenAI itself, and local servers like Ollama or vLLM through their `/v1` endpoint), Anthropic
Claude, and Google Gemini. A provider needs a name, a base URL, an API key where the service
wants one, and a list of model names. Local servers that need no key work the same way — point
the base URL at `http://localhost:11434/v1` and leave the key blank.

Each task can use a different model, with fallbacks. **Triage** judges every finding as
confirmed, likely, a false positive, or needing verification, and writes a short note back onto
the finding. **Correlate** looks across findings and traffic for issues that chain into
something bigger. **Recommend** names the attack surface worth focusing on and the next tests to
run. **Verify** reasons about one finding and how to prove it. **Chat** answers questions about
what Sift has seen. When a task has no model set it falls back to the first provider.

Keys live in `ai.json` under `%USERPROFILE%\.sift`, never in the project, and are never sent
anywhere except the provider you configured.

### MCP

Sift exposes an MCP server so an external AI agent can read its results and drive it. It speaks
JSON-RPC over `http://127.0.0.1:<ui-port>/mcp`, gated by a token shown in AI settings. The tools
cover listing and reading findings and captured requests, scan statistics and job status,
running passive analysis, and starting or stopping an active scan against named in-scope hosts.
An agent can therefore scan, read the evidence, correlate it and come back with verified,
prioritised findings. The endpoint only listens on localhost and refuses any request without the
token.

## Code

```
cmd/sift/main.go        flags, startup, shutdown
internal/app/           the App bundle every subsystem is handed, plus replay and compose
internal/core/          Flow, Store, the live-update Hub, Config/Settings, rules, breakpoints,
                        body decoding (gzip/deflate/brotli/zstd) and content classification
internal/proxy/         proxy.go        CONNECT, what to decrypt, rules, streaming, pass-through
                        clienthello.go  server name and protocols from an app's TLS hello
                        pins.go         pinning detection and the known-pinned list
                        upstream.go     connections out (HTTP/1.1, HTTP/2, h2c, legacy TLS)
                        websocket.go    WebSocket relay and message capture
internal/ca/            the Sift certificate authority and installing it
internal/sysproxy/      Windows proxy settings, app-per-connection lookup, Store-app and
                        firewall fixes, the crash watchdog
internal/apk/           mobile.go       the APK/IPA analysis engine
                        mobilestore.go  in-memory report store
                        scan.go         endpoint/secret/pinning/auth pattern scanner
                        dexscan.go      dex string scan for apps too big to decompile
                        axml.go         binary AndroidManifest reader
                        plist.go        Apple property lists (binary + XML) for IPAs
                        bundle.go       split-APK bundles
                        tools.go        downloads and caches jadx on first use
internal/emulator/      emulator.go     boot an AVD, route it through Sift, install and run
                        avd.go          the Sift device: picks a rootable image, writes the AVD, boot flags
                        frida.go        pinning bypass: start frida-server, spawn under Frida
                        unpin.js        the injected unpinning script
internal/sender/        sender.go       raw-HTTP parsing, tabs, routes, send history
                        transport.go    the two transports: Go's net/http, and tls-client for
                                        TLS/HTTP2 fingerprint impersonation
                        probe.go        the lean send path the scanner drives
                        jar.go          the Jar: redirect walking, cookie collection, search
internal/scan/          engine.go       the scan engine, jobs and the passive-on-capture hook
                        finding.go      the finding model: severity, confidence, evidence
                        store.go        findings store with dedup/merge and live push
                        scope.go        in-scope hosts, intensity, rate and concurrency options
                        checks.go       the catalogue of checks the UI lists
                        passive.go      the passive analysers
                        active.go       the active runner: baseline, budget, rate, concurrency
                        insertion.go    query/body/JSON/cookie/header insertion points
                        baseline.go     baseline capture and response comparison
                        payloads.go     the embedded payload library
                        checks_active.go the active checks and their verification
                        discover.go     content discovery and parameter mining
                        request.go      the Requester the engine sends through
                        signatures.go   shared detection regexes
internal/ai/            provider.go     OpenAI-compatible, Anthropic and Gemini HTTP clients
                        manager.go      provider config, per-task routing and fallbacks
                        analyze.go      triage, correlate, recommend, verify and chat
internal/mcp/           server.go       the MCP JSON-RPC endpoint and its token
                        tools.go        the MCP tools: read findings/flows, run scans
internal/ui/            web.go          dashboard server and API
                        web_sender.go   Sender API
                        web_scan.go     Scan API and the findings event stream
                        web_ai.go       AI triage, correlate, recommend, verify and chat
                        web_mobile.go   Apps API
                        web_emulator.go emulator API
                        render.go       detail-pane HTML (bodies, highlighting, timing)
                        har.go          HAR and Postman export and import
                        codegen.go      copy as cURL / PowerShell / Python / Go / fetch
                        highlight.go    source highlighter for the decompiled-code viewer
                        web/            index.html, app.css, modals.html, app.js (traffic),
                                        sender.js (Sender), jar.js (Jar), scan.js (Scan + AI),
                                        apps.js (Apps)
```

The source carries no comments. This file is the explanation.
