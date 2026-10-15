# Sift

**A traffic interception proxy and mobile app analyser in a single 11 MB executable.**

Sift sits between your apps and the internet, decrypts HTTPS, and shows every request live in
your browser. It also pulls apart APK and IPA files to show you the endpoints, secrets and
certificate pinning hiding inside them — then boots the app in an emulator with its traffic
flowing straight into the same window.

No Java runtime. No installer. No cloud account. One Go binary, starts in under a second.

```
dist\sift.exe        →  dashboard on http://127.0.0.1:9091
```

---

## Setup

**1. Build it** (needs [Go 1.26+](https://go.dev/dl/), nothing else)

```
git clone https://github.com/dna0102/Sift
cd Sift
scripts\build.cmd
```

**2. Run it**

```
dist\sift.exe
```

Or just double-click **`Sift.cmd`** — it builds on first run, then launches. The dashboard
opens by itself.

**3. Trust the certificate** — click **Certificate → Install**, confirm the Windows prompt.
Without this, HTTPS stays unreadable.

**4. Capture something** — tick **System proxy**. Every app that honours the Windows proxy
setting now flows through Sift.

That's it. Closing the window (or Ctrl+C, or a crash) puts your proxy settings back.

<details>
<summary><b>Capturing from a phone or another machine</b></summary>

1. Settings → **Allow other devices on my network**
2. Click **Devices** → allow Sift through Windows Firewall (one click, needs admin)
3. On the phone: Wi-Fi proxy → *Automatic* → `http://<this-PC-IP>:9090/proxy.pac`
4. Install the certificate from `http://<this-PC-IP>:9090/`

If Sift isn't running, the phone connects directly instead of dropping offline.
</details>

<details>
<summary><b>Command-line tools (curl, Python, Node)</b></summary>

These ignore the Windows proxy setting. The Certificate dialog lists the exact environment
variables to export. Windows' bundled `curl.exe` also needs `--ssl-no-revoke`.
</details>

---

## What you get

### Traffic
- **HTTP, HTTPS, HTTP/2, h2c, WebSockets** (every frame) and streaming responses — captured at
  full speed, because responses stream to the app while a copy is kept.
- **Which app made each request**, grouped by app and by domain in the sidebar.
- **Inspector** — headers, query, cookies, body as JSON tree / pretty / form / multipart /
  GraphQL / image / video / HTML preview / text / hex, raw message, timing breakdown.
- **Filters** — `method:POST status:4xx host:api path:/v1 type:json app:chrome body:token`,
  prefix with `-` to exclude. Plain words search URLs, headers *and* bodies.
- **Tools** — breakpoints (pause, edit, continue, abort), Map Local, Map Remote, Block List,
  Allow List, Rewrite rules, network throttling, no-cache mode.
- **Export** — HAR (streamed to disk, so a 2 GB capture won't OOM you), Postman collections,
  HAR import. Copy any request as cURL, PowerShell, Python, Go or `fetch`.

### Sender
A full request workbench, in the same window as your traffic:

- Right-click any captured request → **Send to Sender** (or press `S`), or start from scratch.
- Edit **everything** as raw HTTP text — request line, every header, the body — and it goes out
  exactly as typed, mismatched `Host` and all. **Target** is a separate box, so one request can
  be pointed at staging, production or localhost without retyping it.
- **Choose how it goes out**: straight out over your network, back through Sift's own proxy so
  your rules and breakpoints apply to the resend, or via an upstream **HTTP/HTTPS or SOCKS5**
  proxy with username and password. Each route can also pin **which local interface to send
  from** — Wi-Fi vs Ethernet vs VPN — plus certificate verification, redirect following and a
  timeout. Save them as named profiles and switch with one click.
- Named tabs that survive restarts, a send history per tab, and a **Diff** view comparing a
  response line-by-line with the previous send.
- `Ctrl+Enter` sends. Every send also lands in the Traffic list, so all the normal inspection
  tools work on it.

### Apps (APK / IPA)
Drop an `.apk`, `.ipa`, `.xapk` or `.aab` on the page:

- **Android** — decompiled with [jadx](https://github.com/skylot/jadx) (downloaded on first
  use). Reads the manifest: package, version, SDK levels, permissions, exported components,
  deep links, cleartext config, signing scheme.
- **iOS** — `Info.plist` (binary or XML), bundle id, URL schemes, App Transport Security,
  permission usage strings, plus strings from the Mach-O binary.
- **Findings**, each with file, line number and a built-in code viewer:

  | | |
  |---|---|
  | **Endpoints** | URLs and WebSockets the app talks to — hosts also seen in live traffic get a **● traffic** badge that jumps straight to those requests |
  | **Secrets** | API keys, tokens, private keys, hardcoded passwords (masked in the UI) |
  | **SSL pinning** | OkHttp `CertificatePinner`, custom `TrustManager`s, network-security-config pins, TrustKit, Alamofire, Flutter, React Native — i.e. exactly what would block you |
  | **Auth & Captcha** | login, register, OTP/2FA, OAuth, biometric, payment, reCAPTCHA / hCaptcha / Turnstile / Arkose touchpoints |
  | **Deep links, trackers/SDKs, cleartext** | |

Static analysis only: Sift reads the app. It never logs in, submits a form or solves a captcha.

### Run it in an emulator
On an APK report, **▶ Open in emulator** boots an Android AVD, routes it through Sift, installs
the app and launches it. You drive the app by hand while its traffic streams into the Traffic
tab, tagged with the app name.

Tick **Bypass SSL pinning (Frida)** to decrypt apps that pin. Sift starts `frida-server` and
injects a universal unpinning script, hooking OkHttp `CertificatePinner`, custom
`X509TrustManager`s, Conscrypt, the network-security-config checker, TrustKit and WebView.

Needs the Android SDK (an AVD + platform-tools), and for Frida: `pip install frida-tools` plus a
rooted AVD with a matching `frida-server`. Best image is **non-Play-Store, rooted** — Play Store
images have a locked system partition, so only browser HTTPS decrypts there.

---

## Why Sift instead of Burp Suite

Burp is a mature, excellent tool. Sift is built for a narrower job — **understanding and
replaying real traffic, especially mobile traffic** — and in that lane it's faster and far less
work to run.

| | Sift | Burp Suite |
|---|---|---|
| **Install** | one 11 MB `.exe` | ~1 GB installer |
| **Runtime** | none | bundled JVM |
| **Cold start** | under a second | 15–30 s |
| **Idle RAM** | ~30 MB | 600 MB – 1.5 GB |
| **UI** | your browser — zoom, multiple tabs, remote over the LAN | Java desktop window |
| **Big captures** | virtualised list; 10,000 rows cost the same as 40. HAR export streams to disk | sluggish, and exports build in memory |
| **Pinned apps that reject the CA** | auto-detected and passed through, so the app **keeps working** | connection just fails |
| **Resending requests** | Sender: raw editing, per-request route (direct / through Sift / HTTP / SOCKS5), pick the outgoing interface, response diff | Repeater: raw editing, one global upstream proxy setting, no diff |
| **Mobile app analysis** | built in — decompile, find endpoints/secrets/pinning, cross-linked to live traffic | not included |
| **Emulator + Frida unpinning** | one click, from the APK report | manual setup, every time |
| **Which app sent this?** | shown per request | not shown |
| **Price** | free, MIT | Community is crippled; Pro is ~£400/yr |

**What Burp still does better**, and it's worth saying plainly: Intruder, the active scanner,
the BApp extension ecosystem, collaborator/OAST, and a decade of niche hardening. If your job is
automated vulnerability scanning or fuzzing at scale, use Burp. If your job is *watching what an
app actually does and poking at it*, Sift will get you there with a lot less friction.

### vs. the others

- **Fiddler** — closed source, nags toward a subscription, Windows-centric UI, no mobile app analysis.
- **Charles** — paid licence, Java desktop app, no static analysis.
- **Proxyman** — very good, but macOS-first and the useful parts are paywalled.
- **mitmproxy** — great engine, but the Python stack is slow under load and the web UI is thin.
  Sift started life on mitmproxy and was rewritten in Go precisely for the speed.

---

## Flags

| | |
|---|---|
| `-port 9090` | proxy port |
| `-ui-port 9091` | dashboard port |
| `-lan` | let phones and VMs on your network use the proxy |
| `-system-proxy` / `-no-system-proxy` | turn the system proxy on/off at launch |
| `-no-open` | don't open a browser |
| `-reset-proxy` | restore Windows proxy settings and exit |

Flags apply to that run only. Settings, rules, Sender profiles and the certificate live in
`%USERPROFILE%\.sift` — never in the project folder.

### Keyboard

`↑ ↓` move · `/` filter · `Ctrl+K` clear · `Ctrl+E` pause recording · `R` replay ·
`E` edit · `S` send to Sender · `Ctrl+Enter` send · `Del` delete · `Esc` close

---

## Keeping apps working

The hard part of a proxy isn't capturing traffic, it's *not breaking everything else*. Sift:

- **passes pinned hosts through** once an app rejects its certificate, so the app recovers
  instead of staying broken (undo it under Tools → HTTPS decryption)
- **skips known-pinned services** from the start — Apple, iCloud, WhatsApp, Signal, Dropbox,
  password managers, Windows Update, Battle.net
- lets you turn decryption off **per app** (right-click it in the sidebar)
- fixes **Microsoft Store apps**, which can't reach `127.0.0.1` by default — Settings →
  *Allow all Store apps* (needs admin; *Undo* removes only what Sift added)
- relays **non-HTTP traffic** on proxied connections (MQTT, game protocols, raw TCP) instead of
  killing it
- accepts **TLS 1.0/1.1**, old ciphers and RSA-only clients, for legacy apps and devices
- runs a **watchdog** that restores your proxy settings if Sift is killed or crashes
- shows **why** each undecrypted connection wasn't decrypted, right in the list

---

## Layout

```
Sift.cmd          double-click launcher
go.mod, go.sum    Go module
cmd/sift/         all Go source + the embedded dashboard (web/)
scripts/          build.cmd
docs/             full documentation
dist/             build output — generated, git-ignored
```

See **[docs/README.md](docs/README.md)** for the complete reference, including a map of every
source file.

---

## Notes

- Captured traffic is kept **in memory only**. Limits (request count, body size, total memory)
  are in Settings.
- `SIFT_DEBUG=1` prints connection decisions. `SIFT_PPROF=1` serves a CPU profile on
  `127.0.0.1:6060`.
- Sift is for traffic you are authorised to inspect — your own apps, your own devices, and
  systems you have permission to test.

## Licence

MIT
