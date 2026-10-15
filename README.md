# Sift

An HTTP/HTTPS proxy you run on your own machine. It decrypts TLS, shows every request live in
the browser, lets you edit and resend any of them, and pulls APK/IPA files apart to show you the
endpoints and secrets inside.

One `sift.exe`, about 18 MB. No Java, no installer, no account.

![dashboard](https://img.shields.io/badge/dashboard-127.0.0.1%3A9091-blue) ![go](https://img.shields.io/badge/go-1.26-00ADD8) ![licence](https://img.shields.io/badge/licence-MIT-green)

## Running it

Grab `sift.exe` from [Releases](https://github.com/dna0102/Sift/releases) and run it. Or build
it yourself, which needs [Go 1.26+](https://go.dev/dl/) and nothing else:

```
git clone https://github.com/dna0102/Sift
cd Sift
scripts\build.cmd
dist\sift.exe
```

`Sift.cmd` does the same thing if you'd rather double-click something.

The dashboard opens at http://127.0.0.1:9091. Two things to do on first run:

1. **Certificate → Install.** Windows will ask you to confirm. HTTPS stays unreadable until you
   do this.
2. Tick **System proxy.** Anything that respects the Windows proxy setting now goes through Sift.

Your proxy settings get put back when you close the window, hit Ctrl+C, or if Sift crashes —
there's a watchdog process for that last case.

## The three tabs

**Traffic** is the list. Filter it with plain words or `method:POST status:4xx host:api
type:json app:chrome body:token`; a `-` in front excludes. Click a request for headers, cookies,
a JSON tree, timing, raw bytes, hex. Right-click one for everything else. Breakpoints, Map
Local/Remote, block and rewrite rules live under Tools. Export to HAR or Postman.

**Sender** is the repeater. Right-click any request → *Send to Sender*, or press `S`. You get
the raw HTTP in a text box — change the method, any header, the body, whatever — and `Ctrl+Enter`
sends it. It goes out as typed, mismatched `Host` and all.

The useful bit is the route dropdown. You can send straight out, or back through Sift itself so
your own breakpoints and rewrite rules apply to the resend, or through an upstream HTTP or
SOCKS5 proxy with a username and password. Each saved route can also pin which network interface
to leave from, so you can pick Wi-Fi over Ethernet over a VPN adapter. Tabs keep their own
history and there's a diff against the previous send.

Next to it is the TLS dropdown, which is the other half of the point. Pick Chrome, Firefox,
Safari, OkHttp or any of 83 profiles and the request goes out with that client's real TLS and
HTTP/2 fingerprint, via [tls-client](https://github.com/bogdanfinn/tls-client). Your headers
also go out in the order you typed them — a Chrome JA3 with Go's alphabetical header order
still reads as a bot, so both halves matter. It works through every route, proxies included.

**Jar** takes a URL and shows you everything about its cookies. It walks the redirect chain
keeping a jar like a browser would, and for each hop shows what cookies went out, what
`Set-Cookie` came back with domain, path, expiry and flags, and the full request and response
headers. The Find box searches all of that at once, as text or regex, and tells you where each
hit came from. Same route and TLS choices as the Sender, and every hop lands in the Traffic tab.

**Apps** takes an `.apk` or `.ipa` (drag it onto the page) and tells you what's inside: the
endpoints it talks to, API keys and tokens left in the binary, where it does certificate
pinning, its login and captcha screens, deep links, trackers. Android goes through
[jadx](https://github.com/skylot/jadx), downloaded on first use. Hosts that also show up in your
live traffic get a badge that jumps you there.

From an APK report you can hit **Open in emulator** and Sift will boot an AVD, route it through
itself, install the app and start it, with everything landing in the Traffic tab. Tick the Frida
box and it'll try to defeat certificate pinning too. That part needs a rooted AVD and
`pip install frida-tools`, and it won't beat apps with serious anti-instrumentation — TikTok
being the obvious one.

## Why not just use Burp

Burp is a better tool than this one in most respects and I'm not going to pretend otherwise. It
has Intruder, the scanner, collaborator and a decade of extensions. If you're fuzzing or running
automated scans, use Burp.

Sift is for the other thing — watching what an app actually does and poking at it by hand. For
that it's quicker to live with:

- it starts in under a second instead of thirty, and sits at ~30 MB of RAM instead of a gigabyte
- the UI is a web page, so you can zoom it, open two, or reach it from another machine
- the request list is virtualised; ten thousand rows cost the same as forty, and HAR export
  streams to disk instead of building the whole thing in memory
- when an app rejects the certificate because it pins, Sift notices and passes that host through
  so the app keeps working, instead of leaving you with a dead connection
- it says which program made each request
- APK/IPA analysis and the emulator are built in
- it's free and it's one file

## Phones and other machines

Turn on *Allow other devices on my network* in Settings, click **Devices**, and let Sift through
the firewall (one click, wants admin). On the phone set the Wi-Fi proxy to Automatic with
`http://<your-ip>:9090/proxy.pac`, then install the certificate from `http://<your-ip>:9090/`.

Using Automatic rather than a manual proxy means the phone still works when Sift isn't running.

Most Android apps ignore user-installed certificates. Sift spots that and lets them through
rather than breaking them.

## Flags

```
-port 9090          proxy port
-ui-port 9091       dashboard port
-lan                let other devices on the network use the proxy
-system-proxy       turn the system proxy on at launch
-no-system-proxy    don't
-no-open            don't open a browser
-reset-proxy        put Windows' proxy settings back and exit
```

These apply to one run only. Settings, rules, saved Sender routes and the certificate live in
`%USERPROFILE%\.sift`, never in the project folder.

## Layout

```
cmd/sift/           main.go
internal/app/       the shared App bundle
internal/core/      flows, store, config, rules, breakpoints
internal/proxy/     the proxy, upstream, pinning, websockets
internal/ca/        certificate authority
internal/sysproxy/  Windows proxy and platform bits
internal/apk/       APK/IPA parsing and the scanner
internal/emulator/  emulator control and Frida
internal/sender/    the Sender, TLS fingerprinting and the Jar
internal/ui/        dashboard, templates, web assets
```

[docs/README.md](docs/README.md) has the full reference — every flag, how pinning detection
works, what each finding means, and a map of the source.

## Notes

- Command-line tools (curl, Python, Node) ignore the Windows proxy setting. The Certificate
  dialog lists the environment variables to set. Windows' own `curl.exe` also wants
  `--ssl-no-revoke`.
- Captured traffic is held in memory only. The limits are in Settings.
- `SIFT_DEBUG=1` prints why each connection was or wasn't decrypted. `SIFT_PPROF=1` serves a
  profile on 127.0.0.1:6060.
- Obviously: only point this at traffic you're allowed to look at.

MIT.
