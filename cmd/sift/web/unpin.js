/*
 * Universal SSL unpinning for Android, injected by Sift via Frida.
 *
 * Two layers:
 *  (A) Java hooks — the default TrustManager, OkHttp CertificatePinner, Conscrypt, the
 *      network-security-config pin checker, TrustKit, Appcelerator, WebView.
 *  (B) Native hooks — BoringSSL / OpenSSL certificate verification in the app's .so files
 *      (SSL_CTX_set_custom_verify, SSL_set_custom_verify, SSL_get_verify_result). This is
 *      what big apps (TikTok/ByteDance, Cronet, Flutter, Unity, React Native) use, and what
 *      plain Java hooks miss — the usual cause of "certificate rejected (pinning)".
 *
 * It re-applies the native hooks as libraries load (dlopen), so pinning libs that are loaded
 * late are still covered.
 */

function log(m) { send("[unpin] " + m); }

/* ----------------------------------------------------------------- (A) Java */
function hookJava() {
  if (!Java.available) return;
  Java.perform(function () {
    var n = 0;

    try {
      var X509TM = Java.use("javax.net.ssl.X509TrustManager");
      var SSLContext = Java.use("javax.net.ssl.SSLContext");
      var TrustAll = Java.registerClass({
        name: "com.sift.TrustAll", implements: [X509TM],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; },
        },
      });
      var tms = [TrustAll.$new()];
      var init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
      init.implementation = function (km, tm, sr) { init.call(this, km, tms, sr); };
      n++;
    } catch (e) {}

    // OkHttp CertificatePinner (all overloads)
    try {
      var CP = Java.use("okhttp3.CertificatePinner");
      CP.check.overload("java.lang.String", "java.util.List").implementation = function () {};
      try { CP.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function () {}; } catch (e) {}
      try { CP.check$okhttp.implementation = function () {}; } catch (e) {}
      n++;
    } catch (e) {}

    // Conscrypt TrustManagerImpl (HttpsURLConnection on modern Android)
    try {
      var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      var empty = Java.use("java.util.ArrayList");
      try { TMI.checkTrustedRecursive.implementation = function () { return empty.$new(); }; } catch (e) {}
      try { TMI.verifyChain.implementation = function (certs) { return certs; }; } catch (e) {}
      n++;
    } catch (e) {}

    // Android network-security-config declarative pinning
    try {
      var NSTM = Java.use("android.security.net.config.NetworkSecurityTrustManager");
      NSTM.checkServerTrusted.overload(
        "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String"
      ).implementation = function () { return Java.use("java.util.ArrayList").$new(); };
      n++;
    } catch (e) {}

    // TrustKit
    try {
      Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier")
        .verify.overload("java.lang.String", "javax.net.ssl.SSLSession")
        .implementation = function () { return true; };
      n++;
    } catch (e) {}

    // HostnameVerifier default
    try {
      Java.use("javax.net.ssl.HttpsURLConnection").setDefaultHostnameVerifier.implementation = function () {};
      n++;
    } catch (e) {}

    // WebViewClient.onReceivedSslError -> proceed
    try {
      var WVC = Java.use("android.webkit.WebViewClient");
      WVC.onReceivedSslError.overload(
        "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"
      ).implementation = function (v, handler, err) { handler.proceed(); };
      n++;
    } catch (e) {}

    log("Java hooks active (" + n + ")");
  });
}

/* --------------------------------------------------------------- (B) native */
// BoringSSL's verify functions live in libssl.so but big apps strip the dynamic symbol table,
// so a global findExportByName(null, ...) misses them. We resolve them from libssl.so
// explicitly and always report the certificate as valid. ssl_verify_ok = 0.
var nativeDone = {};
function findSSL(name) {
  // try the module-scoped lookup first (works even when the global one fails)
  var libs = ["libssl.so", "libboringssl.so", "libsscronet.so", "libttboringssl.so"];
  for (var i = 0; i < libs.length; i++) {
    var m = Process.findModuleByName(libs[i]);
    if (m) {
      var p = m.findExportByName(name);
      if (p) return p;
    }
  }
  return Module.findExportByName(null, name);
}

// A single shared "always OK" verify callback. BoringSSL custom-verify callbacks return an
// ssl_verify_result_t: 0 = ssl_verify_ok.
var okVerifyCb = null;
function okCallback() {
  if (!okVerifyCb) okVerifyCb = new NativeCallback(function () { return 0; }, "int", ["pointer", "pointer"]);
  return okVerifyCb;
}

function hookNativeSSL() {
  var hooked = 0;

  // SSL_CTX_set_custom_verify(ctx, mode, cb) / SSL_set_custom_verify(ssl, mode, cb):
  // use Interceptor.attach + onEnter to replace the callback ARGUMENT (arg2) with our
  // always-OK one. This is safe — the original function still runs normally, we only change
  // which verify callback it installs. (Interceptor.replace here risks crashing the app.)
  ["SSL_CTX_set_custom_verify", "SSL_set_custom_verify"].forEach(function (name) {
    if (nativeDone[name]) return;
    var p = findSSL(name);
    if (!p) return;
    try {
      Interceptor.attach(p, {
        onEnter: function (args) { args[2] = okCallback(); },
      });
      nativeDone[name] = true;
      hooked++;
    } catch (e) {}
  });

  if (hooked) log("native SSL hooks active (+" + hooked + ")");
  return hooked;
}

/* re-run native hooks as libraries load (libssl / pinning libs load after startup) */
function watchDlopen() {
  ["android_dlopen_ext", "__dl_android_dlopen_ext", "dlopen"].forEach(function (fn) {
    var p = Module.findExportByName(null, fn);
    if (!p) return;
    try {
      Interceptor.attach(p, { onLeave: function () { setTimeout(hookNativeSSL, 30); } });
    } catch (e) {}
  });
  // also poll a few times in case dlopen isn't hookable
  var tries = 0;
  var iv = setInterval(function () { hookNativeSSL(); if (++tries > 20) clearInterval(iv); }, 500);
}

/* --------------------------------------------------------------------- run */
// Native BoringSSL hooks can decrypt apps that pin in native code, but on some apps they
// destabilise TLS and the app exits. They are therefore opt-in: Sift replaces the token
// below with true only when "aggressive" unpinning is requested. Java hooks (the reliable
// default, covering OkHttp / TrustManager / Conscrypt / network-security-config) always run.
var ENABLE_NATIVE = __SIFT_NATIVE__;
setTimeout(function () {
  try { hookJava(); } catch (e) { log("java err: " + e); }
  if (ENABLE_NATIVE) {
    try { hookNativeSSL(); } catch (e) { log("native err: " + e); }
    try { watchDlopen(); } catch (e) {}
  }
  send("[unpin] ready");
}, 0);
