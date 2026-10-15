

function log(m) { send("[unpin] " + m); }

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

    try {
      var CP = Java.use("okhttp3.CertificatePinner");
      CP.check.overload("java.lang.String", "java.util.List").implementation = function () {};
      try { CP.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function () {}; } catch (e) {}
      try { CP.check$okhttp.implementation = function () {}; } catch (e) {}
      n++;
    } catch (e) {}

    try {
      var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      var empty = Java.use("java.util.ArrayList");
      try { TMI.checkTrustedRecursive.implementation = function () { return empty.$new(); }; } catch (e) {}
      try { TMI.verifyChain.implementation = function (certs) { return certs; }; } catch (e) {}
      n++;
    } catch (e) {}

    try {
      var NSTM = Java.use("android.security.net.config.NetworkSecurityTrustManager");
      NSTM.checkServerTrusted.overload(
        "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String"
      ).implementation = function () { return Java.use("java.util.ArrayList").$new(); };
      n++;
    } catch (e) {}

    try {
      Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier")
        .verify.overload("java.lang.String", "javax.net.ssl.SSLSession")
        .implementation = function () { return true; };
      n++;
    } catch (e) {}

    try {
      Java.use("javax.net.ssl.HttpsURLConnection").setDefaultHostnameVerifier.implementation = function () {};
      n++;
    } catch (e) {}

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

var nativeDone = {};
function findSSL(name) {
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

var okVerifyCb = null;
function okCallback() {
  if (!okVerifyCb) okVerifyCb = new NativeCallback(function () { return 0; }, "int", ["pointer", "pointer"]);
  return okVerifyCb;
}

function hookNativeSSL() {
  var hooked = 0;

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

function watchDlopen() {
  ["android_dlopen_ext", "__dl_android_dlopen_ext", "dlopen"].forEach(function (fn) {
    var p = Module.findExportByName(null, fn);
    if (!p) return;
    try {
      Interceptor.attach(p, { onLeave: function () { setTimeout(hookNativeSSL, 30); } });
    } catch (e) {}
  });
  var tries = 0;
  var iv = setInterval(function () { hookNativeSSL(); if (++tries > 20) clearInterval(iv); }, 500);
}

var ENABLE_NATIVE = __SIFT_NATIVE__;
setTimeout(function () {
  try { hookJava(); } catch (e) { log("java err: " + e); }
  if (ENABLE_NATIVE) {
    try { hookNativeSSL(); } catch (e) { log("native err: " + e); }
    try { watchDlopen(); } catch (e) {}
  }
  send("[unpin] ready");
}, 0);
