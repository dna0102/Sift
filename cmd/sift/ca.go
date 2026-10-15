package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CA signs a certificate for every HTTPS host on the fly. Apps accept those certificates
// once the root is trusted by the OS.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     crypto.Signer
	leafKey *ecdsa.PrivateKey

	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey // for old apps that can't use ECDSA certificates

	mu       sync.Mutex
	cache    map[string]*tls.Certificate // key: host, or "rsa:"+host
	inflight map[string]chan struct{}

	SHA1      string
	Subject   string
	NotAfter  time.Time
	PEMPath   string
	CERPath   string
	trusted   atomic.Int32 // -1 unknown, 0 no, 1 yes
}

func LoadCA(home string) (*CA, error) {
	ca := &CA{cache: map[string]*tls.Certificate{}, inflight: map[string]chan struct{}{}}
	ca.trusted.Store(-1)
	// mitmproxy-ca.pem is the CA the Python version of Sift created: keep using it so
	// an already-installed certificate stays valid.
	candidates := [][2]string{
		{filepath.Join(home, "mitmproxy-ca.pem"), filepath.Join(home, "mitmproxy-ca.pem")},
		{filepath.Join(home, "sift-ca.pem"), filepath.Join(home, "sift-ca-key.pem")},
	}
	loaded := false
	for _, c := range candidates {
		if err := ca.load(c[0], c[1]); err == nil {
			loaded = true
			break
		}
	}
	if !loaded {
		if err := ca.create(filepath.Join(home, "sift-ca.pem"), filepath.Join(home, "sift-ca-key.pem")); err != nil {
			return nil, err
		}
	}
	sum := sha1.Sum(ca.certDER)
	ca.SHA1 = strings.ToUpper(hex.EncodeToString(sum[:]))
	ca.Subject = ca.cert.Subject.CommonName
	ca.NotAfter = ca.cert.NotAfter
	ca.PEMPath = filepath.Join(home, "sift-ca-cert.pem")
	ca.CERPath = filepath.Join(home, "sift-ca-cert.cer")
	_ = os.WriteFile(ca.PEMPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER}), 0o644)
	_ = os.WriteFile(ca.CERPath, ca.certDER, 0o644)

	var err error
	ca.leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return ca, err
}

func (ca *CA) load(certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM := certPEM
	if keyFile != certFile {
		if keyPEM, err = os.ReadFile(keyFile); err != nil {
			return err
		}
	}
	for rest := certPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" && ca.cert == nil {
			if ca.cert, err = x509.ParseCertificate(b.Bytes); err != nil {
				return err
			}
			ca.certDER = b.Bytes
		}
	}
	for rest := keyPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if strings.Contains(b.Type, "PRIVATE KEY") {
			ca.key = parseKey(b.Bytes)
		}
	}
	if ca.cert == nil || ca.key == nil {
		ca.cert, ca.key = nil, nil
		return errors.New("no certificate/key in " + certFile)
	}
	return nil
}

func parseKey(der []byte) crypto.Signer {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k
	}
	return nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n.Add(n, big.NewInt(1))
}

func (ca *CA) create(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Sift CA", Organization: []string{"Sift"}, OrganizationalUnit: []string{"Sift Local Debugging Proxy"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	ca.cert, _ = x509.ParseCertificate(der)
	ca.certDER = der
	ca.key = key
	return nil
}

// Leaf returns (and caches) an ECDSA certificate for host signed by the CA.
func (ca *CA) Leaf(host string) (*tls.Certificate, error) { return ca.leafFor(host, false) }

// LeafFor picks the certificate type the app supports: ECDSA (fast) or RSA (old apps).
func (ca *CA) LeafFor(hello *tls.ClientHelloInfo, host string) (*tls.Certificate, error) {
	c, err := ca.leafFor(host, false)
	if err != nil || hello.SupportsCertificate(c) == nil {
		return c, err
	}
	return ca.leafFor(host, true)
}

// leafFor generates certificates outside the lock, so one slow host never blocks others.
func (ca *CA) leafFor(host string, useRSA bool) (*tls.Certificate, error) {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		host = "localhost"
	}
	key := host
	if useRSA {
		key = "rsa:" + host
	}
	for {
		ca.mu.Lock()
		if c, ok := ca.cache[key]; ok {
			ca.mu.Unlock()
			return c, nil
		}
		wait, busy := ca.inflight[key]
		if !busy {
			ca.inflight[key] = make(chan struct{})
			ca.mu.Unlock()
			break
		}
		ca.mu.Unlock()
		<-wait // another handshake is generating this one
	}
	c, err := ca.generate(host, useRSA)
	ca.mu.Lock()
	if err == nil {
		if len(ca.cache) > 5000 {
			clear(ca.cache)
		}
		ca.cache[key] = c
	}
	close(ca.inflight[key])
	delete(ca.inflight, key)
	ca.mu.Unlock()
	return c, err
}

func (ca *CA) generate(host string, useRSA bool) (*tls.Certificate, error) {
	cn := host
	if len(cn) > 64 {
		cn = cn[:64]
	}
	notAfter := time.Now().AddDate(0, 0, 397)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Sift"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	var pub any = &ca.leafKey.PublicKey
	var priv crypto.Signer = ca.leafKey
	if useRSA {
		ca.rsaOnce.Do(func() { ca.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
		pub, priv = &ca.rsaKey.PublicKey, ca.rsaKey
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

func (ca *CA) PEM() []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER}) }
func (ca *CA) DER() []byte { return ca.certDER }

// Trusted: 1 yes, 0 no, -1 unknown.
func (ca *CA) Trusted() int { return int(ca.trusted.Load()) }

func run(name string, args ...string) (bool, string) {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	return err == nil, strings.TrimSpace(string(out))
}

func (ca *CA) CheckTrusted() int {
	switch runtime.GOOS {
	case "windows":
		ok, _ := run("certutil", "-user", "-verifystore", "Root", ca.SHA1)
		if !ok {
			ok, _ = run("certutil", "-verifystore", "Root", ca.SHA1)
		}
		ca.trusted.Store(b2i(ok))
	case "darwin":
		ok, _ := run("security", "verify-cert", "-c", ca.PEMPath)
		ca.trusted.Store(b2i(ok))
	default:
		ca.trusted.Store(-1)
	}
	return ca.Trusted()
}

func b2i(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func (ca *CA) Install() (bool, string) {
	var out string
	switch runtime.GOOS {
	case "windows":
		// Windows shows its own "Do you want to install this certificate?" confirmation.
		_, out = run("certutil", "-user", "-addstore", "Root", ca.CERPath)
	case "darwin":
		home, _ := os.UserHomeDir()
		_, out = run("security", "add-trusted-cert", "-r", "trustRoot", "-k", filepath.Join(home, "Library/Keychains/login.keychain-db"), ca.PEMPath)
	default:
		return false, "Automatic install isn't available on Linux. Copy " + ca.PEMPath + " to /usr/local/share/ca-certificates/sift.crt and run sudo update-ca-certificates."
	}
	if ca.CheckTrusted() == 1 {
		return true, "Certificate installed. Restart your browser if HTTPS pages still show errors."
	}
	if out == "" {
		out = "Installation was cancelled."
	}
	return false, out
}

func (ca *CA) Uninstall() (bool, string) {
	switch runtime.GOOS {
	case "windows":
		run("certutil", "-user", "-delstore", "Root", ca.SHA1)
	case "darwin":
		run("security", "delete-certificate", "-Z", ca.SHA1)
	}
	if ca.CheckTrusted() == 1 {
		return false, "The certificate is still trusted (it may be installed for all users)."
	}
	return true, "Certificate removed."
}
