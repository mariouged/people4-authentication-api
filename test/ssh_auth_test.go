package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
)

// serverAddr returns the SSH server address from SSH_SERVER_ADDR env or the default.
func serverAddr() string {
	if addr := os.Getenv("SSH_SERVER_ADDR"); addr != "" {
		return addr
	}
	return "localhost:2222"
}

// dial connects to the SSH server using signer and returns the raw output written
// by the server on the session channel.
func dial(t *testing.T, signer ssh.Signer) []byte {
	t.Helper()

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	client, err := ssh.Dial("tcp", serverAddr(), cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	out, err := session.Output("")
	if err != nil && err != io.EOF {
		t.Fatalf("session output: %v", err)
	}
	return out
}

// TestSSHAuthReturnsJWT authenticates with test/test_key (which must be listed
// in db/authorized_keys) and asserts a non-empty JWT is returned.
//
// Prerequisites:
//   - Server running: go run .
//   - JWT_SECRET env var set for the server process.
//   - test/test_key.pub content present in db/authorized_keys.
//   - test/test_key private key file present (generate once with:
//     ssh-keygen -t rsa -b 2048 -f test/test_key -N "")
//
// Run: go test ./test/ -v
func TestSSHAuthReturnsJWT(t *testing.T) {
	keyPEM, err := os.ReadFile("test_key.priv")
	if err != nil {
		t.Fatalf("read test_key.priv: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse test_key: %v", err)
	}

	out := dial(t, signer)

	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", string(out), err)
	}
	if resp.Token == "" {
		t.Fatal("expected a non-empty JWT, got empty string")
	}
	t.Logf("received JWT: %s", resp.Token)
}

// TestSSHAuthRejectsUnknownKey verifies that an unregistered key is rejected.
func TestSSHAuthRejectsUnknownKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	_, err = ssh.Dial("tcp", serverAddr(), cfg)
	if err == nil {
		t.Fatal("expected connection to be rejected for unknown key, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestJWTClaims authenticates, receives the JWT, and verifies all expected claims.
func TestJWTClaims(t *testing.T) {
	secret := os.Getenv("JWT_SECRET")

	keyPEM, err := os.ReadFile("test_key.priv")
	if err != nil {
		t.Fatalf("read test_key.priv: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse test_key.priv: %v", err)
	}

	out := dial(t, signer)

	var raw struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("unmarshal response %q: %v", string(out), err)
	}

	// Use an insecure parse when the secret is unavailable so claims can still
	// be asserted; full signature verification requires JWT_SECRET to be set.
	var keyFunc jwt.Keyfunc
	if secret != "" {
		keyFunc = func(tok *jwt.Token) (any, error) {
			if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		}
	} else {
		t.Log("JWT_SECRET not set — skipping signature verification, checking claims only")
		keyFunc = func(tok *jwt.Token) (any, error) { return jwt.UnsafeAllowNoneSignatureType, nil }
	}

	parser := jwt.NewParser(jwt.WithExpirationRequired())
	token, _, err := parser.ParseUnverified(raw.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse JWT claims: %v", err)
	}
	if secret != "" {
		if _, err := jwt.Parse(raw.Token, keyFunc, jwt.WithExpirationRequired()); err != nil {
			t.Fatalf("verify JWT signature: %v", err)
		}
	}
	_ = keyFunc

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("invalid token claims")
	}

	if sub, _ := claims["sub"].(string); sub == "" {
		t.Error("claim 'sub' is missing or empty")
	} else {
		t.Logf("sub = %s", sub)
	}

	if iss, _ := claims["iss"].(string); iss != "custom-ssh-auth-server" {
		t.Errorf("claim 'iss': want %q, got %q", "custom-ssh-auth-server", iss)
	} else {
		t.Logf("iss = %s", iss)
	}

	if seller, _ := claims["seller"].(string); seller != "test_currito" {
		t.Errorf("claim 'seller': want %q, got %q", "test_currito", seller)
	} else {
		t.Logf("seller = %s", seller)
	}

	expNum, ok := claims["exp"].(float64)
	if !ok {
		t.Error("claim 'exp' is missing or not a number")
	} else {
		exp := time.Unix(int64(expNum), 0)
		if !exp.After(time.Now()) {
			t.Errorf("claim 'exp' %v is not in the future", exp)
		}
		t.Logf("exp = %s", exp)
	}
}
